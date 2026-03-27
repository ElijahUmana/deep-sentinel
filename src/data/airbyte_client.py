"""
Airbyte integration for DeepSentinel.
Multi-source data ingestion: GitHub + Slack via agent connectors.
Cross-source correlation engine.
"""
import asyncio
import base64
import json
import os
from dataclasses import dataclass, field

import httpx

from airbyte_agent_github import GithubConnector
from airbyte_agent_github.models import GithubPersonalAccessTokenAuthConfig
from airbyte_agent_slack import SlackConnector
from airbyte_agent_slack.models import SlackTokenAuthenticationAuthConfig


@dataclass
class PRData:
    number: int
    title: str
    author: str
    body: str
    changed_files: list = field(default_factory=list)
    commits: list = field(default_factory=list)
    labels: list = field(default_factory=list)


@dataclass
class SlackContext:
    messages: list = field(default_factory=list)
    channels_searched: list = field(default_factory=list)


@dataclass
class CrossSourceContext:
    github: PRData = None
    slack: SlackContext = None
    correlations: list = field(default_factory=list)


SECURITY_KEYWORDS = [
    "vulnerability", "security", "CVE", "XSS", "SQL injection",
    "auth", "authentication", "authorization", "token", "secret",
    "encrypt", "SSL", "TLS", "OWASP", "exploit", "patch",
    "dependency", "risk", "compliance", "skip validation",
    "no auth", "hardcoded", "plaintext", "password", "leak",
]


class AirbyteDataLayer:
    """Multi-source data ingestion via Airbyte agent connectors."""

    def __init__(self, github_token: str = None, slack_token: str = None):
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN", "")
        self.slack_token = slack_token or os.environ.get("SLACK_BOT_TOKEN", "")

        self.github = None
        self.slack = None

        if self.github_token:
            try:
                self.github = GithubConnector(
                    auth_config=GithubPersonalAccessTokenAuthConfig(token=self.github_token)
                )
                print("[Airbyte] GitHub connector initialized")
            except Exception as e:
                print(f"[Airbyte] GitHub connector init error: {e}")
                self.github = None

        if self.slack_token:
            self.slack = SlackConnector(
                auth_config=SlackTokenAuthenticationAuthConfig(api_token=self.slack_token)
            )
            print("[Airbyte] Slack connector initialized")

    # ===========================
    # GITHUB DATA
    # ===========================

    async def get_open_prs(self, owner: str, repo: str) -> list:
        """Get all open PRs for monitoring."""
        if not self.github:
            return []
        result = await self.github.execute(
            "pull_requests", "list", {"owner": owner, "repo": repo, "states": ["OPEN"], "per_page": 20}
        )
        return result.data if hasattr(result, "data") else []

    async def get_pr_details(self, owner: str, repo: str, pr_number: int) -> PRData:
        """Get full PR details including changed files."""
        pr = await self._github_api_pr(owner, repo, pr_number)
        if not pr:
            return PRData(number=pr_number, title=f"PR #{pr_number}", author="unknown", body="")

        # Get the PR's head branch for fetching file content
        head_ref = pr.get("head", {}).get("ref", "main") if isinstance(pr.get("head"), dict) else "main"

        pr_files = await self._github_api_pr_files(owner, repo, pr_number)
        changed_files = []
        for pf in pr_files[:10]:
            fp = pf.get("filename", "")
            content = await self._github_api_file(owner, repo, fp, ref=head_ref)
            changed_files.append({"path": fp, "content": content, "patch": pf.get("patch", "")})

        user = pr.get("user", {})
        labels = pr.get("labels", [])
        label_names = []
        for l in labels:
            if isinstance(l, dict):
                label_names.append(l.get("name", ""))
            elif isinstance(l, str):
                label_names.append(l)

        return PRData(
            number=pr.get("number", pr_number),
            title=pr.get("title", ""),
            author=user.get("login", "unknown") if isinstance(user, dict) else str(user),
            body=pr.get("body", "") or "",
            changed_files=changed_files,
            commits=[],
            labels=label_names,
        )

    async def get_repo_files(self, owner: str, repo: str, path: str = "") -> list:
        """List repository directory contents."""
        if not self.github:
            return []
        try:
            result = await self.github.execute("directory_content", "list", {"owner": owner, "repo": repo, "path": path})
            return result.data if hasattr(result, "data") else []
        except Exception:
            return []

    async def get_file_content(self, owner: str, repo: str, path: str) -> str:
        """Get raw file content from GitHub."""
        return await self._github_api_file(owner, repo, path)

    async def _github_api_file(self, owner: str, repo: str, path: str, ref: str = None) -> str:
        """Fetch file content from GitHub API."""
        try:
            async with httpx.AsyncClient() as client:
                params = {}
                if ref:
                    params["ref"] = ref
                resp = await client.get(
                    f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
                    headers={"Authorization": f"Bearer {self.github_token}", "Accept": "application/vnd.github.v3+json"},
                    params=params,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return base64.b64decode(data.get("content", "")).decode("utf-8", errors="replace")
        except Exception:
            pass
        return ""

    async def _github_api_pr(self, owner: str, repo: str, pr_number: int) -> dict:
        """Direct GitHub API fallback for PR data."""
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}",
                    headers={"Authorization": f"Bearer {self.github_token}", "Accept": "application/vnd.github.v3+json"},
                )
                if resp.status_code == 200:
                    return resp.json()
        except Exception:
            pass
        return {}

    async def _github_api_pr_files(self, owner: str, repo: str, pr_number: int) -> list:
        """Get changed files in a PR via GitHub API."""
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files",
                    headers={"Authorization": f"Bearer {self.github_token}", "Accept": "application/vnd.github.v3+json"},
                )
                if resp.status_code == 200:
                    return resp.json()
        except Exception:
            pass
        return []

    # ===========================
    # SLACK DATA
    # ===========================

    async def get_security_discussions(self) -> SlackContext:
        """Pull security-related discussions from Slack channels."""
        if not self.slack:
            return SlackContext()

        all_messages = []
        channels_searched = []

        try:
            # List channels and find security-relevant ones
            ch_result = await self.slack.execute("channels", "list", {})
            channels = ch_result.data if hasattr(ch_result, "data") else []

            security_channels = []
            for ch in channels:
                name = ch.get("name", "").lower()
                if any(kw in name for kw in ["security", "vuln", "infosec", "appsec", "dev", "engineering", "general"]):
                    security_channels.append(ch)

            if not security_channels:
                security_channels = channels[:3]

            # Pull messages from each channel
            for ch in security_channels[:5]:
                ch_id = ch.get("id", "")
                ch_name = ch.get("name", "")
                channels_searched.append(ch_name)

                try:
                    msg_result = await self.slack.execute("channel_messages", "list", {"channel": ch_id})
                    messages = msg_result.data if hasattr(msg_result, "data") else []

                    for msg in messages:
                        text = msg.get("text", "").lower()
                        if any(kw.lower() in text for kw in SECURITY_KEYWORDS):
                            all_messages.append({
                                "channel": ch_name,
                                "text": msg.get("text", ""),
                                "user": msg.get("user", ""),
                                "ts": msg.get("ts", ""),
                            })
                except Exception:
                    continue

        except Exception as e:
            print(f"[Airbyte] Slack error: {e}")

        return SlackContext(messages=all_messages[:30], channels_searched=channels_searched)

    async def post_slack_alert(self, channel_id: str, message: str):
        """Post a security alert to Slack."""
        if not self.slack:
            print(f"[Airbyte] Would post to Slack: {message[:100]}...")
            return
        try:
            await self.slack.execute("messages", "create", {"channel": channel_id, "text": message})
        except Exception as e:
            print(f"[Airbyte] Slack post error: {e}")

    # ===========================
    # CROSS-SOURCE CORRELATION
    # ===========================

    async def gather_full_context(self, owner: str, repo: str, pr_number: int) -> CrossSourceContext:
        """Gather data from all sources in parallel and correlate."""
        print("[Airbyte] Gathering cross-source context...")

        # Parallel data fetch
        github_task = self.get_pr_details(owner, repo, pr_number)
        slack_task = self.get_security_discussions()

        github_data, slack_data = await asyncio.gather(github_task, slack_task, return_exceptions=True)

        if isinstance(github_data, Exception):
            print(f"[Airbyte] GitHub error: {github_data}")
            github_data = PRData(number=pr_number, title="", author="", body="")
        if isinstance(slack_data, Exception):
            print(f"[Airbyte] Slack error: {slack_data}")
            slack_data = SlackContext()

        # Cross-source correlation
        correlations = self._correlate(github_data, slack_data)

        print(f"[Airbyte] GitHub: PR #{github_data.number} — {github_data.title}")
        print(f"[Airbyte] GitHub: {len(github_data.changed_files)} files changed")
        print(f"[Airbyte] Slack: {len(slack_data.messages)} security messages from {len(slack_data.channels_searched)} channels")
        print(f"[Airbyte] Correlations: {len(correlations)} cross-source links found")

        return CrossSourceContext(github=github_data, slack=slack_data, correlations=correlations)

    def _correlate(self, github: PRData, slack: SlackContext) -> list:
        """Find connections between GitHub and Slack data."""
        correlations = []

        for file_info in github.changed_files:
            file_path = file_info.get("path", "")
            file_name = file_path.split("/")[-1] if file_path else ""
            module = "/".join(file_path.split("/")[:-1]) if file_path else ""

            for msg in slack.messages:
                text = msg.get("text", "")
                if file_name and (file_name in text or module in text):
                    correlations.append({
                        "type": "slack_file_mention",
                        "github_ref": f"PR #{github.number} - {file_path}",
                        "slack_ref": f"#{msg.get('channel', '')} - {msg.get('ts', '')}",
                        "slack_text": text[:200],
                        "risk_note": f"File {file_name} was discussed in Slack: {text[:100]}",
                    })

        # Check if PR title/content mentioned in security discussions
        for msg in slack.messages:
            text = msg.get("text", "").lower()
            pr_keywords = github.title.lower().split() if github.title else []
            matches = sum(1 for kw in pr_keywords if len(kw) > 3 and kw in text)
            if matches >= 2:
                correlations.append({
                    "type": "slack_pr_discussion",
                    "github_ref": f"PR #{github.number} - {github.title}",
                    "slack_ref": f"#{msg.get('channel', '')}",
                    "slack_text": msg.get("text", "")[:200],
                    "risk_note": f"PR topic discussed in Slack security channel",
                })

        return correlations
