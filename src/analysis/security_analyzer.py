"""
Core security analysis engine for DeepSentinel.
Uses TrueFoundry for multi-model analysis, Overmind for prompt optimization.
"""
import json
import re
import os

# Overmind instrumentation
try:
    import overmind_sdk
    from opentelemetry.overmind.prompt import PromptString
    OVERMIND_AVAILABLE = True
except ImportError:
    OVERMIND_AVAILABLE = False

from src.llm.truefoundry_gateway import TrueFoundryGateway
from src.storage.aerospike_cache import AerospikeCache, VULNERABILITY_PATTERNS


def init_overmind():
    """Initialize Overmind SDK for prompt optimization."""
    if not OVERMIND_AVAILABLE:
        print("[Overmind] SDK not available, skipping instrumentation")
        return

    api_key = os.environ.get("OVERMIND_API_KEY", "")
    if api_key:
        overmind_sdk.init(service_name="deepsentinel", environment="production")
        print("[Overmind] Initialized — all LLM calls will be traced for optimization")
    else:
        print("[Overmind] No API key, skipping instrumentation")


def make_prompt(prompt_id: str, template: str, **kwargs) -> str:
    """Create a prompt, optionally wrapped with Overmind PromptString."""
    formatted = template.format(**kwargs) if kwargs else template

    if OVERMIND_AVAILABLE and os.environ.get("OVERMIND_API_KEY"):
        return str(PromptString(id=prompt_id, template=template, kwargs=kwargs))

    return formatted


class SecurityAnalyzer:
    """Multi-step security analysis with cross-source intelligence."""

    def __init__(self, llm: TrueFoundryGateway, cache: AerospikeCache):
        self.llm = llm
        self.cache = cache

    def regex_prescan(self, code: str, file_path: str) -> list:
        """Fast regex-based pre-scan for known vulnerability patterns."""
        findings = []
        patterns = self.cache.get_patterns()

        for pattern in patterns:
            regex = pattern.get("regex", "")
            if not regex:
                continue

            try:
                matches = list(re.finditer(regex, code, re.IGNORECASE | re.MULTILINE))
                for match in matches:
                    line_num = code[:match.start()].count("\n") + 1
                    findings.append({
                        "file_path": file_path,
                        "line_number": line_num,
                        "severity": pattern["severity"],
                        "cwe_id": pattern["cwe_id"],
                        "title": pattern["description"],
                        "description": f"Pattern match: {match.group()[:80]}",
                        "source": "regex_prescan",
                    })
            except re.error:
                continue

        return findings

    def analyze(self, context: dict) -> list:
        """Run multi-step security analysis on PR context."""
        all_findings = []

        # Step 1: Regex pre-scan (fast, no LLM needed)
        for file_info in context.get("files", []):
            content = file_info.get("content", "")
            if not content:
                continue
            regex_findings = self.regex_prescan(content, file_info["path"])
            all_findings.extend(regex_findings)

        print(f"[Analyzer] Regex pre-scan: {len(all_findings)} potential issues")

        # Step 2: LLM-powered deep analysis
        for file_info in context.get("files", []):
            content = file_info.get("content", "")
            if not content or len(content) < 20:
                continue

            prompt = make_prompt(
                "security_scan_v1",
                """Analyze this code for security vulnerabilities.

File: {file_path}
```
{code}
```

Cross-source intelligence:
- Slack discussions: {slack_context}
- Historical patterns: {history}

Return a JSON array of findings. Each: {{severity, cwe_id, line_number, title, description, attack_scenario, fix_suggestion}}.
If no vulnerabilities, return []. Output ONLY the JSON array.""",
                file_path=file_info["path"],
                code=content[:3500],
                slack_context=json.dumps(context.get("slack_context", [])[:3]),
                history=json.dumps(context.get("historical_patterns", [])[:5]),
            )

            try:
                result = self.llm.chat(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": "You are a security vulnerability scanner. Output ONLY valid JSON arrays."},
                        {"role": "user", "content": prompt},
                    ],
                    metadata={"agent": "deepsentinel", "task": "llm_scan", "file": file_info["path"]},
                    temperature=0.1,
                )

                llm_findings = self._parse_findings(result["content"], file_info["path"])
                all_findings.extend(llm_findings)
                print(f"[Analyzer] LLM scan of {file_info['path']}: {len(llm_findings)} findings")
            except Exception as e:
                print(f"[Analyzer] LLM scan error for {file_info['path']}: {e}")

        # Step 3: Verify critical/high findings with deep analysis
        critical_findings = [f for f in all_findings if f.get("severity") in ("CRITICAL", "HIGH")]
        if critical_findings and len(critical_findings) <= 10:
            print(f"[Analyzer] Deep-verifying {len(critical_findings)} critical/high findings...")
            try:
                verify_prompt = make_prompt(
                    "deep_verify_v1",
                    """Verify these security findings. Remove false positives. Enhance with attack scenarios.

Findings:
{findings}

Cross-source correlations:
{correlations}

Return verified findings as JSON array. Add 'verified': true for real issues. Remove false positives entirely.""",
                    findings=json.dumps(critical_findings, indent=2),
                    correlations=json.dumps(context.get("correlations", [])[:5], indent=2),
                )

                result = self.llm.chat(
                    model="gpt-4o",
                    messages=[
                        {"role": "system", "content": "You are an expert security analyst. Output ONLY valid JSON."},
                        {"role": "user", "content": verify_prompt},
                    ],
                    metadata={"agent": "deepsentinel", "task": "deep_verify"},
                    temperature=0.0,
                )

                verified = self._parse_findings(result["content"])
                if verified:
                    # Replace critical findings with verified versions
                    non_critical = [f for f in all_findings if f.get("severity") not in ("CRITICAL", "HIGH")]
                    all_findings = non_critical + verified
                    print(f"[Analyzer] Verified: {len(verified)} confirmed findings")
            except Exception as e:
                print(f"[Analyzer] Verification error: {e}")

        # Deduplicate
        seen = set()
        deduped = []
        for f in all_findings:
            key = (f.get("file_path", ""), f.get("cwe_id", ""), f.get("line_number", 0))
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        return deduped

    def generate_report(self, findings: list, correlations: list) -> str:
        """Generate formatted security report."""
        if not findings:
            return "# DeepSentinel Security Report\n\n**No vulnerabilities found.** All clear.\n\n**Recommendation: APPROVE**"

        return self.llm.generate_report(findings, correlations)

    def _parse_findings(self, content: str, default_path: str = "") -> list:
        """Parse LLM output into structured findings."""
        content = content.strip()

        # Strip markdown code blocks
        if content.startswith("```"):
            content = content.split("\n", 1)[1] if "\n" in content else content[3:]
        if content.endswith("```"):
            content = content[:-3]
        content = content.strip()

        try:
            parsed = json.loads(content)
            if isinstance(parsed, list):
                for f in parsed:
                    if default_path and not f.get("file_path"):
                        f["file_path"] = default_path
                    f["source"] = "llm_analysis"
                return parsed
            return []
        except json.JSONDecodeError:
            # Try to extract JSON array from mixed content
            match = re.search(r"\[.*\]", content, re.DOTALL)
            if match:
                try:
                    parsed = json.loads(match.group())
                    if isinstance(parsed, list):
                        for f in parsed:
                            if default_path and not f.get("file_path"):
                                f["file_path"] = default_path
                        return parsed
                except json.JSONDecodeError:
                    pass
            return []
