"""
TrueFoundry AI Gateway integration for DeepSentinel.
Routes all LLM calls through TrueFoundry for multi-model routing,
observability, rate limiting, and cost tracking.
"""
import json
import os
from openai import OpenAI


class TrueFoundryGateway:
    def __init__(self, api_key: str = None, base_url: str = None):
        self.api_key = api_key or os.environ.get("TRUEFOUNDRY_API_KEY", "")
        self.base_url = base_url or os.environ.get("TRUEFOUNDRY_BASE_URL", "https://gateway.truefoundry.ai")

        # If TrueFoundry key available, route through gateway
        # Otherwise fall back to direct OpenAI
        if self.api_key:
            self.client = OpenAI(api_key=self.api_key, base_url=self.base_url)
            self.model_prefix = "openai-main/"
            self.anthropic_prefix = "anthropic-main/"
        else:
            self.client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", ""))
            self.model_prefix = ""
            self.anthropic_prefix = ""

    def _model(self, model: str) -> str:
        """Resolve model name for TrueFoundry gateway format."""
        if self.model_prefix and not model.startswith(("openai", "anthropic")):
            if "claude" in model:
                return f"{self.anthropic_prefix}{model}"
            return f"{self.model_prefix}{model}"
        return model

    def chat(self, model: str, messages: list, metadata: dict = None, **kwargs) -> dict:
        """Send a chat completion through TrueFoundry gateway."""
        extra_headers = {}
        if metadata:
            meta = {"tfy_log_request": "true", **metadata}
            extra_headers["X-TFY-METADATA"] = json.dumps(meta)

        response = self.client.chat.completions.create(
            model=self._model(model),
            messages=messages,
            extra_headers=extra_headers if extra_headers else None,
            **kwargs,
        )
        return {
            "content": response.choices[0].message.content,
            "model": response.model,
            "usage": {
                "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                "completion_tokens": response.usage.completion_tokens if response.usage else 0,
            },
        }

    def fast_scan(self, code: str, file_path: str) -> dict:
        """Fast initial security scan with lightweight model."""
        return self.chat(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": "You are a code security scanner. Identify potential vulnerabilities. Output ONLY a JSON array of findings. Each finding: {severity, cwe_id, line_number, title, description, fix_suggestion}. Empty array if none found.",
                },
                {"role": "user", "content": f"File: {file_path}\n```\n{code[:4000]}\n```"},
            ],
            metadata={"agent": "deepsentinel", "task": "fast_scan", "file": file_path},
            temperature=0.1,
        )

    def deep_analysis(self, findings: str, context: str) -> dict:
        """Deep vulnerability analysis with powerful model."""
        return self.chat(
            model="gpt-4o",
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert security analyst. Verify findings, remove false positives, enhance with attack scenarios. Output ONLY a JSON array of verified findings.",
                },
                {"role": "user", "content": f"Findings:\n{findings}\n\nContext:\n{context}"},
            ],
            metadata={"agent": "deepsentinel", "task": "deep_analysis"},
            temperature=0.0,
        )

    def generate_report(self, findings: list, correlations: list) -> str:
        """Generate formatted security report."""
        result = self.chat(
            model="gpt-4o",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "Generate a security report. Format:\n"
                        "# DeepSentinel Security Report\n"
                        "**Findings: X total (Y critical, Z high)**\n\n"
                        "## [SEVERITY] Title\n"
                        "**CWE:** CWE-XXX | **File:** path:line\n"
                        "**Risk:** Attack scenario\n"
                        "**Fix:** Specific fix\n"
                        "**Cross-source context:** Related Slack/Jira info\n\n"
                        "End with BLOCK/REVIEW/APPROVE recommendation."
                    ),
                },
                {
                    "role": "user",
                    "content": f"Findings:\n{json.dumps(findings, indent=2)}\n\nCorrelations:\n{json.dumps(correlations, indent=2)}",
                },
            ],
            metadata={"agent": "deepsentinel", "task": "report_generation"},
            temperature=0.3,
        )
        return result["content"]
