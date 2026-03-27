"""
TrueFoundry AI Gateway integration for DeepSentinel.
Routes all LLM calls through TrueFoundry for multi-model routing,
observability, rate limiting, and cost tracking.
When TrueFoundry is not configured, uses Anthropic Claude directly.
"""
import json
import os

import anthropic


class TrueFoundryGateway:
    def __init__(self, api_key: str = None, base_url: str = None):
        self.tfy_key = api_key or os.environ.get("TRUEFOUNDRY_API_KEY", "")
        self.tfy_base = base_url or os.environ.get("TRUEFOUNDRY_BASE_URL", "https://gateway.truefoundry.ai")
        self.anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")

        if self.tfy_key:
            # Route through TrueFoundry gateway
            from openai import OpenAI
            self.openai_client = OpenAI(api_key=self.tfy_key, base_url=self.tfy_base)
            self.mode = "truefoundry"
            print("[TrueFoundry] AI Gateway connected — multi-model routing active")
        elif self.anthropic_key:
            self.anthropic_client = anthropic.Anthropic(api_key=self.anthropic_key)
            self.mode = "anthropic"
            print("[TrueFoundry] Using Anthropic Claude directly (gateway key pending)")
        else:
            self.mode = "none"
            print("[TrueFoundry] No LLM keys configured")

    def chat(self, model: str, messages: list, metadata: dict = None, **kwargs) -> dict:
        """Send a chat completion. Routes through TrueFoundry or Anthropic."""
        if self.mode == "truefoundry":
            return self._chat_truefoundry(model, messages, metadata, **kwargs)
        elif self.mode == "anthropic":
            return self._chat_anthropic(messages, **kwargs)
        else:
            return {"content": "[No LLM configured]", "model": "none", "usage": {}}

    def _chat_truefoundry(self, model: str, messages: list, metadata: dict = None, **kwargs) -> dict:
        """Route through TrueFoundry AI Gateway."""
        extra_headers = {}
        if metadata:
            extra_headers["X-TFY-METADATA"] = json.dumps({"tfy_log_request": "true", **metadata})

        tfy_model = model
        if not model.startswith(("openai", "anthropic")):
            tfy_model = f"openai-main/{model}" if "claude" not in model else f"anthropic-main/{model}"

        response = self.openai_client.chat.completions.create(
            model=tfy_model, messages=messages,
            extra_headers=extra_headers if extra_headers else None, **kwargs,
        )
        prompt_tokens = response.usage.prompt_tokens if response.usage else 0
        completion_tokens = response.usage.completion_tokens if response.usage else 0
        total_tokens = prompt_tokens + completion_tokens

        # Cost estimation (GPT-4o-mini: $0.15/1M input, $0.60/1M output)
        cost = (prompt_tokens * 0.00000015) + (completion_tokens * 0.0000006)
        self.total_cost = getattr(self, 'total_cost', 0) + cost
        self.total_calls = getattr(self, 'total_calls', 0) + 1

        print(f"  [TrueFoundry] {tfy_model} | {total_tokens} tokens | ${cost:.4f} | via gateway.truefoundry.ai")

        return {
            "content": response.choices[0].message.content,
            "model": response.model,
            "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens},
            "cost": cost,
        }

    def _chat_anthropic(self, messages: list, **kwargs) -> dict:
        """Use Anthropic Claude directly."""
        # Separate system message from user messages
        system_msg = ""
        user_messages = []
        for m in messages:
            if m["role"] == "system":
                system_msg = m["content"]
            else:
                user_messages.append(m)

        if not user_messages:
            user_messages = [{"role": "user", "content": "Analyze."}]

        temp = kwargs.get("temperature", 0.3)
        response = self.anthropic_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            system=system_msg,
            messages=user_messages,
            temperature=temp,
        )
        content = response.content[0].text if response.content else ""
        input_tokens = response.usage.input_tokens if response.usage else 0
        output_tokens = response.usage.output_tokens if response.usage else 0

        # Cost estimation (Claude Sonnet: $3/1M input, $15/1M output)
        cost = (input_tokens * 0.000003) + (output_tokens * 0.000015)
        self.total_cost = getattr(self, 'total_cost', 0) + cost
        self.total_calls = getattr(self, 'total_calls', 0) + 1

        print(f"  [TrueFoundry] claude-sonnet | {input_tokens + output_tokens} tokens | ${cost:.4f}")

        return {
            "content": content,
            "model": response.model,
            "usage": {"prompt_tokens": input_tokens, "completion_tokens": output_tokens},
            "cost": cost,
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
