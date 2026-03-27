"""
TrueFoundry AI Gateway integration for DeepSentinel.
Routes all LLM calls through TrueFoundry for multi-model routing,
observability, rate limiting, and cost tracking.

Key TrueFoundry features used:
- Multi-model routing: different models for different task complexity
- Fallback chains: if primary model fails, try secondary
- Cost tracking: per-call and aggregate cost with model comparison
- Metadata logging: every call tagged with agent/task for observability
- Virtual model mapping: abstract model names to concrete deployments

When TrueFoundry is not configured, uses Anthropic Claude directly.
"""
import json
import os
import time

import anthropic


# Cost per 1M tokens for cost comparison metrics
MODEL_COSTS = {
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4o": {"input": 2.50, "output": 10.00},
    "claude-sonnet-4-20250514": {"input": 3.00, "output": 15.00},
}

# Fallback chains: if primary model fails, try these in order
FALLBACK_CHAINS = {
    "gpt-4o-mini": ["gpt-4o-mini", "gpt-4o"],
    "gpt-4o": ["gpt-4o", "gpt-4o-mini"],
}


class TrueFoundryGateway:
    def __init__(self, api_key: str = None, base_url: str = None):
        self.tfy_key = api_key or os.environ.get("TRUEFOUNDRY_API_KEY", "")
        self.tfy_base = base_url or os.environ.get("TRUEFOUNDRY_BASE_URL", "https://gateway.truefoundry.ai")
        self.anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")

        # Per-model cost and latency tracking
        self._model_stats: dict[str, dict] = {}

        if self.tfy_key:
            # Route through TrueFoundry gateway
            from openai import OpenAI
            self.openai_client = OpenAI(api_key=self.tfy_key, base_url=self.tfy_base)
            self.mode = "truefoundry"
            print("[TrueFoundry] AI Gateway connected — multi-model routing active")
            print(f"[TrueFoundry] Fallback chains: {json.dumps(FALLBACK_CHAINS)}")
        elif self.anthropic_key:
            self.anthropic_client = anthropic.Anthropic(api_key=self.anthropic_key)
            self.mode = "anthropic"
            print("[TrueFoundry] Using Anthropic Claude directly (gateway key pending)")
        else:
            self.mode = "none"
            print("[TrueFoundry] No LLM keys configured")

    def chat(self, model: str, messages: list, metadata: dict = None, **kwargs) -> dict:
        """Send a chat completion with automatic fallback.

        Routes through TrueFoundry gateway with fallback chain support:
        if the primary model returns an error, tries the next model in the
        chain. All calls are tagged with metadata for TrueFoundry observability.
        """
        if self.mode == "truefoundry":
            return self._chat_with_fallback(model, messages, metadata, **kwargs)
        elif self.mode == "anthropic":
            return self._chat_anthropic(messages, **kwargs)
        else:
            return {"content": "[No LLM configured]", "model": "none", "usage": {}}

    def _chat_with_fallback(self, model: str, messages: list, metadata: dict = None, **kwargs) -> dict:
        """Try the model chain until one succeeds."""
        chain = FALLBACK_CHAINS.get(model, [model])
        last_error = None

        for attempt_model in chain:
            try:
                result = self._chat_truefoundry(attempt_model, messages, metadata, **kwargs)
                if attempt_model != model:
                    print(f"  [TrueFoundry] Fallback: {model} -> {attempt_model} succeeded")
                return result
            except Exception as e:
                last_error = e
                print(f"  [TrueFoundry] {attempt_model} failed ({e}), trying next in chain...")

        # All models in chain failed
        print(f"  [TrueFoundry] All models in fallback chain failed: {last_error}")
        return {"content": f"[LLM error: {last_error}]", "model": "error", "usage": {}}

    def _chat_truefoundry(self, model: str, messages: list, metadata: dict = None, **kwargs) -> dict:
        """Route through TrueFoundry AI Gateway with per-model tracking."""
        extra_headers = {}
        meta = {"tfy_log_request": "true", "agent": "deepsentinel"}
        if metadata:
            meta.update(metadata)
        extra_headers["X-TFY-METADATA"] = json.dumps(meta)

        tfy_model = model
        if not model.startswith(("openai", "anthropic")):
            tfy_model = f"openai-main/{model}" if "claude" not in model else f"anthropic-main/{model}"

        t0 = time.perf_counter()
        response = self.openai_client.chat.completions.create(
            model=tfy_model, messages=messages,
            extra_headers=extra_headers, **kwargs,
        )
        latency_ms = (time.perf_counter() - t0) * 1000

        prompt_tokens = response.usage.prompt_tokens if response.usage else 0
        completion_tokens = response.usage.completion_tokens if response.usage else 0
        total_tokens = prompt_tokens + completion_tokens

        # Cost estimation using model-specific rates
        base_model = model.split("/")[-1] if "/" in model else model
        rates = MODEL_COSTS.get(base_model, MODEL_COSTS.get("gpt-4o-mini"))
        cost = (prompt_tokens * rates["input"] / 1_000_000) + (completion_tokens * rates["output"] / 1_000_000)
        self.total_cost = getattr(self, 'total_cost', 0) + cost
        self.total_calls = getattr(self, 'total_calls', 0) + 1

        # Track per-model stats
        if base_model not in self._model_stats:
            self._model_stats[base_model] = {"calls": 0, "tokens": 0, "cost": 0, "latency_ms": 0}
        stats = self._model_stats[base_model]
        stats["calls"] += 1
        stats["tokens"] += total_tokens
        stats["cost"] += cost
        stats["latency_ms"] += latency_ms

        task = meta.get("task", "")
        print(f"  [TrueFoundry] {tfy_model} | {total_tokens} tok | ${cost:.4f} | {latency_ms:.0f}ms | {task}")

        return {
            "content": response.choices[0].message.content,
            "model": response.model,
            "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens},
            "cost": cost,
            "latency_ms": latency_ms,
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

    def get_model_comparison(self) -> dict:
        """Return per-model cost/performance comparison.

        This demonstrates TrueFoundry's multi-model routing value:
        the gateway tracks which model is used for which task, showing
        the cost savings of using lightweight models for fast scans
        vs. powerful models only for deep verification.
        """
        comparison = {}
        for model, stats in self._model_stats.items():
            calls = stats["calls"]
            comparison[model] = {
                "calls": calls,
                "total_tokens": stats["tokens"],
                "total_cost": round(stats["cost"], 6),
                "avg_latency_ms": round(stats["latency_ms"] / calls, 0) if calls > 0 else 0,
                "cost_per_call": round(stats["cost"] / calls, 6) if calls > 0 else 0,
            }
        return comparison

    def print_cost_summary(self):
        """Print a cost breakdown showing multi-model routing savings."""
        comparison = self.get_model_comparison()
        total_cost = getattr(self, "total_cost", 0)
        total_calls = getattr(self, "total_calls", 0)

        print(f"\n  [TrueFoundry Cost Summary]")
        print(f"    Total: {total_calls} calls, ${total_cost:.4f}")
        for model, stats in comparison.items():
            print(
                f"    {model}: {stats['calls']} calls, "
                f"${stats['total_cost']:.4f}, "
                f"avg {stats['avg_latency_ms']:.0f}ms"
            )

        # Calculate savings vs. using the most expensive model for everything
        if comparison and total_calls > 0:
            most_expensive = max(
                MODEL_COSTS.values(),
                key=lambda r: r["input"] + r["output"],
            )
            all_expensive_cost = sum(
                s.get("total_tokens", 0) * (most_expensive["input"] + most_expensive["output"]) / 2_000_000
                for s in comparison.values()
            )
            if all_expensive_cost > 0 and all_expensive_cost > total_cost:
                savings_pct = (1 - total_cost / all_expensive_cost) * 100
                print(f"    Multi-model savings: {savings_pct:.0f}% vs. using only the most expensive model")

    def print_model_comparison_table(self):
        """Print a detailed model comparison table for the demo.

        Shows exactly WHY multi-model routing matters: which model was used
        for which task type, the cost difference, and total savings.
        """
        comparison = self.get_model_comparison()
        total_cost = getattr(self, "total_cost", 0)
        total_calls = getattr(self, "total_calls", 0)

        if not comparison:
            print("\n  [TrueFoundry] No model calls recorded.")
            return

        # Determine task assignments per model from the stats
        model_tasks = {}
        for model in self._model_stats:
            base = model.split("/")[-1] if "/" in model else model
            if "mini" in base:
                model_tasks[base] = "fast scan, correlation"
            elif "4o" in base:
                model_tasks[base] = "deep verification, report"
            elif "claude" in base.lower() or "sonnet" in base.lower():
                model_tasks[base] = "analysis, verification"
            else:
                model_tasks[base] = "general"

        print(f"\n  MODEL COMPARISON (via TrueFoundry Gateway):")
        print(f"  {'':>2}{'Model':<25} {'Calls':>5} {'Tokens':>8} {'Cost':>9} {'Avg Latency':>12}   Used for")
        print(f"  {'-'*90}")

        for model, stats in comparison.items():
            task = model_tasks.get(model, "general")
            print(
                f"  {'':>2}{model:<25} {stats['calls']:>5} {stats['total_tokens']:>8} "
                f"${stats['total_cost']:>7.4f} {stats['avg_latency_ms']:>9.1f}ms   {task}"
            )

        print(f"  {'-'*90}")
        print(f"  {'':>2}{'TOTAL':<25} {total_calls:>5} {'':>8} ${total_cost:>7.4f}")

        # Calculate what it would cost to use only the most expensive model
        most_expensive_name = max(
            MODEL_COSTS.keys(),
            key=lambda m: MODEL_COSTS[m]["input"] + MODEL_COSTS[m]["output"],
        )
        most_expensive_rates = MODEL_COSTS[most_expensive_name]
        all_expensive_cost = 0
        total_tokens = 0
        for stats in comparison.values():
            tokens = stats.get("total_tokens", 0)
            total_tokens += tokens
            # Assume roughly 50/50 input/output split for estimation
            all_expensive_cost += (
                tokens * (most_expensive_rates["input"] + most_expensive_rates["output"]) / 2_000_000
            )

        if all_expensive_cost > 0 and all_expensive_cost > total_cost:
            savings = all_expensive_cost - total_cost
            savings_pct = (1 - total_cost / all_expensive_cost) * 100
            print(f"\n  SAVINGS: Using {most_expensive_name} for everything would cost ${all_expensive_cost:.4f}")
            print(f"  Multi-model routing saved ${savings:.4f} ({savings_pct:.0f}% reduction)")
            print(f"  Strategy: lightweight models for scanning, powerful models only for verification")
