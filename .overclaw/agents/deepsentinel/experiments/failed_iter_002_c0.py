"""
OverClaw-compatible entrypoint for DeepSentinel.
This allows Overmind's OverClaw to optimize our security analysis prompts.
"""
import json
import re
from overclaw.core.tracer import call_llm


def run(input: dict) -> dict:
    """Analyze code for security vulnerabilities. OverClaw will optimize this."""
    code = input.get("code", "")
    file_path = input.get("file_path", "unknown")
    context = input.get("context", "")

    response = call_llm(
        model="claude-sonnet-4-20250514",
        messages=[
            {
                "role": "system",
                "content": (
                    "Analyze code for security vulnerabilities. Check for CWE-798, CWE-89, CWE-78, CWE-79, CWE-22, CWE-327, CWE-502, CWE-918. "
                    "Respond ONLY with valid JSON in this exact format:\n"
                    '{"findings": [{"severity": "HIGH", "cwe_id": "CWE-89", "title": "SQL Injection", "line_number": 1, "description": "...", "fix": "..."}], '
                    '"risk_level": "HIGH", "recommendation": "BLOCK"}\n\n'
                    "Risk levels: CRITICAL, HIGH, MEDIUM, LOW, NONE. Recommendations: BLOCK, REVIEW, APPROVE."
                ),
            },
            {
                "role": "user",
                "content": f"File: {file_path}\nContext: {context}\n\nCode:\n