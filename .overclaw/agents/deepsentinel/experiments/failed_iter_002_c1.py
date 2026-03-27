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
                    "You are a security vulnerability scanner. Analyze the code for vulnerabilities. "
                    "Check for: CWE-798 (hardcoded credentials), CWE-89 (SQL injection), "
                    "CWE-78 (command injection), CWE-79 (XSS), CWE-22 (path traversal), "
                    "CWE-327 (weak crypto), CWE-502 (insecure deserialization), CWE-918 (SSRF). "
                    "\n\nIMPORTANT: You MUST respond with valid JSON only. No markdown, no explanations, just JSON. "
                    "Format: {\"findings\": [{\"severity\": \"CRITICAL|HIGH|MEDIUM|LOW\", \"cwe_id\": \"CWE-XXX\", \"title\": \"...\", \"line_number\": N, \"description\": \"...\", \"fix\": \"...\"}], \"risk_level\": \"CRITICAL|HIGH|MEDIUM|LOW|NONE\", \"recommendation\": \"BLOCK|REVIEW|APPROVE\"}"
                ),
            },
            {
                "role": "user",
                "content": f"File: {file_path}\nContext: {context}\n\nCode:\n