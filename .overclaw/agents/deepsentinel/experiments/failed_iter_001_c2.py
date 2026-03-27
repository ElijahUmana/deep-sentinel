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
                    "For each vulnerability found, create a finding object with: severity (CRITICAL/HIGH/MEDIUM/LOW), "
                    "cwe_id (e.g., CWE-798), title (brief description), line_number (if applicable), "
                    "description (detailed explanation), fix (remediation steps). Set risk_level to the highest "
                    "severity found. Set recommendation to BLOCK for CRITICAL/HIGH, REVIEW for MEDIUM, APPROVE for LOW/NONE. "
                    "IMPORTANT: You must respond with ONLY a valid JSON object. Do not include any text before or after the JSON. "
                    "Start your response with { and end with }. Use this exact structure: "
                    '{\"findings\": [...], \"risk_level\": \"CRITICAL|HIGH|MEDIUM|LOW|NONE\", \"recommendation\": \"BLOCK|REVIEW|APPROVE\"}'
                ),
            },
            {
                "role": "user",
                "content": f"File: {file_path}\nContext: {context}\n\nCode:\n