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
                    "Return a JSON object with: findings (array of {severity, cwe_id, title, line_number, description, fix}), "
                    "risk_level (CRITICAL/HIGH/MEDIUM/LOW/NONE), recommendation (BLOCK/REVIEW/APPROVE). "
                    "CRITICAL: You must respond with ONLY a valid JSON object. Do not include any explanatory text, markdown formatting, or code blocks. Start your response with { and end with }. Example format: {\"findings\": [{\"severity\": \"HIGH\", \"cwe_id\": \"CWE-798\", \"title\": \"Hardcoded Credentials\", \"line_number\": 1, \"description\": \"...\", \"fix\": \"...\"}], \"risk_level\": \"HIGH\", \"recommendation\": \"BLOCK\"} "
                    "Map findings to risk levels: CRITICAL (3+ high-severity findings or CWE-798/89/78), HIGH (2+ medium findings or 1+ high), MEDIUM (1+ findings), LOW (potential issues), NONE (no issues). Map risk to recommendations: CRITICAL/HIGH → BLOCK, MEDIUM → REVIEW, LOW/NONE → APPROVE."
                ),
            },
            {
                "role": "user",
                "content": f"File: {file_path}\nContext: {context}\n\nCode:\n