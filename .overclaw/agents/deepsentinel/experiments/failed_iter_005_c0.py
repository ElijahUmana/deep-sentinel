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
                    "CRITICAL: You must respond with valid JSON only. Do not include any text before or after the JSON object. "
                    "Example format: {\"findings\": [{\"severity\": \"HIGH\", \"cwe_id\": \"CWE-89\", \"title\": \"SQL Injection\", \"line_number\": 1, \"description\": \"Direct string concatenation in SQL query\", \"fix\": \"Use parameterized queries\"}], \"risk_level\": \"HIGH\", \"recommendation\": \"BLOCK\"} "
                    "Map findings to risk levels: CRITICAL (any CWE-78, CWE-89 with direct injection), HIGH (multiple high-severity findings), MEDIUM (single medium finding), LOW (minor issues), NONE (no vulnerabilities found). "
                    "Recommendation should be BLOCK for CRITICAL/HIGH, REVIEW for MEDIUM, APPROVE for LOW/NONE. "
                    "Return a JSON object with: findings (array of {severity, cwe_id, title, line_number, description, fix}), "
                    "risk_level (CRITICAL/HIGH/MEDIUM/LOW/NONE), recommendation (BLOCK/REVIEW/APPROVE)."
                ),
            },
            {
                "role": "user",
                "content": f"File: {file_path}\nContext: {context}\n\nCode:\n