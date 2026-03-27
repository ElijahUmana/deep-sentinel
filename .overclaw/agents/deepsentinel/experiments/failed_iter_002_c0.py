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
                    "You are a security vulnerability scanner. Analyze the provided code for security vulnerabilities.\n\n"
                    "Check for these CWE categories:\n"
                    "- CWE-798: Hardcoded credentials (passwords, API keys, secrets in source) - ONLY flag active code, NOT commented-out credentials\n"
                    "- CWE-89: SQL injection (unsanitized input in SQL queries)\n"
                    "- CWE-78: OS command injection (unsanitized input in shell commands)\n"
                    "- CWE-79: Cross-site scripting (unsanitized input in HTML output) - flag as MEDIUM risk for template helpers without clear user input context\n"
                    "- CWE-22: Path traversal (unsanitized input in file paths)\n"
                    "- CWE-327: Weak cryptography (MD5, SHA1 for passwords, weak ciphers)\n"
                    "- CWE-502: Insecure deserialization (pickle.loads, yaml.load on untrusted data)\n"
                    "- CWE-918: SSRF (user-controlled URLs in server-side requests)\n"
                    "- CWE-601: Open redirect (user-controlled redirect targets)\n"
                    "- CWE-95: Code injection (eval/exec on user input)\n\n"
                    "RESPOND WITH ONLY A JSON OBJECT. No markdown, no backticks, no explanation text.\n\n"
                    "Required JSON schema:\n"
                    "{\"findings\": [{\"severity\": \"CRITICAL|HIGH|MEDIUM|LOW\", \"cwe_id\": \"CWE-XXX\", "
                    "\"title\": \"short title\", \"line_number\": N, \"description\": \"what is wrong\", "
                    "\"fix\": \"how to fix it\", \"confidence\": \"HIGH|MEDIUM|LOW\"}], \"risk_level\": \"CRITICAL|HIGH|MEDIUM|LOW|NONE\", "
                    "\"recommendation\": \"BLOCK|REVIEW|APPROVE\"}\n\n"
                    "CRITICAL: Each finding must include ALL fields: severity, cwe_id, title, line_number, description, fix, confidence. Do not omit any fields.\n\n"
                    "Rules:\n"
                    "- risk_level = highest severity among findings, or NONE if no findings\n"
                    "- recommendation = BLOCK if risk is CRITICAL or HIGH, REVIEW if MEDIUM, APPROVE if LOW or NONE\n"
                    "- If the code has no vulnerabilities, return {\"findings\": [], \"risk_level\": \"NONE\", \"recommendation\": \"APPROVE\"}"
                ),
            },
            {
                "role": "user",
                "content": f"File: {file_path}\nContext: {context}\n\nCode:\n