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
                    "risk_level (CRITICAL/HIGH/MEDIUM/LOW/NONE), recommendation (BLOCK/REVIEW/APPROVE)."
                ),
            },
            {
                "role": "user",
                "content": f"File: {file_path}\nContext: {context}\n\nCode:\n```\n{code}\n```",
            },
        ],
    )

    # Parse the response
    content = response.get("content", "") if isinstance(response, dict) else str(response)

    try:
        # Try to extract JSON from response
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0]
        elif "```" in content:
            content = content.split("```")[1].split("```")[0]

        result = json.loads(content.strip())
        return {
            "findings": result.get("findings", []),
            "risk_level": result.get("risk_level", "UNKNOWN"),
            "recommendation": result.get("recommendation", "REVIEW"),
            "findings_count": len(result.get("findings", [])),
        }
    except (json.JSONDecodeError, IndexError):
        # Regex fallback for finding count
        finding_count = len(re.findall(r"CWE-\d+", content))
        return {
            "findings": [],
            "risk_level": "UNKNOWN",
            "recommendation": "REVIEW",
            "findings_count": finding_count,
            "raw_analysis": content[:500],
        }
