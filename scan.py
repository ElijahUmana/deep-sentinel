#!/usr/bin/env python3
"""
DeepSentinel CLI — Scan any GitHub repository for security vulnerabilities.

Usage:
    python scan.py <owner> <repo>                    # Full repo scan
    python scan.py <owner> <repo> --pr <number>      # PR-specific scan
    python scan.py <owner> <repo> --autonomous       # Continuous monitoring

Examples:
    python scan.py ElijahUmana demo-vulnerable-app
    python scan.py ElijahUmana demo-vulnerable-app --pr 1
    python scan.py OWASP juice-shop
"""
import asyncio
import argparse
import os
import sys

from dotenv import load_dotenv
load_dotenv()

from src.analysis.security_analyzer import init_overmind
init_overmind()

from src.main import DeepSentinel


async def main():
    parser = argparse.ArgumentParser(
        description="DeepSentinel — Cross-source security intelligence",
        epilog="Scans GitHub repos for vulnerabilities using cross-source context from Slack, "
               "codebase architecture, and historical patterns."
    )
    parser.add_argument("owner", help="GitHub repository owner")
    parser.add_argument("repo", help="GitHub repository name")
    parser.add_argument("--pr", type=int, help="PR number to scan (scans full repo if omitted)")
    parser.add_argument("--autonomous", action="store_true", help="Continuous monitoring mode")
    parser.add_argument("--sarif", action="store_true", help="Generate SARIF output")

    args = parser.parse_args()

    sentinel = DeepSentinel()
    await sentinel.initialize()

    if args.autonomous:
        await sentinel.run_autonomous(args.owner, args.repo)
    else:
        pr_number = args.pr or 0
        result = await sentinel.scan_pr(args.owner, args.repo, pr_number)

        if args.sarif and result:
            from src.output.sarif_report import generate_sarif, save_sarif
            sarif = generate_sarif(
                result.get("findings", []),
                result.get("correlations", []),
                {"scan_id": result.get("scan_id", ""), "repository": f"{args.owner}/{args.repo}"}
            )
            save_sarif(sarif, f"deepsentinel-{result.get('scan_id', 'scan')}.sarif.json")

    await sentinel.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
