"""
DeepSentinel Demo Script
Run this for the 3-minute hackathon demo.
Scans the demo-vulnerable-app PR and shows cross-source intelligence.
"""
import asyncio
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env'))

from src.analysis.security_analyzer import init_overmind
init_overmind()

from src.data.airbyte_client import AirbyteDataLayer
from src.storage.aerospike_cache import AerospikeCache
from src.storage.ghost_db import GhostDB
from src.analysis.security_analyzer import SecurityAnalyzer
from src.analysis.macroscope_client import MacroscopeClient
from src.llm.truefoundry_gateway import TrueFoundryGateway
from src.auth.auth0_client import Auth0Client


async def demo():
    print()
    print("=" * 70)
    print("  DEEPSENTINEL — Cross-Source Security Intelligence")
    print("  'Existing tools scan code. We scan context.'")
    print("=" * 70)
    print()

    # === Initialize all 7 integrations ===
    print("[INIT] Connecting 7 sponsor integrations...\n")

    auth = Auth0Client()
    data = AirbyteDataLayer()
    macroscope = MacroscopeClient()
    llm = TrueFoundryGateway()
    db = GhostDB()
    cache = AerospikeCache()

    cache.connect()
    cache.load_patterns()
    await db.connect()

    print()
    print("-" * 70)
    print()

    # === Scan PR #1 ===
    owner = "ElijahUmana"
    repo = "demo-vulnerable-app"
    pr_number = 1

    print(f"[SCAN] Target: {owner}/{repo} PR #{pr_number}")
    print(f"[SCAN] Starting autonomous security analysis...\n")

    start = time.time()

    # Step 1: Gather cross-source context
    print("[1/6] GATHER — Pulling data via Airbyte connectors...")
    context = await data.gather_full_context(owner, repo, pr_number)
    print()

    # Step 2: Architecture analysis
    print("[2/6] UNDERSTAND — Analyzing codebase architecture via Macroscope...")
    for f in context.github.changed_files:
        fctx = macroscope._static_context(f.get("path", ""))
        print(f"  {f.get('path')}: module={fctx['module']}, criticality={fctx['criticality']}")
    print()

    # Step 3: Cache check
    print("[3/6] CACHE — Checking Aerospike for known patterns...")
    patterns = cache.get_patterns()
    print(f"  {len(patterns)} vulnerability patterns loaded")
    print()

    # Step 3.5: Pull cross-source context from GitHub Issues + PR comments
    print("[3.5/6] CROSS-SOURCE — Pulling GitHub Issues + PR review comments...")
    security_issues = await data.get_security_issues(owner, repo)
    pr_comments = await data.get_pr_comments(owner, repo, pr_number)
    print(f"  {len(security_issues)} security issues, {len(pr_comments)} PR review comments")

    # Build context strings from real GitHub data
    cross_source_context = []
    for issue in security_issues:
        cross_source_context.append(
            f"Issue #{issue['number']} ({issue.get('created_at', '')[:10]}): '{issue['title']}'"
        )
    for comment in pr_comments:
        cross_source_context.append(
            f"PR #{pr_number} review ({comment.get('created_at', '')[:10]}): "
            f"'{comment.get('body', '')[:120]}'"
        )

    # Build correlations from real data
    from src.data.airbyte_client import GitHubIssueContext
    issue_ctx = GitHubIssueContext(issues=security_issues, pr_comments=pr_comments)
    real_correlations = data.correlate_issues_with_code(
        context.github.changed_files, issue_ctx, pr_number
    )
    print(f"  {len(real_correlations)} cross-source correlations discovered")

    # Step 4: Multi-model analysis
    print("[4/6] ANALYZE — Running security analysis via TrueFoundry AI Gateway...")
    print("  (All LLM calls instrumented by Overmind for optimization)")

    analysis_context = {
        "files": context.github.changed_files,
        "architecture": {f.get("path", ""): macroscope._static_context(f.get("path", "")) for f in context.github.changed_files},
        "slack_context": cross_source_context,
        "historical_patterns": [
            {"cwe": "CWE-89", "count": 3, "last_seen": "2026-02-15"},
            {"cwe": "CWE-798", "count": 2, "last_seen": "2026-01-20"},
        ],
        "correlations": real_correlations,
    }

    findings = analyzer = SecurityAnalyzer(llm, cache)
    findings = analyzer.analyze(analysis_context)

    # Enrich with Macroscope context
    for f in findings:
        f = macroscope.enrich_finding(f)

    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print(f"\n  Findings: {len(findings)} total")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in severity_counts:
            print(f"    {sev}: {severity_counts[sev]}")
    print()

    # Step 5: Store in Ghost
    print("[5/6] STORE — Persisting results in Ghost Postgres...")
    import uuid
    scan_id = f"demo-{uuid.uuid4().hex[:8]}"
    await db.start_scan(scan_id, owner, repo, pr_number)
    for f in findings:
        f["scan_id"] = scan_id
        f["repo_owner"] = owner
        f["repo_name"] = repo
        f["pr_number"] = pr_number
        await db.record_vulnerability(f)
    for corr in analysis_context["correlations"]:
        await db.record_correlation(scan_id, corr)
    print(f"  {len(findings)} findings + {len(analysis_context['correlations'])} correlations stored")
    print()

    # Step 6: Report
    print("[6/6] REPORT — Generating security report...")

    # CIBA for critical findings
    critical_count = severity_counts.get("CRITICAL", 0)
    if critical_count > 0:
        print(f"\n  [Auth0 CIBA] {critical_count} CRITICAL findings require human approval")
        approved = await auth.request_approval(
            f"Create security tickets for {critical_count} critical vulnerabilities",
            f"{owner}/{repo} PR #{pr_number}"
        )
        if approved:
            print("  [Auth0 CIBA] Approved — proceeding with ticket creation")
    print()

    report = analyzer.generate_report(findings, analysis_context["correlations"])
    elapsed = time.time() - start

    print("=" * 70)
    print(f"  SCAN COMPLETE in {elapsed:.1f}s")
    print(f"  Findings: {len(findings)} ({critical_count} critical)")
    print(f"  Cross-source correlations: {len(analysis_context['correlations'])}")
    print("=" * 70)
    print()
    print(report)
    print()
    print("=" * 70)
    print("  WHAT SNYK/CODEQL MISSED (from REAL GitHub Issues + PR comments):")
    print()
    for corr in analysis_context["correlations"]:
        print(f"  > {corr['risk_note']}")
        context_ref = corr.get('context_ref', corr.get('slack_ref', ''))
        print(f"    Source: {context_ref} <-> {corr['github_ref']}")
        why = corr.get('why_code_only_misses', '')
        if why:
            print(f"    WHY SCANNERS MISS: {why}")
        print()
    print("  DeepSentinel found these because it scans CONTEXT, not just code.")
    print("  All correlations above come from REAL GitHub data (Issues #2, #3 + PR #1 comments).")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(demo())
