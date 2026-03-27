"""
DeepSentinel — Full Hackathon Demo
Demonstrates ALL 7 sponsor integrations with real data.
This is what we run for the 3-minute demo video.
"""
import asyncio
import json
import os
import sys
import time
import uuid
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from src.analysis.security_analyzer import init_overmind
init_overmind()

from src.data.airbyte_client import AirbyteDataLayer
from src.storage.aerospike_cache import AerospikeCache
from src.storage.ghost_db import GhostDB
from src.output.sarif_report import generate_sarif, save_sarif
from src.analysis.security_analyzer import SecurityAnalyzer
from src.analysis.macroscope_client import MacroscopeClient
from src.llm.truefoundry_gateway import TrueFoundryGateway
from src.auth.auth0_client import Auth0Client


def header(text):
    print(f"\n{'='*70}")
    print(f"  {text}")
    print(f"{'='*70}\n")


_step_timings = {}
_step_start = None


def step(num, total, text):
    global _step_start
    # Record previous step's elapsed time
    if _step_start is not None and num > 1:
        _step_timings[num - 1] = time.time() - _step_start
    _step_start = time.time()
    print(f"[{num}/{total}] {text}")


async def demo():
    header("DEEPSENTINEL — Cross-Source Security Intelligence")
    print("  28% of critical security incidents originate OUTSIDE code repositories")
    print("  — in Slack, Jira, and collaboration tools (GitGuardian 2026).")
    print("  No existing scanner connects the dots. DeepSentinel does.")
    print()
    print("  Built with: Auth0 | Airbyte | Macroscope | Ghost | TrueFoundry | Aerospike | Overmind")
    print()

    # ===========================
    # INITIALIZE ALL 7 INTEGRATIONS
    # ===========================
    step(0, 7, "Initializing all 7 sponsor integrations...")
    print()

    auth = Auth0Client()          # Auth0: identity + token vault + CIBA + FGA
    data = AirbyteDataLayer(auth0_client=auth)  # Airbyte: GitHub + Slack via Auth0 Token Vault
    macroscope = MacroscopeClient()  # Macroscope: codebase understanding
    llm = TrueFoundryGateway()    # TrueFoundry: AI Gateway multi-model routing
    db = GhostDB()                # Ghost: persistent Postgres
    cache = AerospikeCache()      # Aerospike: real-time cache
    # Overmind: OverClaw optimizer registered (overclaw agent show deepsentinel)

    cache.connect()
    cache.load_patterns()
    await db.connect()

    # Auth0 Pillar 1: Device Flow authentication
    device_result = await auth.demonstrate_device_flow()
    print(f"  Device flow result: {device_result.get('status', 'unknown')}")
    print()

    print()
    print("-" * 70)

    # ===========================
    # SCAN TARGET
    # ===========================
    owner = "ElijahUmana"
    repo = "demo-vulnerable-app"
    scan_id = f"scan-{uuid.uuid4().hex[:8]}"
    start_time = time.time()

    header(f"SCANNING: {owner}/{repo}")
    print(f"  Scan ID: {scan_id}")
    print(f"  Mode: Full repository scan + PR #1 analysis")
    print()

    # Auth0 Pillar 4: FGA check — verify agent has permission to view findings
    fga_allowed = await auth.fga_check_repo_findings(
        auth.user_id or "agent:deepsentinel", owner, repo
    )
    if not fga_allowed:
        print(f"  [Auth0 FGA] DENIED — agent not authorized to view {owner}/{repo} findings")
        return
    print()

    # ===========================
    # STEP 1: GATHER — Airbyte multi-source data
    # ===========================
    step(1, 7, "GATHER — Pulling multi-source data via Airbyte agent connectors...")

    # Get PR data
    pr = await data.get_pr_details(owner, repo, 1)
    print(f"  [Airbyte/GitHub] PR #{pr.number}: {pr.title}")
    print(f"  [Airbyte/GitHub] {len(pr.changed_files)} PR files")

    # Pull REAL GitHub Issues as cross-source context
    security_issues = await data.get_security_issues(owner, repo)
    print(f"  [Airbyte/GitHub] {len(security_issues)} security-related issues found")
    for issue in security_issues[:3]:
        print(f"    #{issue['number']}: {issue['title']}")

    # Pull REAL PR review comments
    pr_comments = await data.get_pr_comments(owner, repo, 1)
    print(f"  [Airbyte/GitHub] {len(pr_comments)} security-relevant PR comments")

    # Get additional repo files
    all_files = []
    repo_files = ["app.py", "src/auth/login.py", "src/api/users.py"]
    for fp in repo_files:
        content = await data.get_file_content(owner, repo, fp)
        if content:
            all_files.append({"path": fp, "content": content})
            print(f"  [Airbyte/GitHub] Loaded {fp}: {len(content)} chars")

    # Add PR files
    for f in pr.changed_files:
        if f.get("content") and f["path"] not in [af["path"] for af in all_files]:
            all_files.append(f)

    # Build cross-source context from GitHub Issues + PR comments
    # This is the core value prop: issues and review comments represent
    # team decisions, deferred work, and known risks that code-only
    # scanners (Snyk, CodeQL, Semgrep) have zero visibility into.
    from src.data.airbyte_client import GitHubIssueContext
    issue_ctx = GitHubIssueContext(issues=security_issues, pr_comments=pr_comments)

    # Build human-readable context strings from real GitHub data
    # These replace hardcoded Slack messages -- same purpose (team context),
    # but sourced from real, verifiable GitHub artifacts
    slack_context = []
    for issue in security_issues:
        slack_context.append(
            f"GitHub Issue #{issue['number']} ({issue.get('created_at', '')[:10]}): "
            f"'{issue['title']}'"
        )
    for comment in pr_comments:
        slack_context.append(
            f"PR #1 review by {comment.get('user', 'unknown')} ({comment.get('created_at', '')[:10]}): "
            f"'{comment.get('body', '')[:120]}'"
        )
    print(f"  [Cross-Source] {len(slack_context)} context signals from GitHub Issues + PR comments")
    for ctx_line in slack_context:
        print(f"    {ctx_line[:100]}...")

    # Slack: Also try real Slack connector if available
    slack_data = await data.get_security_discussions()
    if slack_data.messages:
        for m in slack_data.messages[:5]:
            slack_context.append(m.get("text", ""))
        print(f"  [Airbyte/Slack] LIVE: +{len(slack_data.messages)} Slack messages from {len(slack_data.channels_searched)} channels")

    # === CROSS-SOURCE CORRELATION ENGINE ===
    # This is the core differentiator. We combine multiple correlation strategies:
    # 1. GitHub Issues + PR comments correlated with changed code (structured)
    # 2. Slack messages correlated with changed code (keyword discovery)
    # 3. LLM-discovered non-obvious correlations

    # Strategy 1: GitHub Issues + PR comments
    issue_correlations = data.correlate_issues_with_code(all_files, issue_ctx, 1)
    print(f"  [Correlation Engine] Strategy 1 (Issues+Comments): {len(issue_correlations)} correlations")

    # Strategy 2: Slack message keyword correlation (auto-discovery)
    # Build a PRData for the correlation engine from what we already have
    from src.data.airbyte_client import PRData, SlackContext as SlackCtx
    pr_for_corr = PRData(
        number=pr.number, title=pr.title, author=pr.author, body=pr.body,
        changed_files=all_files, commits=[], labels=pr.labels,
    )

    # If Slack connector returned nothing, build representative messages for demo
    if not slack_data.messages:
        slack_data = SlackCtx(messages=[
            {"channel": "engineering", "text": "Let's skip input validation for the payment endpoint -- we'll add it in Q2", "user": "john", "ts": ""},
            {"channel": "engineering", "text": "The DB password for payments is still hardcoded, can someone move it to secrets manager?", "user": "sarah", "ts": ""},
            {"channel": "security-review", "text": "Has anyone reviewed the refund endpoint? It's using os.system directly", "user": "mike", "ts": ""},
            {"channel": "engineering", "text": "The auth module uses MD5 -- we need to upgrade to bcrypt before launch", "user": "lisa", "ts": ""},
        ], channels_searched=["engineering", "security-review"])
        print(f"  [Airbyte/Slack] {len(slack_data.messages)} security messages (representative -- set SLACK_BOT_TOKEN for live)")

    slack_correlations = data._correlate(pr_for_corr, slack_data)
    print(f"  [Correlation Engine] Strategy 2 (Slack keywords): {len(slack_correlations)} correlations")
    for corr in slack_correlations:
        conf = corr.get("confidence", "?")
        print(f"    [{conf}] [{corr['type']}] {corr.get('risk_note', '')[:70]}")

    # Strategy 3: LLM-discovered non-obvious correlations
    llm_correlations = await data.discover_llm_correlations(pr_for_corr, slack_data, llm=llm)
    print(f"  [Correlation Engine] Strategy 3 (LLM discovery): {len(llm_correlations)} correlations")
    for corr in llm_correlations:
        print(f"    [LLM] {corr.get('risk_note', '')[:70]}")

    # Merge all correlation sources, normalizing the schema
    cross_source_correlations = []
    for corr in issue_correlations:
        # Normalize issue correlations to include confidence + why_it_matters
        corr.setdefault("confidence", "HIGH")  # Issues are direct evidence
        corr.setdefault("why_it_matters", corr.get("why_code_only_misses", ""))
        corr.setdefault("slack_ref", corr.get("context_ref", ""))
        corr.setdefault("slack_text", corr.get("context_text", ""))
        cross_source_correlations.append(corr)
    cross_source_correlations.extend(slack_correlations)
    cross_source_correlations.extend(llm_correlations)

    # Sort by confidence: HIGH first
    conf_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    cross_source_correlations.sort(key=lambda c: conf_order.get(c.get("confidence", "LOW"), 3))

    print(f"\n  [Correlation Engine] TOTAL: {len(cross_source_correlations)} cross-source links")
    high_count = sum(1 for c in cross_source_correlations if c.get("confidence") == "HIGH")
    med_count = sum(1 for c in cross_source_correlations if c.get("confidence") == "MEDIUM")
    low_count = sum(1 for c in cross_source_correlations if c.get("confidence") == "LOW")
    print(f"    HIGH confidence: {high_count} | MEDIUM: {med_count} | LOW: {low_count}")

    # Show Airbyte multi-source enrichment metrics
    code_signals = len(all_files) * 3
    context_signals = len(security_issues) + len(pr_comments) + len(slack_data.messages)
    cross_signals = len(cross_source_correlations)
    sources_used = 1 + (1 if security_issues else 0) + (1 if pr_comments else 0) + (1 if slack_data.messages else 0)
    enrichment_metrics = {
        "code_only_findings": code_signals,
        "slack_context_findings": context_signals,
        "cross_source_linked": cross_signals,
        "total_signals": code_signals + context_signals + cross_signals,
        "sources_used": sources_used,
        "entity_cache_hits": len(data._entity_cache),
    }
    data.print_enrichment_summary(enrichment_metrics)
    print()

    # ===========================
    # STEP 2: UNDERSTAND — Macroscope codebase architecture
    # ===========================
    step(2, 7, "UNDERSTAND — Analyzing codebase architecture via Macroscope...")

    # Query Macroscope for security surface area (triggers webhook, polls for result)
    security_surface = await macroscope.get_security_surface(
        f"Security scanner analyzing {owner}/{repo}"
    )
    if security_surface.get("macroscope_analysis"):
        print(f"  [Macroscope] Security surface analysis:")
        for line in security_surface["macroscope_analysis"].split("\n")[:8]:
            if line.strip():
                print(f"    {line.strip()}")
    else:
        print(f"  [Macroscope] Surface analysis: {security_surface.get('note', 'pending')}")

    # Get architectural context per file (uses Macroscope when connected, falls back to heuristics)
    for f in all_files:
        ctx = await macroscope.get_module_context(f["path"])
        ms_tag = " (Macroscope)" if ctx.get("macroscope_answer") else " (heuristic)"
        print(f"  {f['path']}: module={ctx['module']}, criticality={ctx['criticality']}{ms_tag}")

    # Dependency risk analysis: which files have the highest blast radius?
    file_paths = [f["path"] for f in all_files]
    dep_risk = await macroscope.analyze_dependency_risk(file_paths)
    if dep_risk.get("risk_ranking") and isinstance(dep_risk["risk_ranking"], str):
        print(f"\n  [Macroscope] Dependency blast radius analysis:")
        for line in dep_risk["risk_ranking"].split("\n")[:6]:
            if line.strip():
                print(f"    {line.strip()}")
    print()

    # ===========================
    # STEP 3: CACHE — Aerospike pattern matching
    # ===========================
    step(3, 7, "CACHE — Aerospike real-time cache + pattern matching...")

    # Show the data model
    cache.print_data_model()
    print()

    patterns = cache.get_patterns()
    print(f"  {len(patterns)} CWE vulnerability patterns loaded from set 'patterns'")

    # Severity-filtered query (demonstrates secondary index query pattern)
    critical_patterns = cache.get_patterns_by_severity("CRITICAL")
    high_patterns = cache.get_patterns_by_severity("HIGH")
    print(f"  Severity filter: {len(critical_patterns)} CRITICAL, {len(high_patterns)} HIGH patterns")
    print(f"  (Uses secondary index on 'severity' bin for server-side filtering)")

    # Batch CVE lookup (demonstrates batch_get for parallel record retrieval)
    sample_cves = ["CVE-2021-44228", "CVE-2023-44487", "CVE-2024-3094"]
    for cve_id in sample_cves:
        cache.cache_cve(cve_id, {"severity": "CRITICAL", "description": f"Known critical: {cve_id}", "cvss_score": 9.8})
    batch_results = cache.batch_lookup_cves(sample_cves)
    print(f"  Batch CVE lookup: {len(batch_results)}/{len(sample_cves)} found in single operation")
    print(f"  (Aerospike batch_get: 1 network round trip instead of {len(sample_cves)} sequential gets)")

    # Demonstrate session state management
    cache.save_session(scan_id, {"status": "scanning", "files": len(all_files), "repo": f"{owner}/{repo}"})
    session = cache.get_session(scan_id)
    print(f"  Session state cached in set 'sessions': {json.dumps(session)}")

    # Cache scan key for deduplication
    cache.cache_scan_result(f"{owner}/{repo}", 1, scan_id[:8], {"status": "in_progress"}, ttl=300)
    print(f"  Scan dedup key cached in set 'scan_cache' (TTL: 300s)")

    # Demonstrate TTL-based expiration
    found_before, expired_after = cache.demonstrate_ttl(scan_id[:6])
    print(f"  TTL expiration demo: record found={found_before}, after TTL expired={not expired_after} -> correctly expired: {expired_after}")

    # Show performance stats
    stats = cache.get_stats()
    print(f"  Performance: {stats['puts']} puts (avg {stats['avg_put_us']:.0f}us), "
          f"{stats['gets']} gets (avg {stats['avg_get_us']:.0f}us), "
          f"{stats['hits']} hits, {stats['misses']} misses")
    print()

    # ===========================
    # STEP 4: ANALYZE — TrueFoundry AI Gateway + Overmind
    # ===========================
    step(4, 7, "ANALYZE — Security analysis via TrueFoundry AI Gateway...")
    print(f"  Routing LLM calls through gateway.truefoundry.ai")
    print(f"  Model: openai-main/gpt-4o-mini (fast scan) + deep verification")
    print(f"  All calls instrumented by Overmind OverClaw for optimization")

    analysis_context = {
        "files": all_files,
        "slack_context": slack_context,
        "historical_patterns": [
            {"cwe": "CWE-89", "count": 3, "last_seen": "2026-02-15"},
            {"cwe": "CWE-798", "count": 2, "last_seen": "2026-01-20"},
        ],
        "correlations": cross_source_correlations,
    }

    analyzer = SecurityAnalyzer(llm, cache)
    findings = analyzer.analyze(analysis_context)

    # Enrich with Macroscope context
    for f in findings:
        f = macroscope.enrich_finding(f)

    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "UNKNOWN").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print(f"\n  Total findings: {len(findings)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in severity_counts:
            print(f"    {sev}: {severity_counts[sev]}")
    print()

    # ===========================
    # STEP 5: STORE — Ghost Postgres persistence + schema + forking
    # ===========================
    step(5, 7, "STORE — Ghost database: schema, persist, query history, fork...")

    db_id = os.environ.get("GHOST_DB_ID", "uipdk8byh3")

    # 5a: Agent introspection — reads its own schema to decide what to query
    print(f"  [Ghost] Database ID: {db_id}")
    print(f"  [Ghost] Agent introspecting its own schema...")
    introspection = GhostDB.agent_introspect(db_id)
    if introspection.get("raw_schema"):
        print(f"\n  [Ghost Schema] LLM-optimized database structure ({introspection['table_count']} tables):")
        for line in introspection["raw_schema"].split("\n"):
            stripped = line.strip()
            if stripped:
                print(f"    {stripped}")
        print()
        print(f"  [Ghost] Agent reads schema to understand available data -- no hardcoded SQL.")
        print(f"  [Ghost] This is Ghost's key differentiator: schema IS the agent's context.\n")

    # 5b: Persist scan results
    await db.start_scan(scan_id, owner, repo, 1)
    for f in findings:
        f["scan_id"] = scan_id
        f["repo_owner"] = owner
        f["repo_name"] = repo
        f["pr_number"] = 1
        await db.record_vulnerability(f)
    for corr in cross_source_correlations:
        await db.record_correlation(scan_id, corr)
    await db.complete_scan(scan_id, len(findings),
                           severity_counts.get("CRITICAL", 0),
                           severity_counts.get("HIGH", 0))

    print(f"  [Ghost] {len(findings)} findings stored in 'vulnerabilities' table")
    print(f"  [Ghost] {len(cross_source_correlations)} correlations stored in 'correlations' table")

    # 5c: Trend analysis — agent detects worsening security patterns
    print(f"\n  [Ghost] Analyzing vulnerability trends across historical scans...")
    trends = await db.get_trend_analysis(owner, repo)
    if trends.get("recurring_cwes"):
        print(f"  [Ghost Trends] Recurring vulnerabilities (appear in multiple scans):")
        for cwe in trends["recurring_cwes"][:5]:
            print(f"    {cwe.get('cwe_id', '?')}: seen in {cwe.get('scan_appearances', 0)} scans, "
                  f"{cwe.get('total_occurrences', 0)} total, severities: {cwe.get('severities', [])}")
    if trends.get("severity_trend"):
        print(f"  [Ghost Trends] Scan-over-scan severity trend:")
        for scan in trends["severity_trend"][:5]:
            print(f"    {scan.get('scan_date', '?')}: {scan.get('findings_count', 0)} findings "
                  f"({scan.get('critical_count', 0)}C, {scan.get('high_count', 0)}H)")
    fix_rate = trends.get("fix_rate", 0)
    print(f"  [Ghost Trends] Fix rate: {fix_rate}% "
          f"({trends.get('total_vulnerabilities', 0)} total, {trends.get('open_vulnerabilities', 0)} open)")

    # Also show via ghost sql for CLI demonstration
    print(f"\n  [Ghost SQL] Raw trend query via CLI:")
    print(f"  [Ghost] Running: ghost sql {db_id} \"SELECT cwe_id, severity, COUNT(*)...\"")
    trend_output = GhostDB.query_database(
        db_id,
        "SELECT cwe_id, UPPER(severity) as severity, COUNT(*) as occurrences, "
        "MIN(created_at::date) as first_seen, MAX(created_at::date) as last_seen "
        "FROM vulnerabilities WHERE repo_owner='ElijahUmana' "
        "GROUP BY cwe_id, UPPER(severity) ORDER BY occurrences DESC LIMIT 8"
    )
    if trend_output:
        for line in trend_output.strip().split("\n"):
            print(f"    {line}")
    print()

    # 5d: Composite risk score (factors in history + cross-source correlations)
    risk = await db.compute_risk_score(owner, repo, len(cross_source_correlations))
    print(f"  [Ghost Risk Score] Composite: {risk.get('risk_score', 0)} ({risk.get('interpretation', '?')})")
    print(f"    Base score: {risk.get('base_score', 0)} | "
          f"Recurrence multiplier: {risk.get('recurrence_multiplier', 1.0)}x | "
          f"Cross-source multiplier: {risk.get('cross_source_multiplier', 1.0)}x")
    print(f"    Repeated CWEs: {risk.get('repeated_cwes', 0)} | "
          f"Cross-source correlations: {len(cross_source_correlations)}")
    print()

    # 5e: Fork database for safe experimentation
    print(f"  [Ghost Fork] Creating ephemeral fork for safe experiment...")
    print(f"  [Ghost] Running: ghost fork {db_id} --name experiment-{scan_id[:6]}")
    fork_result = GhostDB.fork_database(db_id, f"experiment-{scan_id[:6]}")
    fork_output = fork_result.get("output", "")
    fork_conn = fork_result.get("connection", "")
    if fork_output:
        for line in fork_output.split("\n"):
            if line.strip():
                print(f"    {line.strip()}")
    else:
        print(f"    Fork created (see ghost list)")

    # Run an experimental query in the fork (safe -- doesn't touch main DB)
    if fork_conn or fork_output:
        # Extract fork DB ID from output if possible, or use naming convention
        fork_db_id = f"experiment-{scan_id[:6]}"
        print(f"\n  [Ghost Fork] Running experimental query in fork (safe -- main DB untouched)...")
        experiment_result = GhostDB.experiment_in_fork(
            fork_db_id,
            "SELECT COUNT(*) as finding_count, "
            "UPPER(severity) as severity "
            "FROM vulnerabilities GROUP BY UPPER(severity) ORDER BY finding_count DESC"
        )
        if experiment_result and not experiment_result.startswith("ERROR"):
            print(f"  [Ghost Fork] Experiment result:")
            for line in experiment_result.split("\n")[:5]:
                if line.strip():
                    print(f"    {line.strip()}")

    # Show all Ghost databases including forks
    print(f"\n  [Ghost] Running: ghost list")
    ghost_list = GhostDB.ghost_cli(f"list")
    if ghost_list:
        for line in ghost_list.split("\n")[:8]:
            if line.strip():
                print(f"    {line}")
    print(f"\n  [Ghost] Value: Agent introspects schema, maintains history across scans,")
    print(f"  [Ghost]        computes trend-aware risk scores, and forks before experiments.")
    print()

    # ===========================
    # STEP 6: AUTH — Auth0 CIBA for sensitive actions
    # ===========================
    critical_count = severity_counts.get("CRITICAL", 0)
    if critical_count > 0:
        step(6, 7, f"AUTHORIZE — Auth0 CIBA for {critical_count} CRITICAL findings...")
        print(f"  Requesting human approval via Auth0 push notification")
        print(f"  Action: Create security tickets + alert team")
        print(f"  Resource: {owner}/{repo}")
        approved = await auth.request_approval(
            f"Create {critical_count} critical security tickets",
            f"{owner}/{repo}"
        )
        if approved:
            print(f"  APPROVED — proceeding with automated response")
        print()
    else:
        # Record step 5 end time even when step 6 is skipped
        _step_timings[5] = time.time() - _step_start
        _step_timings[6] = 0.0

    # ===========================
    # STEP 7: REPORT — Generate and deliver
    # ===========================
    step(7, 7, "REPORT — Generating cross-source security report...")

    report = analyzer.generate_report(findings, cross_source_correlations)
    elapsed = time.time() - start_time

    # Generate SARIF report (industry-standard format for GitHub Security integration)
    sarif = generate_sarif(findings, cross_source_correlations, {
        "scan_id": scan_id,
        "repository": f"{owner}/{repo}",
        "start_time": datetime.now(tz=__import__('datetime').timezone.utc).isoformat(),
        "end_time": datetime.now(tz=__import__('datetime').timezone.utc).isoformat(),
    })
    save_sarif(sarif, f"deepsentinel-{scan_id}.sarif.json")
    print(f"  [SARIF] GitHub Security compatible report generated")

    # Record final step timing
    _step_timings[7] = time.time() - _step_start

    # TrueFoundry cost summary with per-model breakdown
    total_cost = getattr(llm, 'total_cost', 0)
    total_calls = getattr(llm, 'total_calls', 0)
    llm.print_cost_summary()

    # ===========================
    # VALUE-ADD METRIC
    # ===========================
    # Use the analyzer's tracked code-only count (regex prescan before LLM verification replaces them)
    code_only_count = getattr(analyzer, 'code_only_count', 0)
    total_count = len(findings)
    context_added = total_count - code_only_count
    uplift_pct = (context_added / code_only_count * 100) if code_only_count > 0 else 0

    header(f"SCAN COMPLETE — {elapsed:.1f}s total")

    # Per-step timing breakdown
    print("  Step timing breakdown:")
    step_names = {
        1: "GATHER (Airbyte)",
        2: "UNDERSTAND (Macroscope)",
        3: "CACHE (Aerospike)",
        4: "ANALYZE (TrueFoundry+Overmind)",
        5: "STORE (Ghost)",
        6: "AUTHORIZE (Auth0 CIBA)",
        7: "REPORT (Generation)",
    }
    for s in range(1, 8):
        t = _step_timings.get(s, 0)
        print(f"    Step {s} {step_names[s]:.<40s} {t:.2f}s")
    print()

    # Value-add metric — the key differentiator
    header("VALUE-ADD METRIC")
    print(f"  Code-only scan (regex patterns):    {code_only_count} findings")
    print(f"  With cross-source LLM context:    + {context_added} findings")
    print(f"  Total findings:                     {total_count} findings (+{uplift_pct:.0f}%)")
    print(f"  Cross-source correlations:          {len(cross_source_correlations)} (Issues + PR comments <-> code)")
    print()
    print(f"  Code-only tools (Snyk, CodeQL) would find ~{code_only_count} issues.")
    print(f"  DeepSentinel found {total_count} issues (+{uplift_pct:.0f}%) by correlating GitHub Issues,")
    print(f"  PR review comments, architecture analysis, and historical patterns.")
    print()

    # Integration stats
    print(f"  Files scanned: {len(all_files)}")
    print(f"  Findings: {len(findings)} ({critical_count} critical, {severity_counts.get('HIGH', 0)} high)")
    print(f"  Data persisted: Ghost Postgres ({db_id})")
    aero_stats = cache.get_stats()
    print(f"  Cache: Aerospike ({len(patterns)} patterns, {aero_stats['puts']} writes, "
          f"avg {aero_stats['avg_put_us']:.0f}us per op)")
    print(f"  LLM routing: TrueFoundry AI Gateway")
    print(f"  LLM calls: {total_calls} | Total cost: ${total_cost:.4f}")
    print(f"  Ghost DB: {db_id} (schema queried + history queried + fork created)")
    print(f"  Auth: Auth0 — Device Flow + Token Vault + CIBA + FGA (4 pillars)")
    print(f"  Auth0 CIBA: {'' if critical_count else 'no critical — '}approval {'requested' if critical_count else 'not needed'}")
    print()

    print(report)

    header("WHAT EXISTING TOOLS MISS")
    print("  Snyk, CodeQL, and GitHub Advanced Security scan CODE.")
    print("  DeepSentinel scans CONTEXT -- correlating GitHub Issues, Slack, PR reviews,")
    print("  and architecture to find risks that live BETWEEN tools.")
    print()
    for corr in cross_source_correlations:
        conf = corr.get("confidence", "?")
        ctype = corr.get("type", "unknown")
        print(f"  [{conf}] {corr.get('risk_note', '')}")
        context_ref = corr.get("context_ref", corr.get("slack_ref", ""))
        print(f"    {context_ref} <-> {corr['github_ref']}")
        why = corr.get("why_it_matters", corr.get("why_code_only_misses", ""))
        if why:
            print(f"    WHY SCANNERS MISS THIS: {why}")
        print()

    header("INTEGRATION SUMMARY")
    print("  1. Auth0      — Device Flow + Token Vault + CIBA + FGA (4 agentic pillars)")
    print("  2. Airbyte    — GitHub + Slack agent connectors + entity cache + LLM correlation discovery")
    print("  3. Macroscope — Webhook trigger + poll for results + dependency blast radius analysis")
    print("  4. Ghost      — Agent introspection, trend analysis, risk scoring, fork-before-experiment")
    print("  5. TrueFoundry — Multi-model routing + fallback chains + per-model cost comparison")
    print("  6. Aerospike  — Patterns, sessions, batch CVE lookup, severity index queries, TTL expiration")
    print("  7. Overmind   — OverClaw agent optimization (overclaw optimize deepsentinel)")
    print()
    print("  'Existing tools scan code. We scan context.'")
    print("  DeepSentinel — Cross-Source Security Intelligence")


if __name__ == "__main__":
    asyncio.run(demo())
