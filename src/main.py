"""
DeepSentinel — Autonomous Multi-Source Security Intelligence Agent

Entry point and orchestrator. Coordinates the seven subsystems:
- Auth0: Secure identity + Token Vault + CIBA
- Airbyte: GitHub + Slack data connectors
- Macroscope: Codebase architecture intelligence
- Ghost: Persistent Postgres for findings + audit
- Aerospike: Real-time cache for CVEs + patterns
- TrueFoundry: Multi-model AI Gateway
- Overmind: Prompt optimization
"""
import asyncio
import sys
import uuid
from datetime import datetime

from dotenv import load_dotenv

load_dotenv()

# Initialize Overmind FIRST (must be before any LLM imports)
from src.analysis.security_analyzer import init_overmind

init_overmind()

from src.analysis.macroscope_client import MacroscopeClient
from src.analysis.security_analyzer import SecurityAnalyzer
from src.auth.auth0_client import Auth0Client
from src.config import Config
from src.data.airbyte_client import AirbyteDataLayer
from src.llm.truefoundry_gateway import TrueFoundryGateway
from src.output.github_comment import post_pr_comment
from src.storage.aerospike_cache import AerospikeCache
from src.storage.ghost_db import GhostDB


class DeepSentinel:
    """
    Autonomous Multi-Source Security Intelligence Agent.

    Connects the dots across GitHub, Slack, and your codebase to find
    vulnerabilities that single-source scanners miss.
    """

    def __init__(self):
        self.config = Config()

        # Initialize all 7 integrations
        print("\n" + "=" * 60)
        print("  DEEPSENTINEL — Autonomous Security Intelligence")
        print("=" * 60)
        print("\nInitializing integrations...\n")

        self.auth = Auth0Client()
        self.data = AirbyteDataLayer()
        self.macroscope = MacroscopeClient()
        self.llm = TrueFoundryGateway()
        self.db = GhostDB()
        self.cache = AerospikeCache()
        self.analyzer = SecurityAnalyzer(self.llm, self.cache)

    async def initialize(self):
        """Set up all connections and preload data."""
        # Authenticate the operator via device flow. Without a real Auth0
        # subject there is nobody for CIBA to push an approval request to, so
        # the approval gate would degrade to a terminal prompt. Skipped when
        # Auth0 is unconfigured or the session is non-interactive.
        if self.auth.connected and sys.stdin and sys.stdin.isatty():
            result = await self.auth.device_flow_login()
            if result.get("status") != "authenticated":
                print(
                    f"[Auth0] Device login unavailable ({result.get('status')}) — "
                    "approvals will fall back to a terminal prompt"
                )

        # Connect to Ghost Postgres
        await self.db.connect()

        # Connect to Aerospike and load patterns
        self.cache.connect()
        self.cache.load_patterns()

        # Query Macroscope for the repo's security surface. Retained on the
        # instance rather than discarded — it is the repo-level counterpart to
        # the per-file context resolved during a scan.
        self.security_surface = await self.macroscope.get_security_surface()

        # Log startup
        await self.db.log_audit("agent_started", "system", "deepsentinel")

        print("\n[DeepSentinel] All systems operational.\n")

    async def scan_pr(self, owner: str, repo: str, pr_number: int) -> dict:
        """
        MAIN FUNCTION: Autonomous security scan of a pull request.

        Pipeline:
        1. GATHER — Pull data from GitHub + Slack (Airbyte)
        2. UNDERSTAND — Analyze codebase architecture (Macroscope)
        3. CHECK CACHE — Look up known patterns (Aerospike)
        4. ANALYZE — Multi-model security analysis (TrueFoundry + Overmind)
        5. STORE — Persist findings + audit trail (Ghost)
        6. REPORT — Generate actionable security report
        """
        scan_id = str(uuid.uuid4())

        print(f"\n{'=' * 60}")
        print(f"  SCAN #{scan_id[:8]}")
        print(f"  Target: {owner}/{repo} PR #{pr_number}")
        print(f"  Time: {datetime.utcnow().isoformat()}Z")
        print(f"{'=' * 60}\n")

        # Record scan
        await self.db.start_scan(scan_id, owner, repo, pr_number)
        await self.db.log_audit("scan_started", "scan", scan_id)

        # ============================
        # STEP 1: GATHER (Airbyte)
        # ============================
        print("[1/6] Gathering cross-source context via Airbyte connectors...")
        context = await self.data.gather_full_context(owner, repo, pr_number)

        # Pull GitHub Issues + PR comments as additional cross-source context
        issue_ctx = await self.data.gather_github_intelligence(owner, repo, pr_number)
        print(f"  GitHub Issues: {len(issue_ctx.issues)} security-related")
        print(f"  PR Comments: {len(issue_ctx.pr_comments)} security-relevant")

        # Build cross-source correlations from real GitHub data
        issue_correlations = self.data.correlate_issues_with_code(
            context.github.changed_files, issue_ctx, pr_number
        )
        # Strategy 3: LLM discovery of non-obvious links that keyword and
        # file/module matching cannot reach — paraphrased concerns, implicit
        # references, architectural implications.
        llm_correlations = await self.data.discover_llm_correlations(
            context.github, context.slack, self.llm
        )

        # Merge all three strategies
        all_correlations = context.correlations + issue_correlations + llm_correlations
        print(
            f"  Cross-source correlations: {len(all_correlations)} total "
            f"(keyword+file/module: {len(context.correlations)}, "
            f"issues/comments: {len(issue_correlations)}, "
            f"LLM discovery: {len(llm_correlations)})"
        )

        # Build context strings from GitHub issues/comments for LLM
        github_context = []
        for issue in issue_ctx.issues:
            github_context.append(
                f"Issue #{issue['number']}: {issue['title']} -- {issue.get('body', '')[:150]}"
            )
        for comment in issue_ctx.pr_comments:
            github_context.append(
                f"PR review by {comment.get('user', 'reviewer')}: {comment.get('body', '')[:150]}"
            )

        # ============================
        # STEP 2: UNDERSTAND (Macroscope)
        # ============================
        print("\n[2/6] Analyzing codebase architecture via Macroscope...")
        # Queries Macroscope per changed file and merges the answer with the
        # static path heuristic. Degrades to the heuristic alone when Macroscope
        # is unconfigured, and the returned `note` records which one applied.
        file_contexts = {}
        module_contexts = await asyncio.gather(
            *(
                self.macroscope.get_module_context(f.get("path", ""))
                for f in context.github.changed_files
            )
        )
        for f, fctx in zip(context.github.changed_files, module_contexts, strict=False):
            path = f.get("path", "")
            file_contexts[path] = fctx
            source = "macroscope" if fctx.get("macroscope_answer") else "static"
            print(
                f"  {path or '?'}: module={fctx['module']}, "
                f"criticality={fctx['criticality']} ({source})"
            )

        # ============================
        # STEP 3: CHECK CACHE (Aerospike)
        # ============================
        print("\n[3/6] Checking Aerospike cache...")
        # Keyed on the PR head commit, so re-scanning an unchanged PR hits.
        # Previously this passed a fresh per-run UUID, which made the key unique
        # every time and the cache structurally incapable of ever hitting.
        cache_sha = context.github.head_sha
        if cache_sha:
            cached = self.cache.get_cached_scan(f"{owner}/{repo}", pr_number, cache_sha)
            if cached:
                print(f"  Cache HIT on {cache_sha[:8]} -- returning cached results")
                return cached
            print(f"  Cache MISS on {cache_sha[:8]} -- proceeding with full analysis")
        else:
            print("  No head commit resolved -- skipping cache for this scan")

        # Get historical patterns from Ghost
        historical = await self.db.get_historical_patterns(owner, repo)
        print(f"  Historical patterns: {len(historical)} known for this repo")

        # ============================
        # STEP 4: ANALYZE (TrueFoundry + Overmind)
        # ============================
        print("\n[4/6] Running security analysis via TrueFoundry AI Gateway...")
        print("  (All LLM calls instrumented by Overmind for optimization)")

        # Combine Slack messages + GitHub issue/comment context
        slack_context = [m.get("text", "")[:200] for m in context.slack.messages[:5]]
        combined_context = github_context + slack_context

        analysis_context = {
            "files": context.github.changed_files,
            "architecture": file_contexts,
            "slack_context": combined_context,
            "historical_patterns": [
                {"cwe": h.get("cwe_id", ""), "count": h.get("count", 0)} for h in historical
            ],
            "correlations": all_correlations[:10],
        }

        findings = self.analyzer.analyze(analysis_context)

        # Enrich findings with the module context already resolved in step 2,
        # so the escalation uses the live Macroscope answer for that file.
        for finding in findings:
            finding = self.macroscope.enrich_finding(
                finding, file_contexts.get(finding.get("file_path", ""))
            )

        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Apply composite risk scoring
        from src.analysis.risk_scorer import rank_findings_by_risk
        findings = rank_findings_by_risk(findings, all_correlations, historical, file_contexts)

        print(f"\n  Total findings: {len(findings)}")
        for sev, count in sorted(severity_counts.items()):
            print(f"    {sev}: {count}")

        # Show top risk-scored findings
        top_risk = [f for f in findings if f.get("risk_score", {}).get("composite_score", 0) > 60]
        if top_risk:
            print("\n  TOP RISK-SCORED FINDINGS (composite > 60):")
            for f in top_risk[:3]:
                rs = f.get("risk_score", {})
                print(f"    [{rs.get('composite_score', 0)}/100] {f.get('title', '?')} ({f.get('file_path', '?')})")
                print(f"      {rs.get('explanation', '')}")

        # ============================
        # STEP 5: STORE (Ghost)
        # ============================
        print("\n[5/6] Storing results in Ghost Postgres...")

        critical_count = severity_counts.get("CRITICAL", 0)
        high_count = severity_counts.get("HIGH", 0)

        for finding in findings:
            finding["scan_id"] = scan_id
            finding["repo_owner"] = owner
            finding["repo_name"] = repo
            finding["pr_number"] = pr_number
            await self.db.record_vulnerability(finding)

        for corr in all_correlations:
            await self.db.record_correlation(scan_id, corr)

        await self.db.complete_scan(scan_id, len(findings), critical_count, high_count)

        # Cache in Aerospike
        if cache_sha:
            self.cache.cache_scan_result(
                f"{owner}/{repo}", pr_number, cache_sha,
                {"scan_id": scan_id, "findings_count": len(findings), "timestamp": datetime.utcnow().isoformat()},
            )

        await self.db.log_audit("scan_completed", "scan", scan_id, {
            "findings": len(findings), "critical": critical_count, "high": high_count,
        })

        # ============================
        # STEP 6: REPORT
        # ============================
        print("\n[6/6] Generating security report...")

        # CIBA: Request approval for critical findings. The decision gates the
        # write action below — posting a review back onto the PR.
        ciba_approved = True
        if critical_count > 0:
            print(f"\n[Auth0 CIBA] {critical_count} CRITICAL findings detected")
            ciba_approved = await self.auth.request_approval(
                f"Create security tickets for {critical_count} critical vulnerabilities",
                f"{owner}/{repo} PR #{pr_number}",
            )
            if ciba_approved:
                print("[Auth0 CIBA] Approved — creating tickets")
            else:
                print("[Auth0 CIBA] Denied — skipping ticket creation")

        report = self.analyzer.generate_report(findings, all_correlations)

        # TrueFoundry model comparison. get_model_comparison() returns a flat
        # {model: stats} mapping — the previous code looked for a "per_model"
        # key that the method never produces, so this never printed, and would
        # have raised KeyError on the stat names if it had.
        if hasattr(self.llm, "get_model_comparison"):
            comparison = self.llm.get_model_comparison()
            if comparison:
                print("\n[TrueFoundry] Model Performance Comparison:")
                for model, stats in sorted(comparison.items()):
                    print(
                        f"  {model}: {stats['calls']} calls, "
                        f"{stats['total_tokens']} tokens, "
                        f"${stats['total_cost']:.4f}, "
                        f"avg {stats['avg_latency_ms']:.0f}ms"
                    )
                total = sum(s["total_cost"] for s in comparison.values())
                print(f"  Total scan cost: ${total:.4f}")

        print(f"\n{'=' * 60}")
        print("  SCAN COMPLETE")
        print(f"  Findings: {len(findings)} ({critical_count} critical, {high_count} high)")
        print(f"  Cross-source correlations: {len(all_correlations)}")
        print(f"  Scan ID: {scan_id}")
        print(f"{'=' * 60}\n")

        print(report)

        # Post the review back onto the PR itself. Findings are only useful
        # where the review is happening, and the CIBA gate above governs it:
        # a scan with critical findings posts only once a human has approved.
        posted = False
        if pr_number and (critical_count == 0 or ciba_approved):
            posted = await post_pr_comment(
                owner, repo, pr_number, findings, all_correlations
            )
        elif pr_number:
            print("[GitHub] Approval denied — not posting review comment")

        return {
            "scan_id": scan_id,
            "findings": findings,
            "correlations": all_correlations,
            "report": report,
            "pr_comment_posted": posted,
            "stats": {"total": len(findings), "critical": critical_count, "high": high_count},
        }

    async def run_autonomous(self, owner: str, repo: str, poll_interval: int = 60):
        """
        AUTONOMOUS MODE: Continuously monitor for new PRs and scan them.

        Polls for pull requests that have not been scanned at their current
        head commit and runs the full pipeline against each.
        """
        print("\n[DeepSentinel] AUTONOMOUS MODE")
        print(f"[DeepSentinel] Monitoring: {owner}/{repo}")
        print(f"[DeepSentinel] Poll interval: {poll_interval}s\n")

        scanned = set()
        while True:
            try:
                prs = await self.data.get_open_prs(owner, repo)
                for pr in prs:
                    pr_num = pr.get("number")
                    if pr_num and pr_num not in scanned:
                        print(f"\n[DeepSentinel] New PR detected: #{pr_num}")
                        await self.scan_pr(owner, repo, pr_num)
                        scanned.add(pr_num)

                await asyncio.sleep(poll_interval)
            except KeyboardInterrupt:
                print("\n[DeepSentinel] Shutting down...")
                break
            except Exception as e:
                print(f"[DeepSentinel] Error: {e}")
                await asyncio.sleep(poll_interval)

    async def shutdown(self):
        """Clean up all connections."""
        await self.auth.close()
        await self.macroscope.close()
        await self.db.close()
        self.cache.close()


async def main():
    sentinel = DeepSentinel()
    await sentinel.initialize()

    if len(sys.argv) >= 4:
        owner = sys.argv[1]
        repo = sys.argv[2]

        if sys.argv[1] == "--autonomous":
            await sentinel.run_autonomous(sys.argv[2], sys.argv[3])
        else:
            pr_number = int(sys.argv[3])
            await sentinel.scan_pr(owner, repo, pr_number)
    else:
        print("\nUsage:")
        print("  python -m src.main <owner> <repo> <pr_number>")
        print("  python -m src.main --autonomous <owner> <repo>")
        print("\nExample:")
        print("  python -m src.main ElijahUmana demo-vulnerable-app 1")

    await sentinel.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
