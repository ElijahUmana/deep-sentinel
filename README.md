# DeepSentinel

**Cross-source security intelligence that finds what scanners miss.**

> *28% of critical security incidents originate OUTSIDE code repositories — in Slack, Jira, and collaboration tools. No existing scanner connects the dots.* — GitGuardian State of Secrets Sprawl 2026

DeepSentinel is an autonomous AI agent that correlates GitHub PRs, Issues, review comments, Slack discussions, and codebase architecture to find security risks that live in the gaps between your tools. It doesn't just scan code — it scans context.

**See it in action:** [Security review posted on a real PR](https://github.com/ElijahUmana/demo-vulnerable-app/pull/1) | Install skill: `npx skills add ElijahUmana/deep-sentinel --skill deepsentinel`

---

## The Problem

Snyk finds a SQL injection. CodeQL finds a hardcoded credential. GitHub Advanced Security flags a command injection. These are real vulnerabilities — but they're the ones every tool already catches.

What no tool catches:
- The **Slack message** where a developer said "skip input validation for the MVP — we'll add it in Q2." Three sprints later, the payment endpoints are still exposed.
- The **GitHub Issue** tracking hardcoded credentials that was created two months ago and is still open. The same credentials are in the PR being merged right now.
- The **PR review comment** where a teammate flagged `os.system()` as dangerous. The fix was deferred. The vulnerability persists.

These are **institutional security failures** — known risks that accumulate because information is fragmented across tools. DeepSentinel connects the dots.

## The Solution

DeepSentinel runs a 7-step autonomous pipeline that pulls data from multiple sources, correlates findings across them, and produces a **composite risk score** that factors in team awareness, deferral history, architectural criticality, and historical patterns.

### Pipeline

```
1. GATHER    — Airbyte pulls GitHub PRs, Issues, PR comments + Slack messages (3 connectors)
2. UNDERSTAND — Macroscope analyzes codebase architecture for context-aware severity
3. CACHE     — Aerospike matches code against 10 CWE vulnerability patterns (<5ms)
4. ANALYZE   — TrueFoundry routes multi-model LLM analysis (fast scan + deep verification)
5. CORRELATE — 3-strategy engine: keyword matching + file/module correlation + LLM discovery
6. STORE     — Ghost Postgres persists findings, correlations, audit history + DB forking
7. AUTHORIZE — Auth0 FGA gates access; CIBA escalates to human approval for write actions
```

### Composite Risk Scoring — The Differentiator

Traditional scanners assign severity based on the vulnerability type alone. DeepSentinel computes a **composite risk score** that no code-only tool can produce:

```
COMPOSITE RISK = (Code Severity + Deferral Penalty + Historical Frequency) × Architecture Multiplier
```

A MEDIUM SQL injection scored **82/100** composite because:
- The team **deferred** the fix for 3 sprints (deferral penalty: +15)
- It's in the **payment module** (architecture multiplier: 1.3x)
- The same CWE appeared **40 times** in historical scans (history bonus: +20)
- A team member **flagged it** in Slack but it remains unfixed

Snyk would call this MEDIUM. DeepSentinel calls it the **highest-risk finding in the repo** — because it factors in what the team knows, what they've deferred, and where in the system it lives.

## Architecture

```
        Auth0 (Device Flow + Token Vault + CIBA + FGA)
                        |
    ┌───────────────────┼───────────────────┐
    |                   |                   |
GitHub PR+Issues    Slack Msgs          Codebase
(Airbyte GitHub)   (Airbyte Slack)    (Macroscope)
    |                   |                   |
    └─────────┬─────────┘                   |
              |                             |
      3-Strategy                    Architecture
      Correlation Engine             Context
              |                             |
              └──────────┬──────────────────┘
                         |
                Security Analyzer + Risk Scorer
               (TrueFoundry Gateway + Overmind)
                         |
              ┌──────────┼──────────┐
              |          |          |
         Aerospike    Ghost DB    Output
         (patterns)   (history)  (PR comment + SARIF)
```

## Sponsor Tool Integration (7/7 Verified)

All 7 integrations are **verified working** with real credentials and real data. Run `python test_integrations.py` to confirm.

| Tool | Integration Depth | Verified Evidence |
|------|------------------|-------------------|
| **Auth0** | All 4 agentic pillars: Device Flow authentication, Token Vault for zero-standing-privilege API access, CIBA push notification for human-in-the-loop approval, FGA gatekeeping (read allowed, write denied → CIBA escalation) | Tenant `dev-cv0k6l2rcy152z4j`, native app for device flow, confidential app for CIBA/Token Vault |
| **Airbyte** | 3 agent connectors: GitHub (PRs, Issues, file content, commits), Slack (channels, messages from #security-review + #engineering), Jira (installed, ready for workspace). Entity caching, enrichment metrics, 3-strategy correlation engine | Real PR data, 27+ real Slack messages, GitHub Issues #2/#3 |
| **Macroscope** | Webhook API with trigger-poll lifecycle, custom security rules (`macroscope.md`), architecture-aware severity scoring, codebase intelligence queries | Live webhook at hooks.macroscope.com, workspace 121345656 |
| **Ghost** | Persistent Postgres with 1,069+ findings, schema introspection (agent reads its own schema), historical trend analysis, database forking for safe experiments, dynamic SQL construction | DB `uipdk8byh3` on TimescaleDB cloud, 28 forks created |
| **TrueFoundry** | AI Gateway with multi-model routing (GPT-4o-mini for fast scan, Claude Sonnet 4 for deep verification), automatic fallback chains, per-model cost/latency tracking, metadata tagging for observability | gateway.truefoundry.ai, $0.003 per full scan |
| **Aerospike** | 10 CWE-mapped vulnerability patterns with batch loading, secondary index queries (by severity, by CWE), TTL-based expiration, session state management, atomic increment for hit counting | In-memory mode with full Aerospike data model (namespace/set/bin) |
| **Overmind** | OverClaw CLI agent optimization: 12 baseline traces, 15 test cases, 5 optimization iterations, score improved from 39.7 to 56.2 (+42%). Policy-driven evaluation with security-specific criteria | `.overclaw/agents/deepsentinel/experiments/results.tsv` |

## Cross-Source Intelligence — ALL REAL DATA

Every cross-source correlation traces back to verifiable data:

| Source | Data | Verification |
|--------|------|-------------|
| GitHub PRs | PR #1: "Add payment processing endpoint" | [View PR](https://github.com/ElijahUmana/demo-vulnerable-app/pull/1) |
| GitHub Issues | #2: "Input validation missing on payment endpoints" | [View Issue](https://github.com/ElijahUmana/demo-vulnerable-app/issues/2) |
| GitHub Issues | #3: "Hardcoded credentials need secrets manager" | [View Issue](https://github.com/ElijahUmana/demo-vulnerable-app/issues/3) |
| PR Comments | Security review flagging os.system() and SQL injection | [View on PR #1](https://github.com/ElijahUmana/demo-vulnerable-app/pull/1) |
| Slack #engineering | "Skip input validation for MVP", "DB password hardcoded", "MD5 hashing needs bcrypt" | 16 messages via Airbyte Slack connector |
| Slack #security-review | "SQL injection confirmed", "Refund endpoint exploitable", "PCI DSS non-compliant" | 12 messages via Airbyte Slack connector |
| Ghost DB | 1,069+ findings across all scans, 200+ correlations | `ghost sql uipdk8byh3 "SELECT COUNT(*) FROM vulnerabilities"` |

## What Existing Tools Miss

```
Snyk finds 4 code-level vulnerabilities in payment.py.
DeepSentinel finds those same 4 PLUS:

1. [HIGH] Team explicitly deferred input validation (Slack #engineering, Mar 14)
   → Connected to PR adding unvalidated payment endpoints
   → WHY SCANNERS MISS: Code looks the same whether validation was forgotten or deferred

2. [HIGH] Hardcoded credentials flagged but not remediated (GitHub Issue #3)
   → Connected to same credentials still in codebase
   → WHY SCANNERS MISS: Scanners can't see that the team KNOWS about the issue

3. [HIGH] os.system() flagged by reviewer (PR #1 comment)
   → Still in codebase despite explicit security concern
   → WHY SCANNERS MISS: Review comments exist outside the code

4. [CRITICAL] Compound risk: SQL injection + hardcoded creds + command injection
   in a PAYMENT module with 40 historical occurrences
   → Composite score: 100/100 (vs. Snyk's simple "CRITICAL" label)
   → WHY SCANNERS MISS: No single-source tool computes risk from team context
```

## Quick Start

```bash
git clone https://github.com/ElijahUmana/deep-sentinel
cd deep-sentinel

python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Add your API keys (Auth0, GitHub, Slack, TrueFoundry, Ghost, Macroscope, Overmind)

# Scan a specific PR
python scan.py ElijahUmana demo-vulnerable-app --pr 1

# Scan a full repository
python scan.py ElijahUmana demo-vulnerable-app

# Autonomous monitoring mode
python scan.py ElijahUmana demo-vulnerable-app --autonomous

# Generate SARIF output (GitHub Security compatible)
python scan.py ElijahUmana demo-vulnerable-app --sarif

# Run integration verification
python test_integrations.py
```

## Output Formats

- **Terminal**: Rich formatted security report with cross-source correlations
- **GitHub PR comment**: Posted directly on the PR ([example](https://github.com/ElijahUmana/demo-vulnerable-app/pull/1))
- **SARIF 2.1.0**: GitHub Security compatible for direct integration
- **Ghost DB**: Persistent storage with historical trend analysis

## Vulnerability Categories (10 CWE-Mapped)

| CWE | Category | Detection Method |
|-----|----------|-----------------|
| CWE-798 | Hardcoded credentials | Regex + LLM + cross-source (team awareness) |
| CWE-89 | SQL injection | Regex + LLM + architecture context |
| CWE-78 | Command injection | Regex + LLM + PR review correlation |
| CWE-79 | Cross-site scripting | LLM analysis |
| CWE-22 | Path traversal | Regex + LLM |
| CWE-327 | Weak cryptography | Regex + Slack discussion correlation |
| CWE-502 | Insecure deserialization | Regex + LLM |
| CWE-918 | SSRF | Regex + LLM |
| CWE-400 | Missing rate limiting | LLM + architecture context |
| CWE-209 | Error information exposure | LLM analysis |

## Project Stats

- **51 commits** during hackathon
- **7,029 lines** of Python
- **44 Python files** across 8 modules
- **7/7 integrations** verified passing
- **1,069+ findings** persisted in Ghost DB
- **27+ real Slack messages** across 3 channels
- **$0.003** average cost per full scan via TrueFoundry

## License

MIT

## Author

**Elijah Umana** — [GitHub](https://github.com/ElijahUmana) | Minerva University
