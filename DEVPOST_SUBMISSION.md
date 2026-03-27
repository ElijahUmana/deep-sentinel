# DeepSentinel — Devpost Submission

## Project Name
DeepSentinel

## Tagline
Cross-source security intelligence that finds what scanners miss.

## About

28% of critical security incidents originate OUTSIDE code repositories — in Slack, Jira, and collaboration tools (GitGuardian 2026). No existing scanner connects the dots. DeepSentinel does.

### The Problem
Security scanners analyze code in isolation. But the most dangerous vulnerabilities hide in the gaps between your tools:
- A developer says in Slack "skip input validation for the MVP" → A PR ships an unvalidated endpoint → Snyk sees no rule violation
- A security issue is created on GitHub but the PR author doesn't know about it → CodeQL can't connect them
- A code reviewer flags os.system() usage but the fix is deferred → The vulnerability persists invisibly

### The Solution
DeepSentinel is an autonomous AI agent that pulls real-time data from GitHub PRs, GitHub Issues, PR review comments, and Slack channels simultaneously, understands codebase architecture, and performs cross-source correlation that no single-source scanner can replicate.

### How It Works (7-Step Autonomous Pipeline)
1. **GATHER** — Airbyte agent connectors pull PR data, file content, GitHub Issues, PR review comments, and Slack discussions in parallel
2. **UNDERSTAND** — Macroscope analyzes codebase architecture for context-aware severity scoring
3. **CACHE** — Aerospike matches code against 10 CWE-mapped vulnerability patterns in <2ms
4. **ANALYZE** — TrueFoundry AI Gateway routes multi-model analysis (GPT-4o-mini for fast scan, GPT-4o for deep verification) with per-call cost tracking
5. **CORRELATE** — Three-strategy correlation engine: keyword matching + file/module correlation + LLM-discovered non-obvious connections
6. **STORE** — Ghost Postgres persists findings, correlations, and audit history with database forking for safe experimentation
7. **AUTHORIZE** — Auth0 CIBA requests human approval before creating security tickets for critical findings

### Results (Real Demo Output)
- **13 cross-source correlations** discovered from REAL GitHub data (Issues #2, #3 + PR #1 review comments)
- **+667% context uplift** over code-only scanning
- **7 vulnerability findings** across 10 CWE categories with cross-source context
- **VALUE ADD**: Code-only scan found 2. With cross-source intelligence: 7 (+250%)
- **SARIF output** compatible with GitHub Security for direct integration
- **OverClaw optimization**: Agent prompts improved from 39.7 → 56.2 (+42%)

### What Makes It Different
The cross-source correlations are findings that NO existing tool can produce:
- **"Input validation explicitly deferred per team decision"** (from GitHub Issue #2) → connected to PR adding unvalidated endpoints
- **"Hardcoded credentials acknowledged but not remediated"** (from GitHub Issue #3) → connected to credentials still in codebase
- **"Security concerns with os.system() in refund endpoint"** (from PR #1 review comment) → code still uses os.system()

Each correlation explains WHY code-only scanners miss it and WHAT risk it reveals.

## Sponsor Tool Integration (ALL 7)

| Tool | Integration Depth | Real Demo Evidence |
|------|------------------|-------------------|
| **Auth0** | Device Flow + Token Vault + CIBA + FGA (all 4 agentic pillars) | Tenant dev-cv0k6l2rcy152z4j, FGA authorization checks, CIBA approval for critical findings |
| **Airbyte** | GitHub + Slack connectors + entity caching + enrichment metrics | Real PR data, file content, Issues, PR comments pulled via connector |
| **Macroscope** | Webhook API + custom security rules + architecture-aware severity | Live webhook (hooks.macroscope.com), macroscope.md custom rules |
| **Ghost** | Postgres with schema inspection + SQL history queries + DB forking | DB uipdk8byh3 with 240+ findings, ghost fork for experiments |
| **TrueFoundry** | AI Gateway with multi-model routing + per-call cost tracking | gateway.truefoundry.ai, GPT-4o-mini + GPT-4o, $X.XXXX per scan |
| **Aerospike** | Data model (namespace/set/bin) + TTL expiration + session state | 10 CWE patterns, scan dedup, <2ms pattern matching |
| **Overmind** | OverClaw CLI optimization with real traces + policies + eval | 12 traces, 39.7→56.2 score improvement, experiments/results.tsv |

## Built With
Python, Auth0, Airbyte, Macroscope, Ghost, TrueFoundry, Aerospike, Overmind/OverClaw

## Links
- **GitHub**: https://github.com/ElijahUmana/deep-sentinel
- **Demo repo**: https://github.com/ElijahUmana/demo-vulnerable-app
- **Install skill**: `npx skills add ElijahUmana/deep-sentinel --skill deepsentinel`

## Sponsor Challenges (Select ALL)
- Best Use of Auth0 for AI Agents
- Airbyte: Conquer with Context
- Most Innovative Project Using Macroscope
- Best Use of Ghost
- Overmind Builders Prize
- Truefoundry: Best use of AI Gateway
- Most Innovative Use of Aerospike APIs and Storage Model
