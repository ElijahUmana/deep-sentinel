# DeepSentinel — 3-Minute Demo Narration

## 0:00-0:15 — THE HOOK (show final report first)
"28% of critical security incidents originate outside code repositories. In Slack threads, Jira tickets, and team discussions. Snyk scans code. CodeQL scans code. GitHub Advanced Security scans code. None of them scan context. DeepSentinel does."

[Show the terminal with the final security report, highlighting cross-source correlations]

## 0:15-0:30 — THE ARCHITECTURE (quick visual)
"DeepSentinel connects 7 best-in-class tools into an autonomous security pipeline."

[Show the initialization output — all 7 integrations connecting]
- Auth0: 4 agentic pillars (Device Flow + Token Vault + CIBA + FGA)
- Airbyte: GitHub + Slack connectors
- Macroscope: Codebase intelligence
- Ghost: Persistent Postgres with forking
- TrueFoundry: AI Gateway
- Aerospike: Real-time cache
- Overmind: Agent optimization

## 0:30-1:30 — THE LIVE SCAN
"Watch the agent scan a real GitHub repository. It pulls PR data, GitHub Issues, review comments, and Slack context simultaneously."

[Run: python3 demo/full_demo.py]

Key moments to highlight as they appear:
- "3 correlation strategies firing — Issues, Slack keywords, and LLM discovery"
- "The LLM finds connections that keyword matching misses"
- "+667% context uplift over code-only scanning"
- "Each finding through TrueFoundry gateway with cost tracking — $0.003 total"

## 1:30-2:00 — GHOST DATABASE + AEROSPIKE CACHE
"All findings persist in Ghost Postgres. The agent queries its own history to learn from past scans."

[Show Ghost output: schema, historical patterns, fork creation]
"Ghost forking creates safe experiment databases — like git branches for data."

[Show Aerospike output: data model, TTL expiration, session state]
"Aerospike caches vulnerability patterns for sub-millisecond matching."

## 2:00-2:30 — THE DIFFERENTIATOR
"Here's what Snyk and CodeQL missed."

[Show the WHAT EXISTING TOOLS MISS section]
"GitHub Issue #2 says input validation was explicitly deferred. Issue #3 says hardcoded credentials need a secrets manager. A reviewer flagged os.system() as dangerous. These are REAL GitHub artifacts — not simulated. Every correlation traces back to an actual Issue or PR comment."

[Show the PR with DeepSentinel's security review comment]
"And the findings are posted directly on the PR — where developers already work."

## 2:30-2:45 — AUTH0 SECURITY
"Auth0 secures the entire pipeline. Device Flow authenticates users. Token Vault provides zero-standing-privilege API access. CIBA sends push notifications for human approval of critical actions. FGA ensures the agent only accesses what it needs."

## 2:45-3:00 — CLOSE
"DeepSentinel found 13 cross-source correlations that no existing scanner can produce. Because they require connecting human decisions with code changes. Existing tools scan code. We scan context."

"Published as an Agent Skill — install with one command: npx @senso-ai/shipables install ElijahUmana/deepsentinel"

---

## KEY STATS TO MENTION
- 13 cross-source correlations from 3 discovery strategies
- +667% context uplift over code-only scanning
- $0.003 total LLM cost per scan via TrueFoundry
- 275+ findings persisted in Ghost Postgres
- Auth0 all 4 agentic pillars operational
- OverClaw improved prompts from 39.7 to 56.2 (+42%)
- Security review posted directly on real PR #1
