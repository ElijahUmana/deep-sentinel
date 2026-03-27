# DeepSentinel — 2-Minute High-Impact Demo Plan

## Key constraint: Show ALL of these in 2 minutes
- All 7 sponsor integrations WORKING
- Cross-source intelligence (the unique thing)
- Composite risk scoring (the differentiator)
- Real data (not simulated)
- Autonomy (agent acts without manual intervention)
- Technical depth (not surface-level)

## Demo Flow

### SECOND 0-10: THE HOOK (show the RESULT first)
"28% of critical security incidents happen outside code. Watch what happens when we scan context, not just code."

[Screen shows: the security report with composite risk scores and cross-source correlations — the IMPRESSIVE output is shown FIRST]

### SECOND 10-25: LIVE SCAN STARTS
[Run the demo — it auto-connects all 7 integrations in 2 seconds]
"DeepSentinel connects Auth0 for secure identity, Airbyte for GitHub and Slack data, Macroscope for architecture, TrueFoundry for AI, Aerospike for caching, Ghost for persistence, and Overmind for optimization."

### SECOND 25-45: CROSS-SOURCE DATA GATHERING
[Show the Airbyte step pulling REAL data]
"The agent pulls PR data, GitHub Issues, and REAL Slack messages simultaneously. It found 17 security-relevant Slack messages across 2 channels."
"It discovers 34 cross-source correlations using 3 strategies."

### SECOND 45-70: THE ANALYSIS
[Show TrueFoundry routing LLM calls with cost tracking]
"Multi-model routing: fast scan with GPT-4o-mini at $0.0003/call, deep verification with GPT-4o. Total scan cost: under a penny."

### SECOND 70-85: THE RISK SCORING
[Show composite risk scores]
"Here's what makes this different. A MEDIUM SQL injection scored 82/100 composite because: the team deferred the fix for 3 sprints, it's in the payment module, and it's appeared 40 times in historical scans. Snyk would call this MEDIUM. We call this CRITICAL."

### SECOND 85-100: GHOST PERSISTENCE
[Show Ghost DB stats]
"610 findings persisted across scans. The agent reads its own database schema, queries historical trends, and forks before experiments."

### SECOND 100-110: AUTH0 SECURITY
"Auth0 gates every action. Device Flow for login. Token Vault for zero-privilege API access. FGA checks permissions before every scan. CIBA sends push notification for critical ticket creation."

### SECOND 110-120: THE PUNCHLINE
[Show the PR comment posted on real PR #1]
"And the findings are posted directly on the PR. Judges — you can verify this right now at github.com/ElijahUmana/demo-vulnerable-app/pull/1"

[Show: WHAT EXISTING TOOLS MISS section with 3-4 correlations]
"These correlations are IMPOSSIBLE for any code-only scanner. They require connecting human decisions with code changes."

"DeepSentinel. 40 commits. 6,400 lines. 7 integrations. All data real. Existing tools scan code. We scan context."

## KEY NUMBERS TO SAY
- 34 cross-source correlations
- 610+ findings in Ghost DB
- $0.003 total LLM cost
- 7/7 integrations PASS
- 27 real Slack messages
- 3 Airbyte connectors
- 4 Auth0 pillars
- Composite risk: 82/100 for a "MEDIUM" vuln (deferral + architecture + history)
