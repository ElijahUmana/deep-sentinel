# DeepSentinel — Competitive Differentiation

## Why Existing Tools Are Not Enough

### What exists today (March 2026):
| Tool | What It Does | What It DOESN'T Do |
|------|-------------|-------------------|
| **Snyk** | SAST, SCA, container scanning, AI triage | Cannot correlate with Slack/Jira context. Scans code in isolation. |
| **Semgrep** | 20K+ rules, AI assistant for triage | No cross-source intelligence. Rules are static. |
| **CodeQL** | Deep semantic analysis via query language | Requires writing custom queries. No contextual awareness. |
| **GitHub Advanced Security** | Copilot Autofix, secret scanning | Limited to GitHub data. Doesn't know about Slack discussions. |
| **DryRun Security** | AI-native PR review, contextual analysis | Analyzes code context, but only within the repo — not across tools. |
| **OpenAI Codex Security** | GPT-5 powered scanning, 92% detection | Best-in-class scanning, but still single-source. No team context. |
| **GitGuardian** | Scans GitHub, Slack, Jira for secrets | Only looks for secrets, not security-relevant context. |
| **ASPM tools** (Legit, Apiiro, OX) | Aggregate scanner results across SDLC | Correlate findings, not human discussions or decisions. |

### The gap DeepSentinel fills:

**No existing tool correlates *human context* with code changes for security analysis.**

A developer says in Slack: "Let's skip input validation for the MVP — we'll add it in Q2."
Three weeks later, a PR ships an API endpoint without input validation.
Snyk sees the endpoint. It doesn't flag it — there's no rule violation, just missing validation.
CodeQL doesn't flag it — no explicit vulnerability pattern.
GitGuardian doesn't flag it — no secret to detect.

**DeepSentinel catches this** because it pulls the Slack message, correlates it with the PR's changed files, and produces:

> **[HIGH] Deferred Security Work Detected**
> PR #42 adds `/api/payments` endpoint without input validation.
> Related Slack discussion (Mar 14, #engineering): "skip input validation for the MVP"
> Related context: This endpoint is in the payment module (HIGH criticality via Macroscope).
> **Recommendation: BLOCK — Security work was explicitly deferred for this code path.**

This finding is IMPOSSIBLE for any existing tool to produce. It requires:
1. GitHub data (the PR) ← Airbyte
2. Slack data (the discussion) ← Airbyte
3. Codebase architecture (payment module = high criticality) ← Macroscope
4. Cross-source correlation engine ← DeepSentinel core
5. LLM reasoning to connect the dots ← TrueFoundry/Claude

## What Makes DeepSentinel Fundamentally Different

### 1. Cross-source intelligence (the core differentiator)
Other tools scan code. DeepSentinel scans CONTEXT. It pulls data from multiple systems simultaneously and finds security insights that live in the GAPS between tools.

### 2. Architecture-aware severity scoring
Via Macroscope, DeepSentinel knows that a SQL injection in `src/payments/charge.py` is more critical than the same vulnerability in `tests/test_utils.py`. Existing tools treat all code equally.

### 3. Self-improving analysis
Via Overmind, DeepSentinel's security prompts are optimized over time based on which findings are accepted vs dismissed. After 30+ scans, the agent gets measurably better.

### 4. Human-in-the-loop for sensitive actions
Via Auth0 CIBA, when DeepSentinel finds a CRITICAL vulnerability and wants to create a security ticket or revoke credentials, it sends a push notification for human approval. No other scanner has this built in.

### 5. Persistent institutional memory
Via Ghost Postgres, DeepSentinel remembers every vulnerability it has ever found in your repos. It knows this team had 3 XSS vulnerabilities last quarter. It knows this module was flagged twice before. This historical context is unavailable to stateless scanning tools.

### 6. Real-time pattern matching
Via Aerospike, CVE lookups and vulnerability pattern matching happen in <1ms. When a new dependency is added, DeepSentinel can instantly check it against the full CVE database without waiting for an API call.

## The Demo Moment That Wins

"Existing tools scan code. We scan context. Here's a PR that passed Snyk, passed CodeQL, passed GitHub Advanced Security. Watch what DeepSentinel finds."

Then show the cross-source correlation catching a deferred security decision from Slack that no other tool could detect.

This is what makes judges say: "I've never seen this before."
