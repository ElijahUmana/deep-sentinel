# Devpost Submission Text

## Project Name
DeepSentinel

## Tagline
Cross-source security intelligence that finds what scanners miss.

## About
Security scanners analyze code. DeepSentinel analyzes context.

Every software team has the same problem: security knowledge is fragmented. Code changes go through GitHub. Security decisions happen in Slack. Vulnerability tickets sit in Jira. No existing tool connects the dots.

A developer writes in Slack: "Let's skip input validation for the MVP." Three weeks later, a PR ships an unauthenticated endpoint. Snyk doesn't flag it — there's no rule violation. CodeQL doesn't flag it — no explicit vulnerability pattern. GitHub Advanced Security doesn't flag it — it only scans code.

DeepSentinel catches this because it pulls data from GitHub AND Slack simultaneously, understands the codebase architecture, and performs cross-source correlation that no single-source scanner can replicate.

### What it does
DeepSentinel is an autonomous AI agent that:
1. **Gathers** data from GitHub PRs and Slack channels via Airbyte agent connectors
2. **Understands** codebase architecture via Macroscope for context-aware severity scoring
3. **Analyzes** code through TrueFoundry AI Gateway (multi-model routing with cost tracking)
4. **Cross-references** findings across all sources to surface hidden risks
5. **Caches** CVE patterns in Aerospike for sub-millisecond lookups
6. **Stores** findings and audit trails in Ghost Postgres (with database forking)
7. **Optimizes** security analysis prompts via Overmind OverClaw
8. **Requests human approval** via Auth0 CIBA for critical findings

### How it works
The agent runs a 7-step autonomous pipeline:
- **Airbyte** pulls PR data + Slack discussions in parallel
- **Macroscope** provides architecture context (which module, how critical)
- **Aerospike** matches against 10 CWE-mapped vulnerability patterns
- **TrueFoundry** routes LLM analysis through GPT-4o-mini (fast scan) then verifies critical findings
- **Ghost** persists all findings, correlations, and audit history
- **Auth0 CIBA** sends push notification for approval before creating security tickets
- **Overmind OverClaw** has optimized the agent's prompts through structured experimentation

### Results
Full repo scan of demo application:
- 41 vulnerabilities found across 4 files
- 5 CRITICAL, 25 HIGH, 11 MEDIUM findings
- 4 cross-source correlations from Slack discussions
- 10 CWE categories detected
- Complete audit trail in Ghost Postgres
- Database fork created for safe experimentation

### What makes it different
**The cross-source correlations are findings that NO existing tool can produce:**
- "Input validation explicitly deferred per team decision in Slack" → connected to PR adding unvalidated endpoints
- "Hardcoded credentials flagged in Slack but not remediated" → connected to credentials still in codebase
- "os.system() usage flagged by team member in security review channel" → still present in refund endpoint
- "MD5 hashing identified as needing bcrypt upgrade" → pre-launch blocker still unresolved

These correlations require connecting human discussions with code changes — something Snyk, CodeQL, and every other SAST tool fundamentally cannot do.

## Built with
- Python
- Auth0 (identity, Token Vault, CIBA)
- Airbyte Agent Connectors (GitHub, Slack)
- Macroscope (codebase intelligence)
- Ghost (persistent Postgres)
- TrueFoundry AI Gateway (multi-model LLM routing)
- Aerospike (real-time cache)
- Overmind OverClaw (agent optimization)

## Challenges
- TrueFoundry's cloud domain had SSL issues during the hackathon — resolved by using gateway.truefoundry.ai directly
- Overmind's web console API had backend errors — pivoted to OverClaw CLI which worked perfectly
- Airbyte's GitHub connector returned empty content with OAuth tokens — fixed by using PAT authentication
- Docker unavailable on the hackathon machine — Aerospike runs in intelligent memory-fallback mode with real data structures

## What we learned
- Cross-source intelligence is genuinely powerful for security — connecting Slack discussions with code changes catches risks that pure code analysis misses
- The hackathon sponsor ecosystem (Auth0 + Airbyte + Ghost + TrueFoundry + Aerospike + Overmind + Macroscope) creates a complete stack for building production-grade AI agents
- Ghost's database forking is invaluable for agent experimentation — fork before risky operations, discard if something goes wrong
- OverClaw's structured optimization approach (policy → test → diagnose → fix → validate) is a systematic way to improve agent quality

## Links
- GitHub: https://github.com/ElijahUmana/deep-sentinel
- Demo repo (target): https://github.com/ElijahUmana/demo-vulnerable-app
- Install skill: npx @senso-ai/shipables install ElijahUmana/deepsentinel

## Sponsor Challenges
Select ALL of these:
- Best Use of Auth0 for AI Agents
- Airbyte: Conquer with Context
- Most Innovative Project Using Macroscope
- Best Use of Ghost
- Overmind Builders Prize
- Truefoundry: Best use of AI Gateway
- Most Innovative Use of Aerospike APIs and Storage Model
