# DeepSentinel

**Autonomous multi-source security intelligence that finds what scanners miss.**

DeepSentinel is an AI agent that pulls real-time data from GitHub, Slack, and your codebase simultaneously, correlates findings across all sources, and performs deep security analysis that no single-source scanner can match.

## The Problem

Security reviews are fragmented. Code changes go through GitHub. Decisions happen in Slack. Tickets live in Jira. No tool connects the dots. A developer says "skip auth for the MVP" in Slack, then a PR ships an unauthenticated payment endpoint — and the code reviewer has no idea about the Slack conversation. Standard SAST tools catch the missing auth check, but they can't tell you it was an intentional shortcut with a deferred fix, or that it affects a high-criticality payment module.

## The Solution

DeepSentinel is an autonomous agent that:

1. **Gathers** data from GitHub PRs and Slack channels simultaneously via Airbyte agent connectors
2. **Understands** codebase architecture via Macroscope to contextualize findings
3. **Analyzes** code through multiple AI models via TrueFoundry AI Gateway
4. **Cross-references** findings across all sources to surface hidden risks
5. **Caches** CVE data and patterns in Aerospike for sub-millisecond lookups
6. **Stores** vulnerability history and audit trails in Ghost Postgres
7. **Optimizes** its security analysis prompts over time via Overmind
8. **Requests human approval** for sensitive actions via Auth0 CIBA

## Architecture

```
                Auth0 (Identity + Token Vault + CIBA)
                            |
        ┌───────────────────┼───────────────────┐
        |                   |                   |
   GitHub PR           Slack Msgs          Codebase
   (Airbyte)          (Airbyte)         (Macroscope)
        |                   |                   |
        └─────────┬─────────┘                   |
                  |                             |
          Cross-Source                   Architecture
          Correlation                     Context
                  |                             |
                  └──────────┬──────────────────┘
                             |
                    Security Analyzer
                   (TrueFoundry Gateway)
                   (Overmind Optimization)
                             |
                  ┌──────────┼──────────┐
                  |          |          |
             Aerospike    Ghost DB   Report
             (CVE cache)  (History)  Generation
```

## Sponsor Tool Integration

| Tool | Role | Why It's Essential |
|------|------|--------------------|
| **Auth0** | User auth + Token Vault + CIBA | Zero-privilege token access to GitHub/Slack. Human-in-the-loop approval for critical findings. |
| **Airbyte** | GitHub + Slack connectors | Real-time multi-source data ingestion. Cross-source correlation is the core differentiator. |
| **Macroscope** | Codebase understanding | Architecture-aware severity scoring. A vulnerability in the payment module is more critical than one in tests. |
| **Ghost** | Persistent Postgres | Vulnerability history, scan audit trail, cross-source correlation records. Agent manages its own DB lifecycle. |
| **Aerospike** | Real-time cache | Sub-ms CVE lookups, scan dedup, vulnerability pattern matching. TTL-based expiration for cache management. |
| **TrueFoundry** | AI Gateway | Multi-model routing (fast scan with GPT-4o-mini, deep analysis with GPT-4o). Observability and cost tracking. |
| **Overmind** | Prompt optimization | Every LLM call instrumented. Prompts optimized over time based on accepted/rejected findings. |

## Quick Start

```bash
# Clone
git clone https://github.com/ElijahUmana/deep-sentinel
cd deep-sentinel

# Setup
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env with your API keys

# Run a scan
python -m src.main <github-owner> <github-repo> <pr-number>

# Autonomous mode
python -m src.main --autonomous <github-owner> <github-repo>
```

## What It Finds That Others Don't

1. **Deferred security work**: Slack discussion about "adding auth later" + PR shipping without auth = CRITICAL
2. **Architecture-aware severity**: SQL injection in the payment module vs. in a test file — same CWE, vastly different risk
3. **Historical patterns**: This repo had 3 XSS vulnerabilities last quarter — pattern alert on new similar code
4. **Cross-tool blind spots**: The security Jira ticket exists but the PR author didn't know about it

## Vulnerability Categories (CWE-Mapped)

- CWE-798: Hardcoded credentials
- CWE-89: SQL injection
- CWE-78: Command injection
- CWE-79: Cross-site scripting
- CWE-22: Path traversal
- CWE-327: Weak cryptography
- CWE-502: Insecure deserialization
- CWE-918: SSRF
- CWE-400: Missing rate limiting
- CWE-209: Error information exposure

## Demo Video

[3-minute demo video link]

## License

MIT
