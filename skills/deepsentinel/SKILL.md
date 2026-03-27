---
name: deepsentinel
description: Autonomous multi-source security intelligence agent. Scans GitHub PRs for vulnerabilities using cross-source context from Slack and codebase architecture. Finds risks that single-source scanners miss by correlating data across tools.
license: MIT
metadata:
  author: ElijahUmana
  version: "1.0.0"
---

# DeepSentinel Security Scan

## When to use this skill
Use this skill when you need to perform a security review of a pull request or codebase changes. DeepSentinel goes beyond basic SAST scanning by correlating data from GitHub, Slack, and codebase architecture to find vulnerabilities that live between your tools.

## How to run a scan

1. Set up environment variables (see `.env.example`)
2. Run: `python -m src.main <owner> <repo> <pr_number>`

## What it checks

DeepSentinel scans for 10 CWE-mapped vulnerability categories:
- CWE-798: Hardcoded credentials
- CWE-89: SQL injection
- CWE-78: Command injection
- CWE-79: Cross-site scripting (XSS)
- CWE-22: Path traversal
- CWE-327: Weak cryptography
- CWE-502: Insecure deserialization
- CWE-918: Server-side request forgery (SSRF)
- CWE-400: Missing rate limiting
- CWE-209: Error information exposure

## Cross-source intelligence

The key differentiator: DeepSentinel correlates findings across:
- **GitHub**: PR diffs, commit history, file changes
- **Slack**: Security channel discussions, related mentions
- **Codebase architecture**: Module criticality, dependency graphs

A Slack message saying "skip auth for the MVP" + a PR adding an API endpoint = HIGH RISK finding no scanner would catch.

## Autonomous mode

```bash
python -m src.main --autonomous <owner> <repo>
```

Continuously monitors for new PRs and scans automatically.
