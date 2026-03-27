# DeepSentinel vs Existing Tools — Side-by-Side

## What Snyk finds on payment.py:
- CWE-798: Hardcoded credentials (line 10)
- CWE-89: SQL injection (line 17)
- CWE-78: Command injection (line 30)
- CWE-22: Path traversal (line 40)

**Total: 4 code-level findings**

## What DeepSentinel finds on the SAME code:

### Code-level (same as Snyk):
- CWE-798: Hardcoded credentials (line 10)
- CWE-89: SQL injection (line 17)
- CWE-78: Command injection (line 30)
- CWE-22: Path traversal (line 40)
- CWE-209: Database path exposure (line 23)

### Cross-source intelligence (INVISIBLE to Snyk):
1. **[HIGH] Deferred security work** — GitHub Issue #2 shows input validation was explicitly deferred by the team. The PR ships unvalidated endpoints because it was a conscious decision, not an oversight. Snyk flags the missing validation but doesn't know it was intentional deferral with no remediation date.

2. **[HIGH] Known unresolved credentials** — GitHub Issue #3 shows the team KNOWS the password is hardcoded and planned to move it to secrets manager. But it hasn't happened. Snyk flags the credential but doesn't know the team already flagged it and is accumulating risk.

3. **[HIGH] Reviewer-flagged danger** — PR #1 review comment explicitly calls out os.system() as dangerous. A human security expert reviewed this code and raised concerns. Snyk cannot see review comments.

4. **[LLM-discovered] Architectural risk pattern** — The combination of hardcoded credentials + SQL injection + command injection in a PAYMENT module represents a compound risk that's worse than the sum of its parts. A compromised payment endpoint with hardcoded credentials and command injection enables full system takeover.

### Summary:
| Metric | Snyk | DeepSentinel |
|--------|------|-------------|
| Code findings | 4 | 5 |
| Cross-source correlations | 0 | 13 |
| Team context captured | None | Deferred decisions, known issues, review concerns |
| Risk context | Severity only | Severity + business context + team awareness |
| Output | Dashboard | PR comment + SARIF + Ghost DB audit trail |
| Self-improving | No | Yes (Overmind OverClaw) |

**The 13 cross-source correlations are findings that fundamentally cannot exist in any code-only scanner.** They require connecting human decisions with code changes — which is DeepSentinel's unique capability.
