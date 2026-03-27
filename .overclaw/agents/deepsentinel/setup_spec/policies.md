# Agent Policy: DeepSentinel Security Scanner

## 1. Domain Knowledge

### 1.1 Purpose & Context
DeepSentinel analyzes source code for security vulnerabilities across 10 CWE categories and provides risk-based recommendations for code approval workflows.

### 1.2 Domain Rules
- Must scan for exactly 10 CWE categories: CWE-798 (hardcoded credentials), CWE-89 (SQL injection), CWE-78 (command injection), CWE-79 (XSS), CWE-22 (path traversal), CWE-327 (weak crypto), CWE-502 (insecure deserialization), CWE-918 (SSRF), CWE-601 (open redirect), CWE-95 (code injection)
- Hardcoded credentials include passwords, API keys, and secrets in source code (inferred)
- Weak cryptography includes MD5/SHA1 for passwords and weak ciphers (inferred)
- Path traversal requires unsanitized input in file paths (inferred)

### 1.3 Domain Edge Cases
- **No vulnerabilities found**: Return empty findings array with NONE risk level and APPROVE recommendation (inferred)
- **Multiple severity levels**: Risk level must match the highest individual finding severity (inferred)

### 1.4 Terminology & Definitions
- **Risk Level**: Overall assessment (CRITICAL/HIGH/MEDIUM/LOW/NONE/UNKNOWN)
- **Recommendation**: Action guidance (BLOCK/REVIEW/APPROVE)
- **Finding**: Individual vulnerability with severity, CWE ID, description, and fix

## 2. Agent Behavior

### 2.1 Output Constraints
- Must return structured JSON with findings array, risk_level, recommendation, and findings_count
- Each finding requires: severity, cwe_id, title, line_number, description, fix
- Findings count must equal length of findings array
- Raw analysis only included on JSON parsing failure

### 2.2 Tool Usage
- Must use claude-sonnet-4-20250514 model exclusively
- System prompt must specify all 10 CWE categories and JSON schema requirements
- Must request pure JSON response without markdown formatting

### 2.3 Decision Mapping
- CRITICAL/HIGH risk → BLOCK recommendation
- MEDIUM risk → REVIEW recommendation  
- LOW/NONE risk → APPROVE recommendation
- Zero findings → NONE risk level
- JSON parsing failure → UNKNOWN risk, REVIEW recommendation

### 2.4 Quality Expectations
- Enforce consistency between risk level and recommendation through post-processing
- Attempt multiple JSON extraction methods before fallback
- Provide actionable fix recommendations for each finding
