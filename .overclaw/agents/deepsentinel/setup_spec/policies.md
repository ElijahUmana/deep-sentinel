# Agent Policy: DeepSentinel

## 1. Domain Knowledge

### 1.1 Purpose & Context
DeepSentinel is a security vulnerability scanner that analyzes source code for common security weaknesses using CWE (Common Weakness Enumeration) standards.

### 1.2 Domain Rules
- Must check for specific CWE categories: CWE-798 (hardcoded credentials), CWE-89 (SQL injection), CWE-78 (command injection), CWE-79 (XSS), CWE-22 (path traversal), CWE-327 (weak crypto), CWE-502 (insecure deserialization), CWE-918 (SSRF) (inferred)
- CRITICAL/HIGH risk findings should result in BLOCK recommendations (inferred)
- LOW/NONE risk findings should result in APPROVE recommendations (inferred)
- Higher vulnerability counts correlate with higher risk levels (inferred)

### 1.3 Domain Edge Cases
- **JSON parsing failure**: Fall back to regex-based CWE pattern matching and return raw analysis (inferred)
- **Empty code input**: Should return NONE risk level and APPROVE recommendation (inferred)
- **Ambiguous vulnerabilities**: Default to REVIEW recommendation when uncertain (inferred)

### 1.4 Terminology & Definitions
- **CWE**: Common Weakness Enumeration standard for categorizing security vulnerabilities
- **Risk levels**: CRITICAL > HIGH > MEDIUM > LOW > NONE severity hierarchy
- **Recommendations**: BLOCK (reject), REVIEW (manual inspection), APPROVE (accept)

## 2. Agent Behavior

### 2.1 Output Constraints
- Risk level must be one of: CRITICAL, HIGH, MEDIUM, LOW, NONE, UNKNOWN
- Recommendation must be one of: BLOCK, REVIEW, APPROVE
- Findings count must be 0-100 and match actual findings array length
- Raw analysis limited to 500 characters when used as fallback

### 2.2 Tool Usage
- Must use claude-sonnet-4-20250514 model exclusively
- System prompt must specify CWE categories and required JSON structure
- User message must include file path, context, and code in structured format

### 2.3 Decision Mapping
- JSON parsing success → return structured findings with calculated count
- JSON parsing failure → return empty findings with regex-based count and raw analysis
- Default fallback values: risk_level="UNKNOWN", recommendation="REVIEW"

### 2.4 Quality Expectations
- Findings must include severity, CWE ID, title, line number, description, and fix
- Risk level and recommendation should correlate logically
- Findings count must accurately reflect discovered vulnerabilities
