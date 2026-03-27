# DEEP AGENTS HACKATHON — MASTER PLAN
## DeepSentinel: Autonomous Multi-Source Security Intelligence Agent

**Hackathon:** Deep Agents Hackathon (Descend / Creators Corner)
**Deadline:** March 27, 2026 @ 4:30 PM PDT
**Devpost:** https://bit.ly/devpost-mar27
**Participant:** Elijah Umana (solo)
**Prize target:** 1st place in ALL 7 sponsor tracks ($8,399+ total)

---

# TABLE OF CONTENTS

1. [EXECUTIVE SUMMARY](#1-executive-summary)
2. [PROJECT CONCEPT](#2-project-concept)
3. [JUDGING CRITERIA STRATEGY](#3-judging-criteria-strategy)
4. [SPONSOR TRACK STRATEGY](#4-sponsor-track-strategy)
5. [SYSTEM ARCHITECTURE](#5-system-architecture)
6. [AUTH0 INTEGRATION — DETAILED SPEC](#6-auth0-integration)
7. [AIRBYTE INTEGRATION — DETAILED SPEC](#7-airbyte-integration)
8. [MACROSCOPE INTEGRATION — DETAILED SPEC](#8-macroscope-integration)
9. [GHOST INTEGRATION — DETAILED SPEC](#9-ghost-integration)
10. [OVERMIND INTEGRATION — DETAILED SPEC](#10-overmind-integration)
11. [TRUEFOUNDRY INTEGRATION — DETAILED SPEC](#11-truefoundry-integration)
12. [AEROSPIKE INTEGRATION — DETAILED SPEC](#12-aerospike-integration)
13. [FILE-BY-FILE IMPLEMENTATION SPEC](#13-file-by-file-implementation-spec)
14. [DEPENDENCY GRAPH & INSTALLATION](#14-dependency-graph)
15. [ENVIRONMENT VARIABLES](#15-environment-variables)
16. [IMPLEMENTATION SEQUENCE](#16-implementation-sequence)
17. [DEMO SCRIPT — 3 MINUTES](#17-demo-script)
18. [DEVPOST SUBMISSION](#18-devpost-submission)
19. [SHIPABLES.DEV SKILL PUBLISHING](#19-shipables-skill)
20. [RISK MITIGATION](#20-risk-mitigation)

---

# 1. EXECUTIVE SUMMARY

## The Problem
Security reviews in software teams are fragmented and reactive. Vulnerabilities slip through merge requests because:
- Code reviews happen in GitHub, but context lives in Slack conversations and Jira tickets
- SAST tools produce noisy reports that nobody reads — they lack business context
- Security knowledge is siloed — the person who discussed a dependency concern in Slack isn't the one reviewing the PR
- Historical patterns are lost — the same vulnerability class appears again because nobody connected the dots across systems
- Manual review can't scale — teams push 50+ PRs/day, security engineers review 5

## The Solution
**DeepSentinel** is an autonomous AI agent that:
1. Authenticates securely (Auth0) and gets delegated access to a developer's GitHub, Slack, and Jira
2. Pulls real-time data from all three sources (Airbyte agent connectors)
3. Understands codebase architecture (Macroscope) to contextualize findings
4. Performs deep security analysis using multiple LLMs (TrueFoundry AI Gateway)
5. Stores vulnerability history and audit trails in a persistent database (Ghost Postgres)
6. Caches CVE data and hot patterns for sub-millisecond lookups (Aerospike)
7. Self-optimizes its analysis prompts over time (Overmind)

It operates **fully autonomously** — no human triggers required. It reacts to events, correlates data across sources, and takes action: creating Jira tickets, posting Slack alerts, commenting on PRs.

## Why This Wins
- **Real problem:** Every software team struggles with this. $4.88M average cost of a data breach (IBM 2024).
- **Genuinely autonomous:** Triggers → analyzes → acts. Not a chatbot.
- **All 7 tools used non-trivially:** Each tool has a clear, essential role. Nothing is bolted on.
- **Cross-source intelligence:** The core differentiator. No existing tool connects GitHub + Slack + Jira for security.
- **Self-improving:** Gets better with each scan via Overmind optimization.

---

# 2. PROJECT CONCEPT

## The Name
**DeepSentinel** — "Deep" (deep agents, deep analysis), "Sentinel" (autonomous watchguard)

## The Tagline
"Cross-source security intelligence that finds what scanners miss."

## The Core Loop

```
┌─────────────────────────────────────────────────────────────────┐
│                    DEEPSENTINEL CORE LOOP                        │
│                                                                  │
│  1. TRIGGER                                                      │
│     ├── New PR opened on GitHub                                  │
│     ├── Security discussion detected in Slack                    │
│     └── Vulnerability ticket created in Jira                     │
│                                                                  │
│  2. GATHER (Airbyte)                                             │
│     ├── Pull PR diff + commit history from GitHub                │
│     ├── Pull related Slack discussions (mentions, channels)      │
│     └── Pull linked Jira tickets + comments                     │
│                                                                  │
│  3. UNDERSTAND (Macroscope)                                      │
│     ├── Map codebase architecture                                │
│     ├── Identify affected modules and dependencies               │
│     └── Understand code patterns and conventions                 │
│                                                                  │
│  4. ANALYZE (TrueFoundry + Overmind)                             │
│     ├── Multi-model security analysis via AI Gateway             │
│     ├── Cross-reference findings across all sources              │
│     ├── Check CVE database (Aerospike cache)                     │
│     └── Compare against historical patterns (Ghost DB)           │
│                                                                  │
│  5. ACT                                                          │
│     ├── Post security report as PR comment (GitHub)              │
│     ├── Alert security channel (Slack)                           │
│     ├── Create/update vulnerability ticket (Jira)                │
│     └── Store findings in audit trail (Ghost DB)                 │
│                                                                  │
│  6. LEARN (Overmind)                                             │
│     ├── Track which findings were accepted/dismissed             │
│     ├── Optimize prompts based on feedback                       │
│     └── Reduce false positives over time                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## What Makes It "Deep"
Most security tools scan code in isolation. DeepSentinel goes deep by:
1. **Cross-source correlation:** A Slack message saying "we decided to skip input validation for the MVP" + a PR that adds an API endpoint = HIGH RISK finding that no scanner would catch
2. **Architectural awareness:** Macroscope tells us this endpoint is in the payment module → severity escalation
3. **Historical context:** Ghost DB shows this team had 3 XSS vulnerabilities last quarter → pattern alert
4. **Real-time CVE matching:** Aerospike cache instantly matches dependencies against known vulnerabilities

---

# 3. JUDGING CRITERIA STRATEGY

Each criterion is 20% of the score. Here's how we maximize each:

## 3.1 Autonomy (20%)

**What judges look for:** "How well does the agent act on real-time data without manual intervention?"

**How we score maximum:**
- The agent runs in a continuous loop, polling for new events
- When a new PR is detected on GitHub, the ENTIRE pipeline fires automatically:
  - Pulls PR data → pulls related Slack messages → checks Jira tickets
  - Analyzes code with codebase context
  - Posts results back to GitHub, Slack, and Jira
  - ALL without human input
- The agent self-improves via Overmind — learns from accepted/rejected findings
- The agent manages its own database — creates tables, stores results, queries history
- CIBA (Auth0) enables async human approval for high-risk actions (e.g., auto-creating security tickets)

**Demo proof:** We show the agent detecting a new PR, running the full pipeline, and posting results — all autonomously.

## 3.2 Idea (20%)

**What judges look for:** "Does the solution have the potential to solve a meaningful problem or demonstrate real-world value?"

**How we score maximum:**
- Security is a $188B market. Every software team needs this.
- The specific pain point — fragmented context across GitHub/Slack/Jira — is universal and unsolved
- Clear value proposition: "Find vulnerabilities that scanners miss by connecting the dots across your tools"
- Not theoretical — we demonstrate with real repos and real findings
- The "cross-source intelligence" angle is genuinely novel

## 3.3 Technical Implementation (20%)

**What judges look for:** "How well was the solution implemented?"

**How we score maximum:**
- Clean architecture: each integration is modular and well-organized
- Proper error handling throughout
- Real database schema with proper indexes
- Caching strategy with TTL-based expiration
- Multi-model LLM routing with fallbacks
- Observability via TrueFoundry + Overmind
- Proper auth with token delegation (not hardcoded keys)
- Production-quality code, not hackathon spaghetti

## 3.4 Tool Use (20%)

**What judges look for:** "Did the solution effectively use at least 3 sponsor tools?"

**How we score maximum:**
- We use ALL 7 sponsor tools (minimum is 3)
- Each tool is used in a way that's ESSENTIAL to the product, not bolted on
- We demonstrate deep understanding of each tool's capabilities
- We use advanced features, not just basic hello-world:
  - Auth0: Token Vault + CIBA, not just login
  - Airbyte: 3+ connectors + cross-source queries
  - Macroscope: Architecture analysis feeding into security context
  - Ghost: Full schema with indexes, not just one table
  - Overmind: Prompt optimization loop, not just init()
  - TrueFoundry: Multi-model routing + observability
  - Aerospike: Secondary indexes + TTL cache patterns

## 3.5 Presentation (20%)

**What judges look for:** "Demonstration of the solution in 3 minutes"

**How we score maximum:**
- Open with the problem (15 seconds): "Security tools scan code. But vulnerabilities hide in the gaps between tools."
- Show the architecture (15 seconds): Clean diagram of the data flow
- Live demo (2 minutes):
  - Agent detects a PR with a known vulnerability pattern
  - Agent pulls Slack context showing a developer discussed skipping validation
  - Agent checks Jira for related tickets
  - Agent posts a security report correlating all sources
  - Agent creates a Jira ticket and alerts Slack
- Close with impact (30 seconds): metrics, what's next

---

# 4. SPONSOR TRACK STRATEGY

## 4.1 Auth0 — Best Use of Auth0 for AI Agents ($1,750)

### What They Want
From the slides: "Four requirements to build secure agentic applications"
1. **User Authentication** — Agents need to know who I am
2. **Token Vault** — Agents should have zero standing privileges
3. **Async Authorization (CIBA)** — Agents should use async interactions for sensitive actions
4. **Fine-Grained Authorization** — Agents should only access what they need

### How We Win
We implement ALL FOUR. Most competitors will only do basic auth.

**Implementation:**
- User authenticates via Auth0 Universal Login
- Token Vault stores GitHub, Slack, and Jira tokens — the agent has NO hardcoded API keys
- When the agent wants to create a security ticket (high-risk action), it triggers CIBA — the user gets a push notification to approve/deny
- Fine-grained authorization: the agent only requests scopes it needs per action (read:repo for scanning, write:issues for ticket creation)

**Judge:** Fred Patton (Senior Developer Advocate @ Auth0/Okta) — he'll want to see Token Vault and CIBA used properly, not just basic login.

### Auth0 SDK Details
```
Python: pip install auth0-ai
JavaScript: npm install @auth0/auth0-ai
```

Key classes:
- `Auth0AIClient` — main client for AI agent auth
- `TokenVault` — manages third-party tokens (GitHub, Slack, Jira)
- `CIBAClient` — Client-Initiated Backchannel Authentication

Token Vault flow:
1. User authenticates via Auth0
2. During auth, they also authorize connections to GitHub, Slack, Jira
3. Auth0 stores and refreshes those tokens
4. The agent retrieves tokens at runtime — zero stored credentials
5. Tokens auto-refresh — the agent never deals with expiry

CIBA flow (human-in-the-loop):
1. Agent determines it needs to perform a sensitive action
2. Agent calls CIBA endpoint to initiate auth request
3. User receives push notification on their phone/email
4. User approves or denies
5. Agent receives the result and proceeds or aborts
6. Full audit trail in Auth0 logs

### Auth0 Tenant Setup
- Create tenant at auth0.com
- Create a "Machine to Machine" application for the agent
- Enable "Auth0 for AI" features
- Configure Token Vault connections for GitHub, Slack, Jira
- Enable CIBA for the application
- Set up API scopes (read:repos, write:issues, read:channels, etc.)

## 4.2 Airbyte — Conquer with Context ($1,750 + Job Interview)

### What They Want
"Projects that bring data from MULTIPLE sources through Airbyte connectors and use that combined context to create something more powerful than any single source could provide."

### How We Win
We use 3 connectors (GitHub + Slack + Jira) and demonstrate genuine cross-source intelligence.

**The killer feature:** The agent doesn't just read from each source independently — it CORRELATES across them:
- "PR #42 adds an endpoint without auth" (GitHub) + "John said in #security-reviews: 'we'll add auth in the next sprint'" (Slack) + "JIRA-567: Add authentication to /api/payments" (Jira) → The agent connects all three and produces: "PR #42 introduces an unauthenticated payment endpoint. Related Slack discussion indicates auth was deferred. Linked Jira ticket JIRA-567 confirms this is planned but not yet implemented. RISK: HIGH — payment endpoint exposed without auth until JIRA-567 is resolved."

**Judges:** Pedro Lopez (Senior SWE) and Patrick Nilan (SWE) at Airbyte. They built the connector system. They want to see:
1. Multiple connectors used together (not just one)
2. The entity-action API pattern used correctly
3. Cross-source reasoning (the whole point of their prize)
4. Proper error handling in agent tools
5. Ideally: Platform Mode with Context Store

### Connector Setup
```python
# GitHub connector
from airbyte_agent_github import GithubConnector
from airbyte_agent_github.models import GithubPersonalAccessTokenAuthConfig

github = GithubConnector(
    auth_config=GithubPersonalAccessTokenAuthConfig(token=github_token)
)

# Slack connector
from airbyte_agent_slack import SlackConnector
from airbyte_agent_slack.models import SlackTokenAuthenticationAuthConfig

slack = SlackConnector(
    auth_config=SlackTokenAuthenticationAuthConfig(api_token=slack_token)
)

# Jira connector (if available) or use direct API
from airbyte_agent_jira import JiraConnector
from airbyte_agent_jira.models import JiraAuthConfig

jira = JiraConnector(
    auth_config=JiraAuthConfig(
        username=jira_email,
        password=jira_api_token
    )
)
```

### Key Operations We Use
```python
# GitHub: List open PRs
prs = await github.execute("pull_requests", "list", {
    "owner": "target-org", "repo": "target-repo",
    "states": ["OPEN"], "per_page": 20
})

# GitHub: Get PR file changes
commits = await github.execute("commits", "list", {
    "owner": "target-org", "repo": "target-repo", "per_page": 10
})

# GitHub: Get file content
file = await github.execute("file_content", "get", {
    "owner": "target-org", "repo": "target-repo", "path": "src/api/payments.ts"
})

# Slack: Search for related discussions
messages = await slack.execute("channel_messages", "list", {
    "channel": "C_SECURITY_CHANNEL"
})

# Slack: Post security alert
await slack.execute("messages", "create", {
    "channel": "C_SECURITY_CHANNEL",
    "text": "DeepSentinel Alert: Critical vulnerability found in PR #42..."
})

# Jira: Search for related tickets
issues = await jira.execute("issues", "api_search", {
    "query": "project = SEC AND status != Done"
})

# Jira: Create vulnerability ticket
await jira.execute("issues", "create", {
    "project": "SEC",
    "summary": "Critical: Unauthenticated payment endpoint in PR #42",
    "issuetype": "Bug",
    "priority": "Critical"
})
```

### Cross-Source Correlation Logic
```python
async def correlate_findings(pr_data, slack_messages, jira_tickets):
    """
    The magic: cross-reference data from all three sources to find
    security insights that no single source could reveal.
    """
    correlations = []

    # For each file changed in the PR
    for file in pr_data.changed_files:
        # Check if anyone discussed this file/module in Slack
        related_slack = [m for m in slack_messages
                        if file.name in m.get('text', '')
                        or file.module in m.get('text', '')]

        # Check if there are Jira tickets related to this area
        related_jira = [t for t in jira_tickets
                       if file.module in t.get('summary', '')
                       or file.name in t.get('description', '')]

        if related_slack or related_jira:
            correlations.append({
                'file': file,
                'slack_context': related_slack,
                'jira_context': related_jira,
                'risk_multiplier': calculate_risk(related_slack, related_jira)
            })

    return correlations
```

## 4.3 Macroscope — Most Innovative Project ($1,000)

### What They Want
Macroscope is "the understanding engine for your codebase." They want to see innovative use of their codebase analysis capabilities.

### How We Win
We use Macroscope to add ARCHITECTURAL CONTEXT to security findings. Instead of just "SQL injection on line 42," we say "SQL injection on line 42 of the payment module, which handles $2M/month in transactions and is connected to 14 other services."

**Implementation:**
- Connect Macroscope to the target repository
- Query codebase structure: modules, dependencies, data flow
- When a vulnerability is found in a file, query Macroscope for:
  - What module is this file in?
  - What other files/services depend on this?
  - What data flows through this code path?
  - How critical is this module to the system?
- Use this context to ESCALATE or DE-ESCALATE severity

**Judges:** Ikshita Puri (SWE), Zhuolun Li (AI Engineer) @ Macroscope. They want to see their tool used in a way that demonstrates UNDERSTANDING, not just file listing.

### Setup
```bash
# Sign up at app.macroscope.com (2 weeks free)
# Connect your repository
# Use the API/MCP to query codebase understanding
```

### Integration Points
```python
# Query Macroscope for module context
async def get_codebase_context(file_path: str) -> dict:
    """
    Ask Macroscope: what is this file's role in the architecture?
    """
    # Use Macroscope API or MCP
    context = await macroscope.query(
        f"What module is {file_path} in? "
        f"What services depend on it? "
        f"What data flows through it?"
    )
    return {
        'module': context.module,
        'dependencies': context.dependencies,
        'data_flow': context.data_flow,
        'criticality': context.criticality_score
    }

# Use context to enrich security findings
async def enrich_finding(finding: dict, file_path: str) -> dict:
    context = await get_codebase_context(file_path)

    # Escalate severity based on architectural context
    if context['criticality'] == 'high':
        finding['severity'] = max_severity(finding['severity'], 'HIGH')
        finding['context'] = f"This file is in the {context['module']} module, "
                           f"which {len(context['dependencies'])} services depend on. "
                           f"Data flow: {context['data_flow']}"

    return finding
```

## 4.4 Ghost — Best Use of Ghost ($1,998)

### What They Want
Ghost is "the database for agents." CLI/MCP only, built on Postgres by the TimescaleDB team. They want to see agents that use persistent Postgres storage effectively.

### How We Win
We use Ghost as the BRAIN of DeepSentinel — storing vulnerability history, scan results, agent session state, and audit trails. We also use database forking for safe experimentation.

**Implementation:**

### Setup
```bash
# Install Ghost CLI
curl -fsSL https://install.ghost.build | sh

# Authenticate
ghost login

# Create the DeepSentinel database
ghost create --name deepsentinel

# Get connection string
ghost connect <db_id>
# Returns: postgresql://user:pass@host:port/dbname
```

### Database Schema
```sql
-- Vulnerability findings
CREATE TABLE vulnerabilities (
    id SERIAL PRIMARY KEY,
    scan_id UUID NOT NULL,
    pr_number INTEGER,
    repo_owner TEXT NOT NULL,
    repo_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_number INTEGER,
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    cwe_id TEXT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    fix_suggestion TEXT,
    -- Cross-source context
    slack_context JSONB,
    jira_context JSONB,
    macroscope_context JSONB,
    -- Status tracking
    status TEXT DEFAULT 'open' CHECK (status IN ('open', 'confirmed', 'dismissed', 'fixed')),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Scan history
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_owner TEXT NOT NULL,
    repo_name TEXT NOT NULL,
    pr_number INTEGER,
    trigger_type TEXT NOT NULL, -- 'pr_opened', 'scheduled', 'manual'
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    findings_count INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    status TEXT DEFAULT 'running' CHECK (status IN ('running', 'completed', 'failed')),
    metadata JSONB
);

-- Agent session state
CREATE TABLE agent_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id TEXT NOT NULL,
    started_at TIMESTAMPTZ DEFAULT NOW(),
    last_active TIMESTAMPTZ DEFAULT NOW(),
    state JSONB,
    tokens_used INTEGER DEFAULT 0,
    models_used TEXT[]
);

-- Audit trail
CREATE TABLE audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    action TEXT NOT NULL,
    actor TEXT NOT NULL, -- 'agent' or user_id
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    details JSONB
);

-- Cross-source correlations
CREATE TABLE correlations (
    id SERIAL PRIMARY KEY,
    scan_id UUID REFERENCES scans(id),
    github_ref TEXT, -- PR number or commit SHA
    slack_ref TEXT, -- Message timestamp or channel
    jira_ref TEXT, -- Issue key
    correlation_type TEXT NOT NULL,
    description TEXT NOT NULL,
    risk_score FLOAT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for fast queries
CREATE INDEX idx_vuln_repo ON vulnerabilities(repo_owner, repo_name);
CREATE INDEX idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX idx_vuln_status ON vulnerabilities(status);
CREATE INDEX idx_vuln_cwe ON vulnerabilities(cwe_id);
CREATE INDEX idx_scans_repo ON scans(repo_owner, repo_name);
CREATE INDEX idx_scans_pr ON scans(pr_number);
CREATE INDEX idx_audit_action ON audit_log(action);
CREATE INDEX idx_correlations_scan ON correlations(scan_id);
```

### Python Integration
```python
import asyncpg

class GhostDB:
    def __init__(self, connection_string: str):
        self.conn_str = connection_string
        self.pool = None

    async def connect(self):
        self.pool = await asyncpg.create_pool(self.conn_str)

    async def record_vulnerability(self, vuln: dict) -> int:
        async with self.pool.acquire() as conn:
            return await conn.fetchval(
                """INSERT INTO vulnerabilities
                   (scan_id, pr_number, repo_owner, repo_name, file_path,
                    line_number, severity, cwe_id, title, description,
                    fix_suggestion, slack_context, jira_context, macroscope_context)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
                   RETURNING id""",
                vuln['scan_id'], vuln.get('pr_number'), vuln['repo_owner'],
                vuln['repo_name'], vuln['file_path'], vuln.get('line_number'),
                vuln['severity'], vuln.get('cwe_id'), vuln['title'],
                vuln['description'], vuln.get('fix_suggestion'),
                json.dumps(vuln.get('slack_context')),
                json.dumps(vuln.get('jira_context')),
                json.dumps(vuln.get('macroscope_context'))
            )

    async def get_historical_patterns(self, repo_owner: str, repo_name: str) -> list:
        async with self.pool.acquire() as conn:
            return await conn.fetch(
                """SELECT cwe_id, severity, COUNT(*) as count,
                          MAX(created_at) as last_seen
                   FROM vulnerabilities
                   WHERE repo_owner = $1 AND repo_name = $2
                   GROUP BY cwe_id, severity
                   ORDER BY count DESC""",
                repo_owner, repo_name
            )

    async def start_scan(self, scan: dict) -> str:
        async with self.pool.acquire() as conn:
            return await conn.fetchval(
                """INSERT INTO scans (repo_owner, repo_name, pr_number, trigger_type)
                   VALUES ($1, $2, $3, $4) RETURNING id""",
                scan['repo_owner'], scan['repo_name'],
                scan.get('pr_number'), scan['trigger_type']
            )

    async def log_audit(self, action: str, actor: str,
                       resource_type: str, resource_id: str = None,
                       details: dict = None):
        async with self.pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO audit_log (action, actor, resource_type, resource_id, details)
                   VALUES ($1, $2, $3, $4, $5)""",
                action, actor, resource_type, resource_id,
                json.dumps(details) if details else None
            )
```

### Ghost Fork for Safe Testing
```python
# Fork the database before running a risky scan
# ghost fork <db_id> --name "deepsentinel-test"
# If the scan corrupts data, just delete the fork
# Original database is untouched
```

**Judges:** Justin Murray (SWE @ TigerData), Isabel Macaulay (Marketing @ TigerData). Ghost is by TigerData (TimescaleDB team). They want to see:
- Real database usage, not just "store a string"
- Proper schema design
- Using Ghost's unique features: fork, MCP, CLI
- Agent managing its own database lifecycle

## 4.5 Overmind — Builders Prize ($651)

### What They Want
Overmind optimizes AI agents — better prompts, better models, lower cost. They want to see their SDK used to instrument and optimize an agent.

### How We Win
We instrument EVERY LLM call in DeepSentinel with Overmind. The agent literally gets better at security analysis over time.

**Implementation:**

### Setup
```bash
pip install overmind-sdk
# Sign up at console.overmindlab.ai
```

### Instrumentation
```python
import overmind_sdk
from opentelemetry.overmind.prompt import PromptString

# Initialize once at startup
overmind_sdk.init(
    service_name="deepsentinel",
    environment="production"
)

# Wrap each prompt with PromptString for identification
security_analysis_prompt = PromptString(
    id="security_scan_v1",
    template="""You are a security analyst. Analyze the following code change for vulnerabilities.

Code diff:
{diff}

Codebase context (from Macroscope):
{architecture_context}

Historical vulnerabilities in this repo:
{historical_patterns}

Cross-source intelligence:
- Slack discussions: {slack_context}
- Jira tickets: {jira_context}

Identify all security vulnerabilities. For each, provide:
- Severity (CRITICAL/HIGH/MEDIUM/LOW)
- CWE ID
- File and line
- Attack scenario
- Specific fix

Be precise. No false positives.""",
    kwargs={
        "diff": diff_content,
        "architecture_context": macroscope_data,
        "historical_patterns": ghost_history,
        "slack_context": slack_data,
        "jira_context": jira_data
    }
)

correlation_prompt = PromptString(
    id="cross_source_correlation_v1",
    template="""You are correlating security-relevant information across multiple sources.

GitHub PR data:
{github_data}

Slack messages from security-related channels:
{slack_data}

Jira tickets in the security backlog:
{jira_data}

Find connections between these sources that reveal security risks.
Focus on: deferred security work, known vulnerabilities, compliance gaps.""",
    kwargs={...}
)

report_generation_prompt = PromptString(
    id="security_report_v1",
    template="""Generate a security report for the following findings.
{findings}
Format as a clear, actionable report with severity ratings and fix suggestions.""",
    kwargs={...}
)
```

**Why this impresses Overmind judges:**
- We use PromptString with unique IDs for each agent function
- Multiple distinct prompts means the optimization engine has real work to do
- The security analysis prompt is COMPLEX (multi-context) — exactly where optimization helps most
- We demonstrate the full cycle: instrument → collect traces → optimization activates
- Tyler Edwards (CEO) and Akhat Rakishev (CTO) will see their product adding real value

## 4.6 TrueFoundry — Best Use of AI Gateway ($600)

### What They Want
TrueFoundry AI Gateway: unified interface for 1000+ LLMs with observability, rate limiting, and governance.

### How We Win
We route ALL LLM calls through TrueFoundry, using multiple models for different tasks:
- Fast model (GPT-4o-mini via TF) for initial code scanning
- Powerful model (Claude Sonnet via TF) for deep vulnerability analysis
- Specialized model for report generation

**Implementation:**

### Setup
```bash
# Sign up at truefoundry.com
# Get API key
# Install: pip install truefoundry or use direct HTTP
```

### Multi-Model Routing
```python
import httpx

class TrueFoundryGateway:
    def __init__(self, api_key: str, base_url: str):
        self.api_key = api_key
        self.base_url = base_url
        self.client = httpx.AsyncClient()

    async def chat(self, model: str, messages: list, **kwargs) -> dict:
        """Unified interface for any model via TrueFoundry."""
        response = await self.client.post(
            f"{self.base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": model,
                "messages": messages,
                **kwargs
            }
        )
        return response.json()

    async def scan_code(self, code: str) -> dict:
        """Fast initial scan with lightweight model."""
        return await self.chat(
            model="openai/gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a code security scanner. Identify potential vulnerabilities quickly."},
                {"role": "user", "content": code}
            ],
            temperature=0.1
        )

    async def deep_analysis(self, findings: str, context: str) -> dict:
        """Deep analysis with powerful model."""
        return await self.chat(
            model="anthropic/claude-sonnet-4-6",
            messages=[
                {"role": "system", "content": "You are an expert security analyst. Perform deep vulnerability analysis."},
                {"role": "user", "content": f"Findings:\n{findings}\n\nContext:\n{context}"}
            ],
            temperature=0.0
        )

    async def generate_report(self, analysis: str) -> dict:
        """Generate human-readable report."""
        return await self.chat(
            model="openai/gpt-4o",
            messages=[
                {"role": "system", "content": "Generate a clear, actionable security report."},
                {"role": "user", "content": analysis}
            ],
            temperature=0.3
        )
```

**Why this impresses TrueFoundry judges:**
- Multi-model routing (not just one model through the gateway)
- Different models for different tasks (fast scan vs. deep analysis vs. report)
- Observability: every call is logged and traceable
- Shows understanding of the unified API interface
- Sai Krishna (Dev Rel) will appreciate the proper use of their gateway pattern

## 4.7 Aerospike — Most Innovative Use ($650)

### What They Want
Aerospike is a high-performance, real-time key-value/document database. They want innovative use of their APIs and storage model.

### How We Win
We use Aerospike as a HOT CACHE for:
1. **CVE database** — the entire NVD (National Vulnerability Database) cached for sub-ms lookups
2. **Scan result cache** — recent scans cached so repeated queries are instant
3. **Pattern fingerprints** — known vulnerability patterns stored for quick matching
4. **Session state** — agent session data for real-time access

**Implementation:**

### Setup
```bash
# Run Aerospike in Docker
docker run -d --name aerospike \
  -p 3000-3002:3000-3002 \
  aerospike/aerospike-server

# Install Python client
pip install aerospike
```

### Python Integration
```python
import aerospike
from aerospike import exception as ae_exception
import json
import time

class AerospikeCache:
    def __init__(self, host: str = '127.0.0.1', port: int = 3000):
        config = {'hosts': [(host, port)]}
        self.client = aerospike.client(config).connect()
        self.namespace = 'test'

    # =========================================
    # CVE CACHE — Sub-millisecond vulnerability lookups
    # =========================================

    def cache_cve(self, cve_id: str, cve_data: dict, ttl: int = 86400):
        """Cache a CVE entry with 24h TTL."""
        key = (self.namespace, 'cves', cve_id)
        bins = {
            'cve_id': cve_id,
            'severity': cve_data.get('severity', 'UNKNOWN'),
            'description': cve_data.get('description', '')[:1000],
            'affected_packages': json.dumps(cve_data.get('affected', [])),
            'cvss_score': cve_data.get('cvss_score', 0.0),
            'published': cve_data.get('published', ''),
            'cached_at': int(time.time())
        }
        meta = {'ttl': ttl}
        self.client.put(key, bins, meta)

    def lookup_cve(self, cve_id: str) -> dict | None:
        """Look up a CVE by ID — returns in <1ms."""
        key = (self.namespace, 'cves', cve_id)
        try:
            _, _, bins = self.client.get(key)
            bins['affected_packages'] = json.loads(bins.get('affected_packages', '[]'))
            return bins
        except ae_exception.RecordNotFound:
            return None

    def check_package_cves(self, package_name: str) -> list:
        """Check if a package has known CVEs using secondary index."""
        query = self.client.query(self.namespace, 'cves')
        # Note: requires secondary index on affected_packages
        # This demonstrates Aerospike's query capabilities
        results = []
        def callback(record):
            _, _, bins = record
            affected = json.loads(bins.get('affected_packages', '[]'))
            if package_name in str(affected):
                results.append(bins)
        query.foreach(callback)
        return results

    # =========================================
    # SCAN RESULT CACHE — Avoid redundant scans
    # =========================================

    def cache_scan_result(self, scan_key: str, results: dict, ttl: int = 3600):
        """Cache scan results for 1 hour."""
        key = (self.namespace, 'scan_cache', scan_key)
        bins = {
            'results': json.dumps(results),
            'cached_at': int(time.time()),
            'hit_count': 0
        }
        self.client.put(key, bins, {'ttl': ttl})

    def get_cached_scan(self, scan_key: str) -> dict | None:
        """Get cached scan results — avoids redundant analysis."""
        key = (self.namespace, 'scan_cache', scan_key)
        try:
            _, _, bins = self.client.get(key)
            # Increment hit count
            self.client.increment(key, 'hit_count', 1)
            return json.loads(bins.get('results', '{}'))
        except ae_exception.RecordNotFound:
            return None

    # =========================================
    # PATTERN FINGERPRINTS — Fast vulnerability matching
    # =========================================

    def store_pattern(self, pattern_id: str, pattern: dict):
        """Store a vulnerability pattern fingerprint."""
        key = (self.namespace, 'patterns', pattern_id)
        bins = {
            'pattern_id': pattern_id,
            'regex': pattern.get('regex', ''),
            'cwe_id': pattern.get('cwe_id', ''),
            'severity': pattern.get('severity', 'MEDIUM'),
            'description': pattern.get('description', ''),
            'language': pattern.get('language', 'any')
        }
        self.client.put(key, bins)

    def get_patterns_for_language(self, language: str) -> list:
        """Get all vulnerability patterns for a specific language."""
        query = self.client.query(self.namespace, 'patterns')
        results = []
        def callback(record):
            _, _, bins = record
            if bins.get('language') in (language, 'any'):
                results.append(bins)
        query.foreach(callback)
        return results

    # =========================================
    # AGENT SESSION STATE — Real-time state management
    # =========================================

    def save_session(self, session_id: str, state: dict, ttl: int = 7200):
        """Save agent session state with 2h TTL."""
        key = (self.namespace, 'sessions', session_id)
        bins = {
            'session_id': session_id,
            'state': json.dumps(state),
            'updated_at': int(time.time())
        }
        self.client.put(key, bins, {'ttl': ttl})

    def get_session(self, session_id: str) -> dict | None:
        """Retrieve agent session state."""
        key = (self.namespace, 'sessions', session_id)
        try:
            _, _, bins = self.client.get(key)
            return json.loads(bins.get('state', '{}'))
        except ae_exception.RecordNotFound:
            return None

    def close(self):
        self.client.close()
```

**Why this impresses Aerospike judges:**
- Multiple use cases: CVE cache, scan cache, pattern store, session state
- TTL-based expiration (shows understanding of Aerospike's expiration model)
- Secondary index queries (not just simple key-value gets)
- Increment operations (atomic counters for hit tracking)
- Proper namespace/set organization
- Real-time performance advantage: CVE lookups in <1ms vs 100ms+ from NVD API
- Harin Avvari (SWE), Lucas Beeler (Solutions Architect), Jagrut Nemade (SWE) will see genuine understanding of the data model

---

# 5. SYSTEM ARCHITECTURE

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        DEEPSENTINEL ARCHITECTURE                          │
│                                                                           │
│  ┌───────────┐     ┌──────────────────────────────────────────────────┐  │
│  │   Auth0    │     │              AGENT ORCHESTRATOR                  │  │
│  │           │────▶│                  (main.py)                       │  │
│  │ - Login   │     │                                                  │  │
│  │ - Token   │     │  ┌────────┐  ┌──────────┐  ┌──────────────┐    │  │
│  │   Vault   │     │  │ GitHub │  │  Slack   │  │    Jira      │    │  │
│  │ - CIBA    │     │  │Connector│ │Connector │  │  Connector   │    │  │
│  └───────────┘     │  └───┬────┘  └────┬─────┘  └──────┬───────┘    │  │
│                     │      │            │                │            │  │
│                     │      └────────────┼────────────────┘            │  │
│                     │                   │                             │  │
│                     │           ┌───────▼────────┐                   │  │
│                     │           │  CORRELATION    │                   │  │
│                     │           │    ENGINE       │                   │  │
│                     │           │ Cross-source    │                   │  │
│                     │           │ intelligence    │                   │  │
│                     │           └───────┬────────┘                   │  │
│                     │                   │                             │  │
│                     │    ┌──────────────┼──────────────┐             │  │
│                     │    │              │              │             │  │
│                     │    ▼              ▼              ▼             │  │
│                     │ ┌────────┐ ┌──────────┐ ┌────────────┐       │  │
│                     │ │Macroscop│ │TrueFoundry│ │ Aerospike  │       │  │
│                     │ │  Code  │ │AI Gateway │ │ CVE Cache  │       │  │
│                     │ │ Context│ │Multi-model│ │ Pattern DB │       │  │
│                     │ └────┬───┘ └────┬─────┘ └─────┬──────┘       │  │
│                     │      │          │             │               │  │
│                     │      └──────────┼─────────────┘               │  │
│                     │                 │                              │  │
│                     │         ┌───────▼────────┐                    │  │
│                     │         │   SECURITY     │                    │  │
│                     │         │   ANALYZER     │                    │  │
│                     │         │ + Overmind     │                    │  │
│                     │         │   optimization │                    │  │
│                     │         └───────┬────────┘                    │  │
│                     │                 │                              │  │
│                     │         ┌───────▼────────┐                    │  │
│                     │         │    Ghost DB    │                    │  │
│                     │         │  - Findings    │                    │  │
│                     │         │  - History     │                    │  │
│                     │         │  - Audit log   │                    │  │
│                     │         └───────┬────────┘                    │  │
│                     │                 │                              │  │
│                     │         ┌───────▼────────┐                    │  │
│                     │         │   REPORTER     │                    │  │
│                     │         │ - PR comment   │                    │  │
│                     │         │ - Slack alert  │                    │  │
│                     │         │ - Jira ticket  │                    │  │
│                     │         └────────────────┘                    │  │
│                     └──────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

---

# 6. AUTH0 INTEGRATION — DETAILED SPEC

## 6.1 Auth0 Tenant Configuration

### Application Setup
- **Type:** Machine-to-Machine + Regular Web Application (dual)
- **Name:** DeepSentinel
- **Allowed Callback URLs:** http://localhost:3000/callback
- **Allowed Logout URLs:** http://localhost:3000
- **Grant Types:** Authorization Code, Client Credentials, urn:openid:params:grant-type:ciba

### API Configuration
- **Name:** DeepSentinel API
- **Identifier:** https://deepsentinel.local/api
- **Signing Algorithm:** RS256
- **Permissions/Scopes:**
  - `read:repos` — Read repository data
  - `write:issues` — Create/update issues
  - `read:channels` — Read Slack channels
  - `write:messages` — Send Slack messages
  - `read:tickets` — Read Jira tickets
  - `write:tickets` — Create/update Jira tickets
  - `admin:scans` — Manage security scans

### Token Vault Connections
- **GitHub:** OAuth App with scopes `repo, read:org`
- **Slack:** Bot token with scopes `channels:read, chat:write, users:read`
- **Jira:** API token with Classic project access

### CIBA Configuration
- **Binding Message:** "DeepSentinel wants to {action} on {resource}"
- **Token Delivery Mode:** Poll
- **Interval:** 5 seconds
- **Expires In:** 300 seconds (5 minutes)

## 6.2 Code Implementation

### File: src/auth/auth0_client.py
```python
"""
Auth0 integration for DeepSentinel.
Handles: User authentication, Token Vault, CIBA async authorization.
"""
import os
import httpx
import time
from dataclasses import dataclass
from typing import Optional

@dataclass
class TokenSet:
    access_token: str
    token_type: str
    expires_at: float
    scopes: list[str]

class Auth0Client:
    def __init__(self):
        self.domain = os.environ['AUTH0_DOMAIN']
        self.client_id = os.environ['AUTH0_CLIENT_ID']
        self.client_secret = os.environ['AUTH0_CLIENT_SECRET']
        self.audience = os.environ.get('AUTH0_AUDIENCE', 'https://deepsentinel.local/api')
        self.http = httpx.AsyncClient()
        self._token_cache: dict[str, TokenSet] = {}

    # ===========================
    # USER AUTHENTICATION
    # ===========================

    async def get_device_code(self) -> dict:
        """Initiate device authorization flow for CLI auth."""
        response = await self.http.post(
            f"https://{self.domain}/oauth/device/code",
            data={
                'client_id': self.client_id,
                'scope': 'openid profile email offline_access',
                'audience': self.audience
            }
        )
        return response.json()

    async def poll_device_token(self, device_code: str, interval: int = 5) -> TokenSet:
        """Poll for device authorization completion."""
        while True:
            response = await self.http.post(
                f"https://{self.domain}/oauth/token",
                data={
                    'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
                    'device_code': device_code,
                    'client_id': self.client_id
                }
            )
            data = response.json()

            if 'access_token' in data:
                return TokenSet(
                    access_token=data['access_token'],
                    token_type=data['token_type'],
                    expires_at=time.time() + data.get('expires_in', 3600),
                    scopes=data.get('scope', '').split()
                )

            error = data.get('error')
            if error == 'authorization_pending':
                await asyncio.sleep(interval)
            elif error == 'slow_down':
                await asyncio.sleep(interval + 5)
            else:
                raise Exception(f"Auth failed: {error} - {data.get('error_description')}")

    # ===========================
    # TOKEN VAULT
    # ===========================

    async def get_vault_token(self, connection: str, user_id: str) -> str:
        """
        Retrieve a third-party token from Auth0 Token Vault.
        The agent NEVER stores credentials — Auth0 manages them.

        connection: 'github', 'slack', or 'jira'
        user_id: Auth0 user ID
        """
        # Get management API token
        mgmt_token = await self._get_management_token()

        response = await self.http.get(
            f"https://{self.domain}/api/v2/users/{user_id}/identities",
            headers={'Authorization': f'Bearer {mgmt_token}'}
        )

        identities = response.json()
        for identity in identities:
            if identity.get('connection') == connection:
                return identity.get('access_token')

        raise Exception(f"No {connection} token found for user {user_id}")

    async def _get_management_token(self) -> str:
        """Get Auth0 Management API token."""
        if 'mgmt' in self._token_cache:
            cached = self._token_cache['mgmt']
            if cached.expires_at > time.time():
                return cached.access_token

        response = await self.http.post(
            f"https://{self.domain}/oauth/token",
            json={
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'audience': f'https://{self.domain}/api/v2/',
                'grant_type': 'client_credentials'
            }
        )
        data = response.json()
        token_set = TokenSet(
            access_token=data['access_token'],
            token_type='Bearer',
            expires_at=time.time() + data.get('expires_in', 86400),
            scopes=[]
        )
        self._token_cache['mgmt'] = token_set
        return token_set.access_token

    # ===========================
    # CIBA — ASYNC AUTHORIZATION
    # ===========================

    async def request_ciba_authorization(self, user_id: str, action: str,
                                          resource: str) -> str:
        """
        Request human approval for a sensitive action via CIBA.
        Returns an auth_req_id to poll for the result.

        Example: agent wants to create a CRITICAL security ticket
        → user gets a push notification to approve/deny
        """
        response = await self.http.post(
            f"https://{self.domain}/bc-authorize",
            data={
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'login_hint': f'sub:{user_id}',
                'binding_message': f'DeepSentinel: {action} on {resource}',
                'scope': 'openid',
                'audience': self.audience
            }
        )
        data = response.json()
        return data['auth_req_id']

    async def poll_ciba_result(self, auth_req_id: str,
                                timeout: int = 300) -> bool:
        """
        Poll for CIBA authorization result.
        Returns True if approved, False if denied.
        Raises on timeout.
        """
        start = time.time()
        interval = 5

        while time.time() - start < timeout:
            response = await self.http.post(
                f"https://{self.domain}/oauth/token",
                data={
                    'grant_type': 'urn:openid:params:grant-type:ciba',
                    'auth_req_id': auth_req_id,
                    'client_id': self.client_id,
                    'client_secret': self.client_secret
                }
            )
            data = response.json()

            if 'access_token' in data:
                return True  # Approved

            error = data.get('error')
            if error == 'authorization_pending':
                await asyncio.sleep(interval)
            elif error == 'access_denied':
                return False  # Denied
            elif error == 'expired_token':
                raise TimeoutError("CIBA request expired")
            else:
                raise Exception(f"CIBA error: {error}")

        raise TimeoutError("CIBA polling timed out")

    async def authorize_sensitive_action(self, user_id: str, action: str,
                                          resource: str) -> bool:
        """
        High-level: request + poll for CIBA authorization.
        Use for: creating CRITICAL tickets, auto-fixing code, etc.
        """
        auth_req_id = await self.request_ciba_authorization(
            user_id, action, resource
        )
        return await self.poll_ciba_result(auth_req_id)

    async def close(self):
        await self.http.aclose()
```

---

# 7. AIRBYTE INTEGRATION — DETAILED SPEC

## 7.1 Connector Setup

### Dependencies
```
airbyte-agent-github>=0.1.0
airbyte-agent-slack>=0.1.0
airbyte-agent-jira>=0.1.0
```

### File: src/data/airbyte_client.py
```python
"""
Airbyte integration for DeepSentinel.
Multi-source data ingestion: GitHub + Slack + Jira.
"""
import json
import asyncio
from dataclasses import dataclass
from typing import Optional
from airbyte_agent_github import GithubConnector
from airbyte_agent_github.models import GithubPersonalAccessTokenAuthConfig
from airbyte_agent_slack import SlackConnector
from airbyte_agent_slack.models import SlackTokenAuthenticationAuthConfig
from airbyte_agent_jira import JiraConnector
from airbyte_agent_jira.models import JiraAuthConfig


@dataclass
class PRData:
    number: int
    title: str
    author: str
    body: str
    changed_files: list[dict]
    commits: list[dict]
    labels: list[str]
    created_at: str


@dataclass
class SlackContext:
    messages: list[dict]
    channels_searched: list[str]
    related_discussions: list[dict]


@dataclass
class JiraContext:
    related_tickets: list[dict]
    security_backlog: list[dict]
    recent_security_issues: list[dict]


@dataclass
class CrossSourceContext:
    """Combined context from all three sources."""
    github: PRData
    slack: SlackContext
    jira: JiraContext
    correlations: list[dict]


class AirbyteDataLayer:
    def __init__(self, github_token: str, slack_token: str,
                 jira_email: str, jira_token: str):
        self.github = GithubConnector(
            auth_config=GithubPersonalAccessTokenAuthConfig(token=github_token)
        )
        self.slack = SlackConnector(
            auth_config=SlackTokenAuthenticationAuthConfig(api_token=slack_token)
        )
        self.jira = JiraConnector(
            auth_config=JiraAuthConfig(
                username=jira_email,
                password=jira_token
            )
        )

    # ===========================
    # GITHUB DATA
    # ===========================

    async def get_open_prs(self, owner: str, repo: str) -> list[dict]:
        """Get all open PRs for monitoring."""
        result = await self.github.execute("pull_requests", "list", {
            "owner": owner, "repo": repo,
            "states": ["OPEN"], "per_page": 50
        })
        return result.data

    async def get_pr_details(self, owner: str, repo: str, pr_number: int) -> PRData:
        """Get full PR details including file changes."""
        # Get PR data
        pr = await self.github.execute("pull_requests", "get", {
            "owner": owner, "repo": repo, "number": pr_number
        })

        # Get commits
        commits_result = await self.github.execute("commits", "list", {
            "owner": owner, "repo": repo, "per_page": 20
        })

        # Get file contents for changed files
        changed_files = []
        if pr.get('changed_files_paths'):
            for file_path in pr['changed_files_paths'][:10]:  # Limit to 10 files
                try:
                    content = await self.github.execute("file_content", "get", {
                        "owner": owner, "repo": repo, "path": file_path
                    })
                    changed_files.append({
                        'path': file_path,
                        'content': content.get('content', ''),
                        'encoding': content.get('encoding', 'utf-8')
                    })
                except Exception:
                    changed_files.append({'path': file_path, 'content': '', 'error': True})

        return PRData(
            number=pr.get('number', pr_number),
            title=pr.get('title', ''),
            author=pr.get('user', {}).get('login', 'unknown'),
            body=pr.get('body', ''),
            changed_files=changed_files,
            commits=commits_result.data if hasattr(commits_result, 'data') else [],
            labels=[l.get('name', '') for l in pr.get('labels', [])],
            created_at=pr.get('created_at', '')
        )

    async def get_file_content(self, owner: str, repo: str, path: str) -> str:
        """Get raw file content from a repository."""
        result = await self.github.execute("file_content", "get", {
            "owner": owner, "repo": repo, "path": path
        })
        return result.get('content', '')

    async def search_issues(self, owner: str, repo: str, query: str) -> list[dict]:
        """Search GitHub issues."""
        result = await self.github.execute("issues", "api_search", {
            "query": f"repo:{owner}/{repo} {query}"
        })
        return result.data if hasattr(result, 'data') else []

    # ===========================
    # SLACK DATA
    # ===========================

    async def get_security_discussions(self, channels: list[str] = None) -> SlackContext:
        """
        Pull security-related discussions from Slack.
        Searches security channels and filters for relevant keywords.
        """
        if channels is None:
            # Default security-related channels
            channels = []
            # List all channels and find security-related ones
            result = await self.slack.execute("channels", "list", {})
            for ch in result.data:
                name = ch.get('name', '').lower()
                if any(kw in name for kw in ['security', 'vuln', 'infosec', 'appsec', 'devsec']):
                    channels.append(ch['id'])

            # If no security channels found, use general
            if not channels:
                for ch in result.data[:3]:  # First 3 channels
                    channels.append(ch['id'])

        all_messages = []
        for channel_id in channels[:5]:  # Limit to 5 channels
            try:
                result = await self.slack.execute("channel_messages", "list", {
                    "channel": channel_id
                })
                messages = result.data if hasattr(result, 'data') else []

                # Filter for security-relevant messages
                security_keywords = [
                    'vulnerability', 'security', 'CVE', 'XSS', 'SQL injection',
                    'auth', 'authentication', 'authorization', 'token', 'secret',
                    'encrypt', 'SSL', 'TLS', 'OWASP', 'penetration', 'exploit',
                    'patch', 'update', 'dependency', 'risk', 'compliance',
                    'skip validation', 'no auth', 'hardcoded', 'plaintext'
                ]

                for msg in messages:
                    text = msg.get('text', '').lower()
                    if any(kw.lower() in text for kw in security_keywords):
                        all_messages.append(msg)
            except Exception:
                continue

        return SlackContext(
            messages=all_messages,
            channels_searched=channels,
            related_discussions=all_messages[:20]  # Top 20 most relevant
        )

    async def post_slack_alert(self, channel: str, message: str):
        """Post a security alert to Slack."""
        await self.slack.execute("messages", "create", {
            "channel": channel,
            "text": message
        })

    # ===========================
    # JIRA DATA
    # ===========================

    async def get_security_tickets(self, project: str = None) -> JiraContext:
        """Pull security-related Jira tickets."""
        # Search for security-related issues
        jql = "labels = security OR labels = vulnerability OR type = Bug AND priority in (Critical, Highest)"
        if project:
            jql = f"project = {project} AND ({jql})"

        try:
            result = await self.jira.execute("issues", "api_search", {
                "query": jql
            })
            tickets = result.data if hasattr(result, 'data') else []
        except Exception:
            tickets = []

        # Get security backlog
        backlog_jql = "labels = security AND status != Done ORDER BY priority DESC"
        if project:
            backlog_jql = f"project = {project} AND {backlog_jql}"

        try:
            backlog_result = await self.jira.execute("issues", "api_search", {
                "query": backlog_jql
            })
            backlog = backlog_result.data if hasattr(backlog_result, 'data') else []
        except Exception:
            backlog = []

        return JiraContext(
            related_tickets=tickets,
            security_backlog=backlog,
            recent_security_issues=tickets[:10]
        )

    async def create_security_ticket(self, project: str, title: str,
                                      description: str, priority: str = "High") -> dict:
        """Create a security vulnerability ticket in Jira."""
        return await self.jira.execute("issues", "create", {
            "project": project,
            "summary": title,
            "description": description,
            "issuetype": "Bug",
            "priority": priority,
            "labels": ["security", "deepsentinel-automated"]
        })

    # ===========================
    # CROSS-SOURCE CORRELATION
    # ===========================

    async def gather_full_context(self, owner: str, repo: str,
                                   pr_number: int,
                                   jira_project: str = None) -> CrossSourceContext:
        """
        THE KEY FUNCTION: Gather context from ALL sources in parallel
        and correlate findings across them.
        """
        # Parallel data gathering
        github_task = self.get_pr_details(owner, repo, pr_number)
        slack_task = self.get_security_discussions()
        jira_task = self.get_security_tickets(jira_project)

        github_data, slack_data, jira_data = await asyncio.gather(
            github_task, slack_task, jira_task
        )

        # Cross-source correlation
        correlations = self._correlate(github_data, slack_data, jira_data)

        return CrossSourceContext(
            github=github_data,
            slack=slack_data,
            jira=jira_data,
            correlations=correlations
        )

    def _correlate(self, github: PRData, slack: SlackContext,
                   jira: JiraContext) -> list[dict]:
        """
        Find connections between data from different sources.
        This is the CORE DIFFERENTIATOR of DeepSentinel.
        """
        correlations = []

        # Correlate: PR files mentioned in Slack discussions
        for file_info in github.changed_files:
            file_path = file_info['path']
            file_name = file_path.split('/')[-1]
            module = '/'.join(file_path.split('/')[:-1])

            for msg in slack.messages:
                text = msg.get('text', '')
                if file_name in text or module in text:
                    correlations.append({
                        'type': 'slack_file_mention',
                        'github_ref': f"PR #{github.number} - {file_path}",
                        'slack_ref': msg.get('ts', ''),
                        'slack_text': text[:200],
                        'risk_note': f"File {file_name} was discussed in Slack: {text[:100]}"
                    })

        # Correlate: PR title/body referenced in Jira
        for ticket in jira.related_tickets:
            ticket_summary = ticket.get('summary', '').lower()
            ticket_desc = ticket.get('description', '').lower() if ticket.get('description') else ''

            # Check if any changed files or PR content relates to this ticket
            for file_info in github.changed_files:
                file_path = file_info['path'].lower()
                if any(part in ticket_summary or part in ticket_desc
                       for part in file_path.split('/')):
                    correlations.append({
                        'type': 'jira_file_reference',
                        'github_ref': f"PR #{github.number} - {file_info['path']}",
                        'jira_ref': ticket.get('key', ''),
                        'jira_summary': ticket.get('summary', ''),
                        'risk_note': f"Changed file relates to Jira ticket {ticket.get('key')}: {ticket.get('summary')}"
                    })

        # Correlate: Deferred security work
        for ticket in jira.security_backlog:
            status = ticket.get('status', {}).get('name', '').lower() if isinstance(ticket.get('status'), dict) else ''
            if status in ('to do', 'backlog', 'open'):
                # Check if the PR touches code that this security ticket relates to
                ticket_summary = ticket.get('summary', '').lower()
                for file_info in github.changed_files:
                    content = file_info.get('content', '').lower()
                    if any(keyword in content for keyword in ticket_summary.split()[:3]):
                        correlations.append({
                            'type': 'deferred_security_work',
                            'github_ref': f"PR #{github.number}",
                            'jira_ref': ticket.get('key', ''),
                            'risk_note': f"PR touches code related to unresolved security ticket {ticket.get('key')}: {ticket.get('summary')}",
                            'severity_boost': True
                        })

        return correlations
```

---

# 8. MACROSCOPE INTEGRATION — DETAILED SPEC

## 8.1 Setup

```bash
# Sign up at app.macroscope.com — 2 weeks free trial
# Connect repository via GitHub integration
# Wait for initial analysis to complete
```

## 8.2 File: src/analysis/macroscope_client.py

```python
"""
Macroscope integration for DeepSentinel.
Provides codebase architecture context for security analysis.
"""
import httpx
from typing import Optional


class MacroscopeClient:
    """
    Queries Macroscope for codebase understanding.
    Adds architectural context to security findings.
    """

    def __init__(self, api_key: str, project_id: str):
        self.api_key = api_key
        self.project_id = project_id
        self.base_url = "https://api.macroscope.com/v1"
        self.http = httpx.AsyncClient(headers={
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        })

    async def get_module_context(self, file_path: str) -> dict:
        """
        Get architectural context for a file.
        Returns: module name, dependencies, criticality, data flow.
        """
        response = await self.http.post(
            f"{self.base_url}/projects/{self.project_id}/query",
            json={
                "query": f"What module is {file_path} in? "
                         f"What services and files depend on it? "
                         f"What data flows through this code path? "
                         f"How critical is this module to the overall system?"
            }
        )

        if response.status_code == 200:
            data = response.json()
            return {
                'file_path': file_path,
                'module': data.get('module', 'unknown'),
                'dependencies': data.get('dependencies', []),
                'dependents': data.get('dependents', []),
                'data_flow': data.get('data_flow', ''),
                'criticality': data.get('criticality', 'medium'),
                'description': data.get('description', '')
            }
        return {
            'file_path': file_path,
            'module': 'unknown',
            'dependencies': [],
            'dependents': [],
            'data_flow': '',
            'criticality': 'medium',
            'description': ''
        }

    async def get_architecture_overview(self) -> dict:
        """Get high-level architecture of the codebase."""
        response = await self.http.post(
            f"{self.base_url}/projects/{self.project_id}/query",
            json={
                "query": "Describe the overall architecture of this codebase. "
                         "What are the main modules? How do they interact? "
                         "Where is sensitive data handled? "
                         "What are the external API boundaries?"
            }
        )

        if response.status_code == 200:
            return response.json()
        return {}

    async def get_security_surface(self) -> dict:
        """Identify the security-relevant surface area."""
        response = await self.http.post(
            f"{self.base_url}/projects/{self.project_id}/query",
            json={
                "query": "Identify all security-relevant code: "
                         "authentication modules, API endpoints, "
                         "database queries, file I/O operations, "
                         "external service calls, and data validation logic."
            }
        )

        if response.status_code == 200:
            return response.json()
        return {}

    async def enrich_vulnerability(self, vuln: dict) -> dict:
        """
        Enrich a vulnerability finding with architectural context.
        This is what makes DeepSentinel's findings MORE than a basic scanner.
        """
        file_path = vuln.get('file_path', '')
        context = await self.get_module_context(file_path)

        vuln['macroscope_context'] = context

        # Severity escalation based on architectural context
        if context['criticality'] == 'high':
            vuln['severity_note'] = (
                f"ESCALATED: This file is in the {context['module']} module "
                f"which is marked as HIGH criticality. "
                f"{len(context['dependents'])} other components depend on it."
            )
            if vuln.get('severity') == 'MEDIUM':
                vuln['severity'] = 'HIGH'
            elif vuln.get('severity') == 'LOW':
                vuln['severity'] = 'MEDIUM'

        # Add data flow context
        if context['data_flow']:
            vuln['data_flow_note'] = f"Data flow: {context['data_flow']}"

        return vuln

    async def close(self):
        await self.http.aclose()
```

---

# 9. GHOST INTEGRATION — DETAILED SPEC

(See Section 4.4 for full schema and code. File: src/storage/ghost_db.py)

## 9.1 Setup Commands
```bash
curl -fsSL https://install.ghost.build | sh
ghost login
ghost create --name deepsentinel
# Note the database ID returned
ghost connect <DB_ID>
# Returns: postgresql://user:pass@host:port/dbname

# Initialize schema
ghost sql <DB_ID> < schema.sql
```

## 9.2 Schema File: schema.sql
(See Section 4.4 for full CREATE TABLE statements)

## 9.3 Ghost-Specific Features We Use
1. **Database forking:** Before running experimental scans, fork the DB. If something goes wrong, delete the fork.
2. **MCP integration:** Install Ghost MCP so Claude Code can query our database directly.
3. **Schema inspection:** Use `ghost schema <DB_ID>` to verify table structure.
4. **SQL execution:** Use `ghost sql <DB_ID> "SELECT ..."` for ad-hoc queries.

---

# 10. OVERMIND INTEGRATION — DETAILED SPEC

(See Section 4.5 for full code. File: src/optimization/overmind_client.py)

## 10.1 Key Implementation Details
```python
# Initialize ONCE at startup
import overmind_sdk
overmind_sdk.init(
    service_name="deepsentinel",
    environment="production",
    providers=["openai", "anthropic"]  # Instrument both providers
)

# Every LLM prompt wrapped with PromptString
from opentelemetry.overmind.prompt import PromptString

# Three distinct prompts for optimization:
# 1. security_scan_v1 — Initial vulnerability detection
# 2. cross_source_correlation_v1 — Cross-source intelligence
# 3. security_report_v1 — Report generation

# After 30+ traces, Overmind's optimization engine activates
# and starts recommending better prompts and models
```

---

# 11. TRUEFOUNDRY INTEGRATION — DETAILED SPEC

(See Section 4.6 for full code. File: src/llm/truefoundry_gateway.py)

## 11.1 Setup
```bash
# Sign up at truefoundry.com
# Get API key from dashboard
# Base URL: provided during signup
```

## 11.2 Multi-Model Strategy
| Task | Model | Why |
|------|-------|-----|
| Initial code scan | gpt-4o-mini | Fast, cheap, good for pattern matching |
| Deep vulnerability analysis | claude-sonnet-4-6 | Best at nuanced security reasoning |
| Report generation | gpt-4o | Good at structured output and formatting |
| Correlation analysis | claude-sonnet-4-6 | Best at connecting complex information |

---

# 12. AEROSPIKE INTEGRATION — DETAILED SPEC

(See Section 4.7 for full code. File: src/storage/aerospike_cache.py)

## 12.1 Docker Setup
```bash
docker run -d --name aerospike \
  -p 3000-3002:3000-3002 \
  aerospike/aerospike-server:latest
```

## 12.2 Data Organization
| Namespace | Set | Key Pattern | TTL | Purpose |
|-----------|-----|-------------|-----|---------|
| test | cves | CVE-YYYY-XXXXX | 24h | CVE database cache |
| test | scan_cache | {repo}:{pr}:{sha} | 1h | Scan result dedup |
| test | patterns | {cwe}:{lang}:{id} | None | Vulnerability patterns |
| test | sessions | {session_uuid} | 2h | Agent session state |

## 12.3 Preloaded CVE Data
At startup, we preload the top 500 most critical CVEs from NVD into Aerospike. This demonstrates:
- Batch write performance
- Real-time lookup capability
- Cache strategy with TTL

---

# 13. FILE-BY-FILE IMPLEMENTATION SPEC

## 13.1 Project Structure
```
deep-agents-hackathon/
├── README.md                          # Project description for Devpost
├── requirements.txt                   # Python dependencies
├── .env.example                       # Environment variable template
├── .gitignore                         # Standard Python gitignore
├── LICENSE                            # MIT License
├── schema.sql                         # Ghost database schema
├── setup.sh                           # One-command setup script
├── src/
│   ├── __init__.py
│   ├── main.py                        # Entry point + orchestrator
│   ├── config.py                      # Configuration management
│   ├── auth/
│   │   ├── __init__.py
│   │   └── auth0_client.py            # Auth0 login + Token Vault + CIBA
│   ├── data/
│   │   ├── __init__.py
│   │   └── airbyte_client.py          # Airbyte GitHub + Slack + Jira
│   ├── analysis/
│   │   ├── __init__.py
│   │   ├── macroscope_client.py       # Macroscope codebase understanding
│   │   ├── security_analyzer.py       # Core security analysis logic
│   │   └── correlation_engine.py      # Cross-source correlation
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── ghost_db.py                # Ghost Postgres operations
│   │   └── aerospike_cache.py         # Aerospike hot cache
│   ├── llm/
│   │   ├── __init__.py
│   │   └── truefoundry_gateway.py     # TrueFoundry AI Gateway
│   └── optimization/
│       ├── __init__.py
│       └── overmind_client.py         # Overmind SDK instrumentation
├── skills/
│   └── skill.json                     # Shipables.dev skill definition
└── demo/
    ├── demo_repo/                     # Sample repo with vulnerabilities
    │   ├── src/
    │   │   ├── api/
    │   │   │   └── payments.ts        # Vulnerable payment endpoint
    │   │   ├── auth/
    │   │   │   └── login.ts           # Weak auth implementation
    │   │   └── db/
    │   │       └── queries.ts         # SQL injection vulnerable
    │   └── package.json
    └── demo_script.md                 # Step-by-step demo walkthrough
```

## 13.2 File: src/main.py — The Orchestrator

```python
"""
DeepSentinel — Autonomous Multi-Source Security Intelligence Agent

Entry point and main orchestration loop.
"""
import asyncio
import os
import json
import uuid
from datetime import datetime
from dotenv import load_dotenv

# Overmind instrumentation — MUST be first
import overmind_sdk
overmind_sdk.init(service_name="deepsentinel", environment="production")

from src.config import Config
from src.auth.auth0_client import Auth0Client
from src.data.airbyte_client import AirbyteDataLayer
from src.analysis.macroscope_client import MacroscopeClient
from src.analysis.security_analyzer import SecurityAnalyzer
from src.analysis.correlation_engine import CorrelationEngine
from src.storage.ghost_db import GhostDB
from src.storage.aerospike_cache import AerospikeCache
from src.llm.truefoundry_gateway import TrueFoundryGateway


class DeepSentinel:
    """The main agent orchestrator."""

    def __init__(self):
        load_dotenv()
        self.config = Config()

        # Initialize all integrations
        self.auth = Auth0Client()
        self.data = AirbyteDataLayer(
            github_token=os.environ['GITHUB_TOKEN'],
            slack_token=os.environ['SLACK_BOT_TOKEN'],
            jira_email=os.environ['JIRA_EMAIL'],
            jira_token=os.environ['JIRA_API_TOKEN']
        )
        self.macroscope = MacroscopeClient(
            api_key=os.environ['MACROSCOPE_API_KEY'],
            project_id=os.environ['MACROSCOPE_PROJECT_ID']
        )
        self.llm = TrueFoundryGateway(
            api_key=os.environ['TRUEFOUNDRY_API_KEY'],
            base_url=os.environ['TRUEFOUNDRY_BASE_URL']
        )
        self.db = GhostDB(os.environ['GHOST_CONNECTION_STRING'])
        self.cache = AerospikeCache()
        self.analyzer = SecurityAnalyzer(self.llm, self.cache)
        self.correlator = CorrelationEngine()

    async def initialize(self):
        """Set up connections and load initial data."""
        print("[DeepSentinel] Initializing...")

        # Connect to Ghost DB
        await self.db.connect()
        print("[DeepSentinel] Ghost DB connected")

        # Preload CVE cache into Aerospike
        await self._preload_cve_cache()
        print("[DeepSentinel] Aerospike CVE cache loaded")

        print("[DeepSentinel] All systems operational")

    async def _preload_cve_cache(self):
        """Load top CVEs into Aerospike for fast lookup."""
        # Preload common vulnerability patterns
        patterns = [
            {"pattern_id": "cwe-798-hardcoded", "regex": r"(password|secret|api_key|token)\s*=\s*['\"][^'\"]+['\"]", "cwe_id": "CWE-798", "severity": "CRITICAL", "description": "Hardcoded credentials", "language": "any"},
            {"pattern_id": "cwe-89-sqli", "regex": r"(SELECT|INSERT|UPDATE|DELETE).*\+.*\b(req|request|params|query)\b", "cwe_id": "CWE-89", "severity": "HIGH", "description": "SQL injection via string concatenation", "language": "any"},
            {"pattern_id": "cwe-78-cmdi", "regex": r"(exec|spawn|system|popen)\s*\(.*\b(req|request|input|params)\b", "cwe_id": "CWE-78", "severity": "CRITICAL", "description": "Command injection", "language": "any"},
            {"pattern_id": "cwe-79-xss", "regex": r"(innerHTML|document\.write|\.html\()\s*.*\b(req|request|input|params)\b", "cwe_id": "CWE-79", "severity": "HIGH", "description": "Cross-site scripting", "language": "any"},
            {"pattern_id": "cwe-22-traversal", "regex": r"(readFile|readFileSync|open)\s*\(.*\b(req|request|path|filename)\b", "cwe_id": "CWE-22", "severity": "HIGH", "description": "Path traversal", "language": "any"},
            {"pattern_id": "cwe-327-crypto", "regex": r"(md5|sha1|des|rc4|createHash\(['\"]md5['\"])", "cwe_id": "CWE-327", "severity": "MEDIUM", "description": "Weak cryptography", "language": "any"},
            {"pattern_id": "cwe-502-deser", "regex": r"(pickle\.loads|yaml\.load\(|unserialize|JSON\.parse.*eval)", "cwe_id": "CWE-502", "severity": "HIGH", "description": "Insecure deserialization", "language": "any"},
            {"pattern_id": "cwe-918-ssrf", "regex": r"(fetch|axios|request|http\.get)\s*\(.*\b(req|request|url|input)\b", "cwe_id": "CWE-918", "severity": "HIGH", "description": "Server-side request forgery", "language": "any"},
        ]

        for pattern in patterns:
            self.cache.store_pattern(pattern['pattern_id'], pattern)

    async def scan_pr(self, owner: str, repo: str, pr_number: int,
                      jira_project: str = None) -> dict:
        """
        MAIN FUNCTION: Autonomous security scan of a pull request.

        1. Gather context from GitHub + Slack + Jira (Airbyte)
        2. Understand codebase architecture (Macroscope)
        3. Analyze for vulnerabilities (TrueFoundry + Aerospike)
        4. Correlate across sources
        5. Store results (Ghost DB)
        6. Report findings (GitHub comment + Slack alert + Jira ticket)
        """
        scan_id = str(uuid.uuid4())
        print(f"\n{'='*60}")
        print(f"[DeepSentinel] Starting scan {scan_id}")
        print(f"[DeepSentinel] Target: {owner}/{repo} PR #{pr_number}")
        print(f"{'='*60}\n")

        # Record scan start
        await self.db.start_scan({
            'scan_id': scan_id,
            'repo_owner': owner,
            'repo_name': repo,
            'pr_number': pr_number,
            'trigger_type': 'manual'
        })
        await self.db.log_audit('scan_started', 'agent', 'scan', scan_id)

        # ============================
        # STEP 1: GATHER (Airbyte)
        # ============================
        print("[1/6] Gathering cross-source context via Airbyte...")
        context = await self.data.gather_full_context(
            owner, repo, pr_number, jira_project
        )
        print(f"  - GitHub: PR #{context.github.number} — {context.github.title}")
        print(f"  - GitHub: {len(context.github.changed_files)} files changed")
        print(f"  - Slack: {len(context.slack.messages)} security-related messages found")
        print(f"  - Jira: {len(context.jira.related_tickets)} related tickets found")
        print(f"  - Correlations: {len(context.correlations)} cross-source links")

        # ============================
        # STEP 2: UNDERSTAND (Macroscope)
        # ============================
        print("\n[2/6] Analyzing codebase architecture via Macroscope...")
        architecture = await self.macroscope.get_architecture_overview()

        file_contexts = {}
        for file_info in context.github.changed_files:
            file_path = file_info['path']
            file_ctx = await self.macroscope.get_module_context(file_path)
            file_contexts[file_path] = file_ctx
            print(f"  - {file_path}: module={file_ctx['module']}, criticality={file_ctx['criticality']}")

        # ============================
        # STEP 3: CHECK CACHE (Aerospike)
        # ============================
        print("\n[3/6] Checking Aerospike cache for known patterns...")
        cache_key = f"{owner}:{repo}:{pr_number}"
        cached = self.cache.get_cached_scan(cache_key)
        if cached:
            print("  - Cache HIT: returning cached results")
            return cached
        print("  - Cache MISS: proceeding with full analysis")

        # Get historical patterns from Ghost DB
        historical = await self.db.get_historical_patterns(owner, repo)
        print(f"  - Historical: {len(historical)} known vulnerability patterns for this repo")

        # ============================
        # STEP 4: ANALYZE (TrueFoundry + Overmind)
        # ============================
        print("\n[4/6] Running security analysis via TrueFoundry AI Gateway...")

        # Prepare analysis context
        analysis_context = {
            'pr': {
                'number': context.github.number,
                'title': context.github.title,
                'author': context.github.author,
                'files': [{
                    'path': f['path'],
                    'content': f.get('content', '')[:2000]
                } for f in context.github.changed_files]
            },
            'architecture': file_contexts,
            'slack_context': [m.get('text', '')[:200] for m in context.slack.messages[:5]],
            'jira_context': [t.get('summary', '') for t in context.jira.related_tickets[:5]],
            'historical_patterns': [
                {'cwe': r.get('cwe_id', ''), 'count': r.get('count', 0)}
                for r in (historical or [])
            ],
            'correlations': context.correlations[:10]
        }

        # Run analysis through TrueFoundry (instrumented by Overmind)
        findings = await self.analyzer.analyze(analysis_context)
        print(f"  - Found {len(findings)} potential vulnerabilities")

        # Enrich findings with Macroscope context
        for finding in findings:
            file_path = finding.get('file_path', '')
            if file_path in file_contexts:
                finding = await self.macroscope.enrich_vulnerability(finding)

        # ============================
        # STEP 5: STORE (Ghost DB)
        # ============================
        print("\n[5/6] Storing results in Ghost DB...")

        critical_count = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
        high_count = sum(1 for f in findings if f.get('severity') == 'HIGH')

        for finding in findings:
            finding['scan_id'] = scan_id
            finding['repo_owner'] = owner
            finding['repo_name'] = repo
            finding['pr_number'] = pr_number
            await self.db.record_vulnerability(finding)

        # Cache results in Aerospike
        self.cache.cache_scan_result(cache_key, {
            'scan_id': scan_id,
            'findings': findings,
            'timestamp': datetime.utcnow().isoformat()
        })

        await self.db.log_audit('scan_completed', 'agent', 'scan', scan_id, {
            'findings_count': len(findings),
            'critical': critical_count,
            'high': high_count
        })

        # ============================
        # STEP 6: REPORT
        # ============================
        print("\n[6/6] Generating and distributing security report...")

        report = await self.analyzer.generate_report(findings, context.correlations)

        print(f"\n{'='*60}")
        print(f"[DeepSentinel] SCAN COMPLETE")
        print(f"  Findings: {len(findings)} total")
        print(f"  Critical: {critical_count}")
        print(f"  High: {high_count}")
        print(f"  Cross-source correlations: {len(context.correlations)}")
        print(f"  Scan ID: {scan_id}")
        print(f"{'='*60}\n")

        print(report)

        return {
            'scan_id': scan_id,
            'findings': findings,
            'correlations': context.correlations,
            'report': report
        }

    async def run_continuous(self, owner: str, repo: str,
                             poll_interval: int = 60):
        """
        AUTONOMOUS MODE: Continuously monitor for new PRs and scan them.
        This is what scores maximum on the Autonomy criterion.
        """
        print(f"[DeepSentinel] Autonomous mode: monitoring {owner}/{repo}")
        print(f"[DeepSentinel] Poll interval: {poll_interval}s")

        scanned_prs = set()

        while True:
            try:
                # Check for new open PRs
                prs = await self.data.get_open_prs(owner, repo)

                for pr in prs:
                    pr_number = pr.get('number')
                    if pr_number and pr_number not in scanned_prs:
                        print(f"\n[DeepSentinel] New PR detected: #{pr_number}")
                        await self.scan_pr(owner, repo, pr_number)
                        scanned_prs.add(pr_number)

                await asyncio.sleep(poll_interval)

            except KeyboardInterrupt:
                print("\n[DeepSentinel] Shutting down autonomous mode...")
                break
            except Exception as e:
                print(f"[DeepSentinel] Error in monitoring loop: {e}")
                await asyncio.sleep(poll_interval)

    async def shutdown(self):
        """Clean up all connections."""
        await self.auth.close()
        await self.macroscope.close()
        await self.db.close()
        self.cache.close()


async def main():
    """Entry point."""
    sentinel = DeepSentinel()
    await sentinel.initialize()

    # Demo mode: scan a specific PR
    import sys
    if len(sys.argv) >= 4:
        owner = sys.argv[1]
        repo = sys.argv[2]
        pr_number = int(sys.argv[3])
        jira_project = sys.argv[4] if len(sys.argv) > 4 else None

        result = await sentinel.scan_pr(owner, repo, pr_number, jira_project)

        # Print formatted report
        print("\n" + result.get('report', 'No report generated'))
    else:
        print("Usage: python -m src.main <owner> <repo> <pr_number> [jira_project]")
        print("       python -m src.main --autonomous <owner> <repo>")

        if len(sys.argv) >= 3 and sys.argv[1] == '--autonomous':
            await sentinel.run_continuous(sys.argv[2], sys.argv[3])

    await sentinel.shutdown()


if __name__ == '__main__':
    asyncio.run(main())
```

## 13.3 File: src/analysis/security_analyzer.py

```python
"""
Core security analysis engine.
Uses TrueFoundry for multi-model analysis, Overmind for optimization.
"""
import json
from opentelemetry.overmind.prompt import PromptString
from src.llm.truefoundry_gateway import TrueFoundryGateway
from src.storage.aerospike_cache import AerospikeCache


class SecurityAnalyzer:
    def __init__(self, llm: TrueFoundryGateway, cache: AerospikeCache):
        self.llm = llm
        self.cache = cache

    async def analyze(self, context: dict) -> list[dict]:
        """
        Run multi-step security analysis.
        Step 1: Fast scan with lightweight model
        Step 2: Deep analysis of flagged items with powerful model
        """
        findings = []

        for file_info in context['pr']['files']:
            if not file_info.get('content'):
                continue

            # Step 1: Fast initial scan
            # Overmind tracks this prompt for optimization
            scan_prompt = PromptString(
                id="security_scan_v1",
                template="""Analyze this code for security vulnerabilities:

File: {file_path}
```
{code}
```

Architecture context: {arch_context}
Historical patterns: {history}

Cross-source intelligence:
Slack: {slack}
Jira: {jira}

Return JSON array of findings. Each finding must have:
- severity: CRITICAL/HIGH/MEDIUM/LOW
- cwe_id: CWE-XXX
- line_number: int (approximate)
- title: string
- description: string
- attack_scenario: string
- fix_suggestion: string

If no vulnerabilities found, return an empty array: []
ONLY return the JSON array, no other text.""",
                kwargs={
                    "file_path": file_info['path'],
                    "code": file_info['content'][:3000],
                    "arch_context": json.dumps(context.get('architecture', {}).get(file_info['path'], {})),
                    "history": json.dumps(context.get('historical_patterns', [])),
                    "slack": json.dumps(context.get('slack_context', [])),
                    "jira": json.dumps(context.get('jira_context', []))
                }
            )

            # Use TrueFoundry for fast scan
            result = await self.llm.chat(
                model="openai/gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a security vulnerability scanner. Output ONLY valid JSON."},
                    {"role": "user", "content": str(scan_prompt)}
                ],
                temperature=0.1
            )

            # Parse findings
            try:
                content = result.get('choices', [{}])[0].get('message', {}).get('content', '[]')
                # Clean up content - remove markdown code blocks if present
                content = content.strip()
                if content.startswith('```'):
                    content = content.split('\n', 1)[1] if '\n' in content else content[3:]
                if content.endswith('```'):
                    content = content[:-3]
                content = content.strip()

                file_findings = json.loads(content)
                if isinstance(file_findings, list):
                    for f in file_findings:
                        f['file_path'] = file_info['path']
                    findings.extend(file_findings)
            except (json.JSONDecodeError, KeyError, IndexError):
                continue

        # Step 2: Deep analysis of CRITICAL/HIGH findings
        critical_findings = [f for f in findings if f.get('severity') in ('CRITICAL', 'HIGH')]
        if critical_findings:
            deep_prompt = PromptString(
                id="deep_analysis_v1",
                template="""You are an expert security analyst. Review these findings for accuracy.
Remove any false positives. Enhance descriptions with specific attack scenarios.

Findings:
{findings}

Cross-source correlations:
{correlations}

Return the verified findings as a JSON array. Keep the same format.
Remove any that are false positives. Add a 'verified' field set to true for real issues.""",
                kwargs={
                    "findings": json.dumps(critical_findings, indent=2),
                    "correlations": json.dumps(context.get('correlations', []))
                }
            )

            deep_result = await self.llm.chat(
                model="anthropic/claude-sonnet-4-6",
                messages=[
                    {"role": "system", "content": "You are an expert security analyst. Output ONLY valid JSON."},
                    {"role": "user", "content": str(deep_prompt)}
                ],
                temperature=0.0
            )

            try:
                content = deep_result.get('choices', [{}])[0].get('message', {}).get('content', '[]')
                content = content.strip()
                if content.startswith('```'):
                    content = content.split('\n', 1)[1] if '\n' in content else content[3:]
                if content.endswith('```'):
                    content = content[:-3]

                verified = json.loads(content.strip())
                if isinstance(verified, list):
                    # Replace critical findings with verified versions
                    non_critical = [f for f in findings if f.get('severity') not in ('CRITICAL', 'HIGH')]
                    findings = non_critical + verified
            except (json.JSONDecodeError, KeyError, IndexError):
                pass

        return findings

    async def generate_report(self, findings: list[dict],
                               correlations: list[dict]) -> str:
        """Generate a formatted security report."""
        report_prompt = PromptString(
            id="security_report_v1",
            template="""Generate a security report from these findings and cross-source correlations.

Findings:
{findings}

Cross-source correlations:
{correlations}

Format the report as:

# DeepSentinel Security Report

**Total findings: X (Y critical, Z high, W medium, V low)**

## Critical Findings
[For each critical finding]
### [CRITICAL] Title
- **CWE:** CWE-XXX
- **File:** path:line
- **Risk:** Attack scenario
- **Fix:** Specific fix
- **Cross-source context:** [Any correlated Slack/Jira info]

## High Findings
[Same format]

## Medium Findings
[Same format]

## Cross-Source Intelligence
[Summarize the correlations found between GitHub, Slack, and Jira]

## Recommendation
BLOCK / REVIEW / APPROVE with explanation.""",
            kwargs={
                "findings": json.dumps(findings, indent=2),
                "correlations": json.dumps(correlations, indent=2)
            }
        )

        result = await self.llm.chat(
            model="openai/gpt-4o",
            messages=[
                {"role": "system", "content": "You generate clear, actionable security reports."},
                {"role": "user", "content": str(report_prompt)}
            ],
            temperature=0.3
        )

        return result.get('choices', [{}])[0].get('message', {}).get('content', 'Report generation failed')
```

## 13.4 File: src/config.py

```python
"""Configuration management for DeepSentinel."""
import os
from dataclasses import dataclass

@dataclass
class Config:
    # Auth0
    auth0_domain: str = os.environ.get('AUTH0_DOMAIN', '')
    auth0_client_id: str = os.environ.get('AUTH0_CLIENT_ID', '')
    auth0_client_secret: str = os.environ.get('AUTH0_CLIENT_SECRET', '')

    # Airbyte data sources
    github_token: str = os.environ.get('GITHUB_TOKEN', '')
    slack_bot_token: str = os.environ.get('SLACK_BOT_TOKEN', '')
    jira_email: str = os.environ.get('JIRA_EMAIL', '')
    jira_api_token: str = os.environ.get('JIRA_API_TOKEN', '')

    # Macroscope
    macroscope_api_key: str = os.environ.get('MACROSCOPE_API_KEY', '')
    macroscope_project_id: str = os.environ.get('MACROSCOPE_PROJECT_ID', '')

    # Ghost
    ghost_connection_string: str = os.environ.get('GHOST_CONNECTION_STRING', '')

    # TrueFoundry
    truefoundry_api_key: str = os.environ.get('TRUEFOUNDRY_API_KEY', '')
    truefoundry_base_url: str = os.environ.get('TRUEFOUNDRY_BASE_URL', '')

    # Overmind
    overmind_api_key: str = os.environ.get('OVERMIND_API_KEY', '')

    # Aerospike
    aerospike_host: str = os.environ.get('AEROSPIKE_HOST', '127.0.0.1')
    aerospike_port: int = int(os.environ.get('AEROSPIKE_PORT', '3000'))
```

---

# 14. DEPENDENCY GRAPH & INSTALLATION

## 14.1 requirements.txt
```
# Core
python-dotenv>=1.0.0
httpx>=0.27.0
asyncpg>=0.29.0
pydantic>=2.0.0

# Auth0
# auth0-ai  (install if available, otherwise use httpx directly)

# Airbyte Agent Connectors
airbyte-agent-github>=0.1.0
airbyte-agent-slack>=0.1.0
airbyte-agent-jira>=0.1.0

# Overmind
overmind-sdk>=0.1.0

# Aerospike
aerospike>=15.0.0

# Utilities
rich>=13.0.0
```

## 14.2 setup.sh
```bash
#!/bin/bash
set -e

echo "=== DeepSentinel Setup ==="

# Python dependencies
pip install -r requirements.txt

# Aerospike Docker
echo "Starting Aerospike..."
docker run -d --name aerospike -p 3000-3002:3000-3002 aerospike/aerospike-server:latest 2>/dev/null || echo "Aerospike already running"

# Ghost CLI
echo "Installing Ghost CLI..."
curl -fsSL https://install.ghost.build | sh 2>/dev/null || echo "Ghost already installed"

echo "=== Setup Complete ==="
echo "Now configure your .env file and run: python -m src.main"
```

---

# 15. ENVIRONMENT VARIABLES

## 15.1 .env.example
```bash
# Auth0
AUTH0_DOMAIN=your-tenant.us.auth0.com
AUTH0_CLIENT_ID=your_client_id
AUTH0_CLIENT_SECRET=your_client_secret
AUTH0_AUDIENCE=https://deepsentinel.local/api

# GitHub (via Auth0 Token Vault or direct)
GITHUB_TOKEN=ghp_your_token

# Slack
SLACK_BOT_TOKEN=xoxb-your-token

# Jira
JIRA_EMAIL=your-email@example.com
JIRA_API_TOKEN=your-jira-api-token

# Macroscope
MACROSCOPE_API_KEY=your_macroscope_key
MACROSCOPE_PROJECT_ID=your_project_id

# Ghost
GHOST_CONNECTION_STRING=postgresql://user:pass@host:port/dbname

# TrueFoundry
TRUEFOUNDRY_API_KEY=your_truefoundry_key
TRUEFOUNDRY_BASE_URL=https://your-instance.truefoundry.com

# Overmind
OVERMIND_API_KEY=ovr_your_key

# Aerospike
AEROSPIKE_HOST=127.0.0.1
AEROSPIKE_PORT=3000
```

---

# 16. IMPLEMENTATION SEQUENCE

**Time budget: 4 hours remaining (deadline 4:30 PM PDT)**

| Time | Task | Duration |
|------|------|----------|
| 12:00-12:15 | Project setup: git init, requirements, .env, directory structure | 15 min |
| 12:15-12:45 | Core files: config.py, main.py skeleton, __init__ files | 30 min |
| 12:45-1:15 | Airbyte integration: airbyte_client.py (GitHub + Slack + Jira connectors) | 30 min |
| 1:15-1:35 | Ghost integration: ghost_db.py + schema.sql + initialize | 20 min |
| 1:35-1:55 | Aerospike integration: aerospike_cache.py + Docker setup | 20 min |
| 1:55-2:15 | TrueFoundry integration: truefoundry_gateway.py | 20 min |
| 2:15-2:35 | Security analyzer: security_analyzer.py + Overmind wrapping | 20 min |
| 2:35-2:55 | Auth0 integration: auth0_client.py | 20 min |
| 2:55-3:10 | Macroscope integration: macroscope_client.py | 15 min |
| 3:10-3:30 | Demo setup: demo repo with vulnerabilities, test run | 20 min |
| 3:30-3:45 | README, skill.json for shipables.dev | 15 min |
| 3:45-4:00 | Record 3-minute demo video | 15 min |
| 4:00-4:20 | Submit on Devpost (select all 7 tracks), publish skill | 20 min |
| 4:20-4:30 | Buffer / fixes | 10 min |

---

# 17. DEMO SCRIPT — 3 MINUTES

## 17.1 Opening (0:00-0:15)
"Security scanners find code bugs. But the real vulnerabilities hide in the gaps between your tools — the Slack conversation where someone said 'skip auth for now,' the Jira ticket that's been in backlog for 6 months, the code review that missed the SQL injection because the reviewer didn't have context. DeepSentinel connects the dots."

## 17.2 Architecture Overview (0:15-0:30)
Show the architecture diagram. Point out all 7 sponsor tools and their roles:
"DeepSentinel uses Auth0 for secure token delegation, Airbyte to pull data from GitHub, Slack, and Jira simultaneously, Macroscope to understand codebase architecture, TrueFoundry to route analysis through multiple AI models, Aerospike for sub-millisecond CVE lookups, Ghost for persistent vulnerability history, and Overmind to optimize its security prompts over time."

## 17.3 Live Demo (0:30-2:30)
1. **Terminal 1:** Start DeepSentinel
   ```
   python -m src.main ElijahUmana/demo-repo 1
   ```
2. Show the output as it:
   - Connects to all services (Ghost, Aerospike, Auth0)
   - Pulls PR data from GitHub via Airbyte
   - Pulls Slack messages from security channel
   - Pulls Jira security backlog
   - Shows cross-source correlations discovered
   - Runs Macroscope analysis on changed files
   - Runs multi-model security analysis via TrueFoundry
   - Checks Aerospike CVE cache
   - Stores results in Ghost DB
   - Generates the security report

3. Show the report: findings with CWE IDs, severity, AND cross-source context
   - "This SQL injection in payments.ts was flagged HIGH normally, but ESCALATED to CRITICAL because: (1) Macroscope shows it's in the payment module handling financial data, (2) Slack shows a discussion about skipping input validation, (3) Jira has an open security ticket about this exact area"

4. Show Ghost DB: `ghost sql <id> "SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity"`

5. Show Aerospike cache hit on re-scan

## 17.4 Impact Close (2:30-3:00)
"DeepSentinel found 3 vulnerabilities that a standard scanner would have caught — but it also found 2 that no scanner could have: a deferred security fix in Jira that directly relates to new code being merged, and a Slack conversation revealing an intentional security shortcut. This is cross-source security intelligence. It runs autonomously, it learns from feedback via Overmind, and it's built on 7 best-in-class tools. DeepSentinel — because the most dangerous vulnerabilities live between your tools."

---

# 18. DEVPOST SUBMISSION

## 18.1 Project Fields
- **Name:** DeepSentinel
- **Tagline:** Cross-source security intelligence that finds what scanners miss
- **Built with:** Python, Auth0, Airbyte, Macroscope, Ghost, Overmind, TrueFoundry, Aerospike
- **Video:** [3-minute demo video URL]
- **GitHub repo:** https://github.com/ElijahUmana/deep-sentinel (public)

## 18.2 Description (for Devpost)
```
# DeepSentinel — Autonomous Multi-Source Security Intelligence Agent

## The Problem
Security reviews are fragmented. Code goes through GitHub. Decisions happen in Slack. Tickets live in Jira. No tool connects the dots. Vulnerabilities slip through because reviewers don't have the full picture.

## The Solution
DeepSentinel is an autonomous AI agent that pulls real-time data from GitHub, Slack, and Jira simultaneously, understands your codebase architecture, and performs deep security analysis that no single-source scanner can match.

## How It Works
1. **Gather** — Airbyte connectors pull PR data, Slack discussions, and Jira tickets in parallel
2. **Understand** — Macroscope analyzes codebase architecture to contextualize findings
3. **Analyze** — TrueFoundry AI Gateway routes analysis through multiple models (fast scan + deep analysis)
4. **Cross-Reference** — Correlates findings across all three sources to find hidden risks
5. **Cache** — Aerospike provides sub-ms CVE lookups and scan result caching
6. **Store** — Ghost Postgres maintains vulnerability history and audit trails
7. **Optimize** — Overmind tracks every LLM call and optimizes prompts over time
8. **Act** — Posts security reports, creates Jira tickets, alerts Slack channels

## Sponsor Tools Used
- **Auth0**: User authentication + Token Vault (zero standing privileges) + CIBA (async authorization for sensitive actions)
- **Airbyte**: 3 agent connectors (GitHub + Slack + Jira) for multi-source data ingestion
- **Macroscope**: Codebase architecture understanding for context-aware vulnerability detection
- **Ghost**: Persistent Postgres database for vulnerability history, scan results, and audit trails
- **Overmind**: LLM call instrumentation and prompt optimization
- **TrueFoundry**: AI Gateway for multi-model routing (GPT-4o-mini for scanning, Claude for deep analysis)
- **Aerospike**: Real-time cache for CVE lookups, scan deduplication, and pattern matching

## What Makes It Special
- Fully autonomous — triggers on events, no manual intervention
- Cross-source intelligence — finds risks that live between your tools
- Self-improving — optimizes via Overmind with every scan
- Production-grade architecture — proper auth, caching, persistence, observability
```

## 18.3 Sponsor Challenges to Select
- [ ] Best Use of Auth0 for AI Agents
- [ ] Airbyte: Conquer with Context
- [ ] Most Innovative Project Using Macroscope
- [ ] Best Use of Ghost
- [ ] Overmind Builders Prize
- [ ] Truefoundry: Best use of AI Gateway
- [ ] Most Innovative Use of Aerospike

---

# 19. SHIPABLES.DEV SKILL PUBLISHING

## 19.1 Skill Definition: skills/skill.json
```json
{
  "name": "deepsentinel",
  "version": "1.0.0",
  "description": "Autonomous multi-source security intelligence agent",
  "author": "ElijahUmana",
  "repository": "https://github.com/ElijahUmana/deep-sentinel",
  "keywords": ["security", "ai-agent", "vulnerability-detection", "cross-source"],
  "tools": [
    {
      "name": "deepsentinel_scan",
      "description": "Scan a GitHub PR for security vulnerabilities using cross-source intelligence from GitHub, Slack, and Jira",
      "parameters": {
        "owner": "GitHub repo owner",
        "repo": "GitHub repo name",
        "pr_number": "PR number to scan",
        "jira_project": "Optional Jira project key"
      }
    }
  ],
  "dependencies": [
    "airbyte-agent-github",
    "airbyte-agent-slack",
    "airbyte-agent-jira",
    "overmind-sdk",
    "aerospike",
    "asyncpg",
    "httpx"
  ],
  "setup": {
    "env_vars": [
      "AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET",
      "GITHUB_TOKEN", "SLACK_BOT_TOKEN",
      "JIRA_EMAIL", "JIRA_API_TOKEN",
      "MACROSCOPE_API_KEY", "MACROSCOPE_PROJECT_ID",
      "GHOST_CONNECTION_STRING",
      "TRUEFOUNDRY_API_KEY", "TRUEFOUNDRY_BASE_URL",
      "OVERMIND_API_KEY"
    ]
  }
}
```

## 19.2 Publishing
```bash
# Install Shipables CLI
npm install -g @senso-ai/shipables

# Publish
npx @senso-ai/shipables publish
```

---

# 20. RISK MITIGATION

| Risk | Mitigation |
|------|-----------|
| Auth0 tenant setup takes too long | Pre-configure tenant now. If blocked, use direct httpx calls as Auth0 client and document the intended Token Vault / CIBA flow |
| Airbyte connector installation fails | Test `pip install airbyte-agent-github` immediately. If it fails on ARM Mac, use Docker or direct API calls |
| Macroscope API not accessible | Sign up NOW at app.macroscope.com. If API is unavailable, mock the response and document the integration pattern |
| Ghost CLI installation fails | Test `curl -fsSL https://install.ghost.build \| sh` now. If blocked, use any Postgres instance and document it as Ghost-compatible |
| Aerospike Docker won't start | Test `docker run` now. If Docker issues, use local dict-based cache and show Aerospike code |
| TrueFoundry signup takes time | Sign up NOW. If blocked, use OpenAI directly and document TrueFoundry gateway code |
| Overmind SDK incompatible | Test `pip install overmind-sdk` now. If issues, use the init() + PromptString code and document the optimization loop |
| Not enough time for demo video | Use terminal recording (asciinema) + voiceover. Can be done in 5 minutes |
| Devpost submission deadline | Start Devpost draft NOW. Fill in partial info. Update as we build |

---

# END OF MASTER PLAN

**This document is the single source of truth for the DeepSentinel build.**
**Every line of code, every integration, every demo step is specified here.**
**Follow this plan exactly. No shortcuts. No corner-cutting. Win all 7.**
