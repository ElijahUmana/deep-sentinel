# Deep Agents Hackathon -- Research Synthesis

All sponsor tools, installation commands, SDK patterns, judge priorities, and gotchas extracted from agent research outputs.

---

## Table of Contents

1. [Auth0 for AI Agents](#1-auth0-for-ai-agents)
2. [Ghost (Agent-First Postgres)](#2-ghost-agent-first-postgres)
3. [Macroscope (Code Understanding)](#3-macroscope-code-understanding)
4. [Overmind (Agent Supervision) + OverClaw (Agent Optimizer)](#4-overmind-agent-supervision--overclaw-agent-optimizer)
5. [TrueFoundry (AI Gateway)](#5-truefoundry-ai-gateway)
6. [Aerospike (Real-Time Multi-Model DB)](#6-aerospike-real-time-multi-model-db)
7. [Shipables / Agent Skills](#7-shipables--agent-skills)
8. [Judging Criteria & Strategy](#8-judging-criteria--strategy)
9. [Winning Architecture Concept](#9-winning-architecture-concept)

---

## 1. Auth0 for AI Agents

**Prize: $1,750** | Judges look for: Multiple Auth0 features used architecturally (not decorative)

### 5 Core Capabilities

1. **User Authentication** -- Universal Login via OAuth 2.0 / OIDC
2. **Call Your APIs on User's Behalf** -- agent calls first-party APIs with Auth0 access tokens
3. **Token Vault** -- securely obtain/store/auto-refresh tokens for 40+ external services (Google, GitHub, Slack, etc.)
4. **CIBA (Async Authorization)** -- human-in-the-loop via push notifications for sensitive actions
5. **RAG Authorization via FGA** -- document-level access control using OpenFGA for retrieval pipelines

### Installation

```bash
# JavaScript/TypeScript
npm install @auth0/ai                    # Core SDK (base abstractions, CIBA, interrupts)
npm install @auth0/ai-langchain          # LangChain / LangGraph integration
npm install @auth0/ai-vercel             # Vercel AI SDK integration
npm install @auth0/ai-llamaindex         # LlamaIndex integration
npm install @auth0/ai-genkit             # Firebase Genkit integration
npm install @auth0/ai-redis              # Redis store with encryption
npm install @auth0/ai-components         # React UI components (TokenVault consent)
npm install @auth0/nextjs-auth0          # Next.js authentication

# Python
pip install auth0-ai                     # Core AI SDK
pip install auth0-ai-langchain           # LangChain / LangGraph
pip install auth0-ai-llamaindex          # LlamaIndex
pip install auth0-fastapi                # FastAPI user auth
pip install auth0-fastapi-api            # FastAPI API auth
```

### Environment Variables

```bash
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_CLIENT_ID=your_client_id
AUTH0_CLIENT_SECRET=your_client_secret
AUTH0_SECRET=long-random-string          # Cookie encryption
APP_BASE_URL=http://localhost:3000
AUDIENCE=https://your-api-audience       # For CIBA
FGA_STORE_ID=your_fga_store_id           # For FGA/RAG auth
FGA_CLIENT_ID=your_fga_client_id
FGA_CLIENT_SECRET=your_fga_client_secret
```

### Token Vault -- Python (LangChain)

```python
from auth0_ai_langchain.auth0_ai import Auth0AI
from auth0_ai_langchain.token_vault import get_credentials_from_token_vault
from langchain_core.tools import StructuredTool

auth0_ai = Auth0AI()  # Reads AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET from env

with_google_access = auth0_ai.with_token_vault(
    connection="google-oauth2",
    scopes=["openid", "https://www.googleapis.com/auth/calendar.freebusy"],
)

def check_calendar(date):
    credentials = get_credentials_from_token_vault()
    # Use credentials["access_token"] to call Google Calendar API

check_calendar_tool = with_google_access(
    StructuredTool(
        name="check_user_calendar",
        description="Check if user is available on a certain date",
        func=check_calendar,
    )
)
```

### Token Vault -- JavaScript (LangChain)

```javascript
import { Auth0AI } from "@auth0/ai-langchain";
import { getAccessTokenFromTokenVault } from "@auth0/ai-langchain";
import { tool } from "@langchain/core/tools";
import { z } from "zod";

const auth0AI = new Auth0AI({
  auth0: {
    domain: "YOUR_AUTH0_DOMAIN",
    clientId: "YOUR_AUTH0_CLIENT_ID",
    clientSecret: "YOUR_AUTH0_CLIENT_SECRET",
  },
});

const withGoogleAccess = auth0AI.withTokenVault({
  refreshToken: async (params, config) => config?.configurable?._credentials?.refreshToken,
  connection: "google-oauth2",
  scopes: ["openid", "https://www.googleapis.com/auth/calendar.freebusy"],
});

export const checkCalendarTool = withGoogleAccess(
  tool(
    async ({ date }) => {
      const accessToken = getAccessTokenFromTokenVault();
      const response = await fetch("https://www.googleapis.com/calendar/v3/freeBusy", {
        method: "POST",
        headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({ timeMin: date, timeMax: addDays(date, 1), timeZone: "UTC", items: [{ id: "primary" }] }),
      });
      return await response.json();
    },
    { name: "check_user_calendar", description: "Check availability", schema: z.object({ date: z.coerce.date() }) }
  )
);
```

### CIBA (Async Human-in-the-Loop) -- Python

```python
from auth0_ai_langchain.auth0_ai import Auth0AI
from auth0_ai_langchain.async_authorization import get_async_authorization_credentials
from langchain_core.runnables import ensure_config
from langchain_core.tools import StructuredTool

auth0_ai = Auth0AI()

with_async_authorization = auth0_ai.with_async_authorization(
    scopes=["stock:trade"],
    audience=os.getenv("AUDIENCE"),
    requested_expiry=os.getenv("REQUESTED_EXPIRY"),
    binding_message=lambda ticker, qty: f"Authorize the purchase of {qty} {ticker}",
    user_id=lambda *_, **__: ensure_config().get("configurable", {}).get("user_id"),
)

def trade_tool_function(ticker: str, qty: int) -> str:
    credentials = get_async_authorization_credentials()
    headers = {"Authorization": f"{credentials['token_type']} {credentials['access_token']}"}
    return f"Purchased {qty} of {ticker}"

trade_tool = with_async_authorization(
    StructuredTool(name="trade_tool", description="Trade a stock", func=trade_tool_function)
)
```

### FGA / RAG Authorization -- Python

```python
from auth0_ai_langchain import FGARetriever
from openfga_sdk.client.models import ClientCheckRequest

retriever = FGARetriever(
    base_retriever,
    build_query=lambda node: ClientCheckRequest(
        user=f"user:{user}",
        object=f"doc:{node.metadata['doc_id']}",
        relation="viewer",
    )
)
```

### CRITICAL: Interrupt Handling

Auth0 AI SDKs use interrupts -- they never block. When authorization is needed, the graph throws a `GraphInterrupt`.

```python
# REQUIRED: disable tool error handling for Auth0 interrupts to work
workflow = StateGraph(State).add_node(
    "tools",
    ToolNode([check_calendar_tool], handle_tool_errors=False)  # REQUIRED
)
```

### Gotchas

- `handleToolErrors: false` is REQUIRED in ToolNode for interrupts to propagate
- Token Vault uses OAuth 2.0 Token Exchange (RFC 8693) under the hood
- CIBA notification priority: Guardian push > email fallback
- If `requestedExpiry` > 5 minutes, push is disqualified -- email only
- Need to enable Token Vault grant type, custom API with offline_access, Multi-Resource Refresh Token policies in Auth0 Dashboard
- 40+ pre-built integrations: Gmail, GitHub, Slack, Google Calendar, Spotify, Salesforce, Microsoft, Dropbox, Box, PayPal, Stripe Connect, Discord, etc.

### What Won Before (LOCATR -- DeerHacks V 2026)

Used 3 Auth0 features: CIBA for booking approvals, Token Vault for Gmail API, Management API for user profiles. 4-person team, 46k lines. Auth0 was architecturally load-bearing, not bolted on.

---

## 2. Ghost (Agent-First Postgres)

**Prize: $1,998** | Built by TimescaleDB team

### Installation

```bash
# macOS / Linux / WSL
curl -fsSL https://install.ghost.build | sh

# Authenticate
ghost login          # GitHub OAuth
ghost login --headless  # CI/headless environments
```

### Core CLI Commands

```bash
ghost create                    # Create a new Postgres database
ghost list                      # List all databases
ghost connect <id>              # Get connection string
ghost psql <id>                 # Open interactive psql session
ghost sql <id> "SQL"            # Execute SQL query
ghost fork <id>                 # Fork database (schema + data)
ghost delete <id>               # Delete database
ghost pause <id>                # Pause running database
ghost resume <id>               # Resume paused database
ghost schema <id>               # Display schema (LLM-optimized format)
ghost logs <id>                 # View logs
ghost password <id> --generate  # Reset password
```

### MCP Integration

```bash
ghost mcp install      # Installs MCP server for Claude Code, Cursor, etc.
ghost mcp start stdio  # Start MCP server directly
ghost mcp list         # List available MCP tools
```

17 MCP tools available: ghost_login, ghost_status, ghost_list, ghost_create, ghost_delete, ghost_fork, ghost_pause, ghost_resume, ghost_connect, ghost_sql, ghost_schema, ghost_password, ghost_logs, ghost_rename, ghost_feedback, search_docs, view_skill

### Connection String Format

```
postgresql://ghost:<password>@<database-name>.ghost.build/postgres
```

### Python Usage

```python
import psycopg2
conn = psycopg2.connect("postgresql://ghost:<password>@<db-name>.ghost.build/postgres")
cur = conn.cursor()
cur.execute("SELECT * FROM my_table")
rows = cur.fetchall()
conn.close()

# Or async
import asyncpg
conn = await asyncpg.connect("postgresql://ghost:<password>@<db-name>.ghost.build/postgres")
rows = await conn.fetch("SELECT * FROM my_table")

# Or SQLAlchemy
from sqlalchemy import create_engine, text
engine = create_engine("postgresql://ghost:<password>@<db-name>.ghost.build/postgres")
with engine.connect() as conn:
    result = conn.execute(text("SELECT * FROM my_table"))
```

### Key Differentiators

- Unlimited databases/forks within compute/storage limits (forks are like git branches for databases)
- No web dashboard -- CLI and MCP only
- Free tier: 100 compute hours/month, 1TB storage
- Hard spending caps -- no surprise bills
- Built-in: pg_textsearch (BM25), pgvectorscale (vectors)
- Additional features: Memory Engine (temporal memory), TigerFS (postgres-backed filesystem), Ox (sandboxed execution)

### Agent Workflow Pattern

```bash
ghost create --name investigation-123    # Create workspace for agent
ghost connect investigation-123          # Get connection string
ghost fork investigation-123             # Fork before risky changes
ghost sql fork-456 "CREATE TABLE ..."    # Run migrations on fork
ghost delete investigation-123           # Discard if false positive
```

---

## 3. Macroscope (Code Understanding)

**Prize: $1,000** | Judges: Ikshita Puri (SWE), Zhuolun Li (AI Engineer)

### Setup

1. Install GitHub App at app.macroscope.com -- connects to repos
2. Activate subscription (Stripe)
3. Add Product Overview in Settings > Workspace
4. Connect Slack (requires Slack admin)

### Webhook API (Primary Integration Path)

```
POST https://macrohook.macroscope.com/api/v1/workspaces/{workspaceType}/{workspaceId}/query-agent-webhook-trigger
```

**Headers:**
```
Content-Type: application/json
X-Webhook-Secret: your-api-key
```

**Request body:**
```json
{
  "query": "What shipped this week?",
  "responseDestination": {
    "slackChannelId": "C0123456789"
  },
  "timezone": "America/Los_Angeles"
}
```

**Response:** 202 Accepted with `{"workflowId": "abc-123-def-456"}`, then async delivery.

`responseDestination` options: `slackChannelId` (posts to Slack), `webhookUrl` (POST to external HTTPS endpoint, must be allowlisted), `slackThreadTs` (reply in thread).

### Other Integration Methods

- **GitHub mentions:** `@macroscope-app` in PR comments or review threads
- **Slack mentions:** `@Macroscope` in channels
- **Custom Rules:** `macroscope.md` files in repo root or specific folders for team coding standards

### Core Features

- **Code Review:** Automatic AST-based bug detection on PRs. Languages: Go, Python, TypeScript, Vue.js, Java, Rust, Kotlin, Swift, Ruby, Elixir
- **Fix It For Me:** Creates branch, applies fix via AI agent, opens PR. Auto-fixes CI failures
- **Approvability:** Auto-approves low-risk PRs (docs, tests, feature-flagged code)
- **AI Agent tools:** Code search, git history analysis, GitHub API (PRs/issues/deployments), Jira, Linear, BigQuery, PostHog, GCP Cloud Logging, LaunchDarkly, web search
- **Macros:** Saved prompts running on schedule (daily/weekly) posting to Slack
- **Commit Summaries:** Chronological feed with semantic search

### What Would Impress Judges

- Deep codebase awareness beyond surface-level file reading
- Automated workflows using Macros + webhook API + Fix It For Me
- Cross-tool intelligence connecting code, analytics, and project management
- Zhuolun Li (AI Engineer) values sophisticated agent architecture with multi-step reasoning
- Ikshita Puri (SWE) values practical developer workflow improvements

### Gotchas

- $30/active developer/month. Commits: $0.05/commit. Reviews: $0.35/review
- API key generated once in Settings > Connections > Webhooks -- cannot be retrieved after
- Webhook URLs must be HTTPS and allowlisted in Settings > Connections > Webhooks > Allowed External URLs
- `.macroscope-ignore` file in repo root for exclusions (glob patterns, max 1,000)

---

## 4. Overmind (Agent Supervision) + OverClaw (Agent Optimizer)

**Prize: $651** | Judge: Tyler Edwards (ex-MI5, security-minded)

### Overmind -- Installation & Setup

```bash
# Self-hosted (Docker)
cp .env.example .env
# Edit .env: add OPENAI_API_KEY, ANTHROPIC_API_KEY, or GEMINI_API_KEY
make run
# Auto-provisions: DB migrations, default admin (admin/admin), default project + API token
# Opens at localhost:5173
```

### Overmind Python SDK

```bash
pip install overmind-sdk
```

```python
import os
import overmind_sdk
from openai import OpenAI
from opentelemetry.overmind.prompt import PromptString

os.environ["OVERMIND_API_KEY"] = "ovr_..."
os.environ["OPENAI_API_KEY"] = "sk-proj-..."

overmind_sdk.init(service_name="my-service", environment="production")

system_prompt = PromptString(
    id="hello_agent",
    template="You are a friendly assistant. Your name is {name}",
    kwargs={"name": "Alfred"},
)

client = OpenAI()
response = client.chat.completions.create(
    model="gpt-4-mini",
    messages=[
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": "Say hi!"},
    ],
)
```

### Overmind JavaScript/TypeScript SDK

```bash
npm install @overmind-lab/trace-sdk openai
```

```typescript
import { OpenAI } from "openai";
import { OvermindClient } from "@overmind-lab/trace-sdk";

const overmindClient = new OvermindClient({
    apiKey: process.env.OVERMIND_API_KEY!,
    appName: "my app",
});

overmindClient.initTracing({
    enableBatching: false,
    enabledProviders: { openai: OpenAI },
});

// All OpenAI calls are auto-traced from here
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const response = await openai.chat.completions.create({
    model: "gpt-4-mini",
    messages: [{ role: "user", content: "Hello!" }],
});
```

### Overmind OpenTelemetry (Any Language)

```python
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

exporter = OTLPSpanExporter(
    endpoint="http://localhost:8000/api/v1/traces/otlp",
    headers={"Authorization": "Bearer <your-api-token>"},
)
```

### Overmind Core Capabilities

1. **Execution Tracing** -- every LLM call recorded with full I/O, timing, tokens, cost
2. **LLM Judge Scoring** -- evaluates traces on quality, cost, latency
3. **Continuous Improvement** -- replays traces through alternative models/prompts
4. **Key results:** up to 66% cost reduction, 25% performance improvement

### Overmind Gotchas

- Only one PromptString per LLM call -- multiple instances trigger an error
- Provider support via `overmind_sdk.init(service_name="...", providers=["anthropic"])` or `providers=["google"]`
- Self-hosted only (Docker + Docker Compose required)

### OverClaw -- Agent Optimizer CLI

```bash
uv tool install overclaw
overclaw --help

# Workflow
overclaw init                                    # Configure API keys, models
overclaw agent register lead-qualification agents.my_agent:run  # Register agent
overclaw setup lead-qualification                # Analyze agent, generate policies, test data
overclaw optimize lead-qualification             # Run optimization loop
```

### OverClaw Agent Function Pattern

```python
from overclaw.core.tracer import call_llm, call_tool

def run(input: dict) -> dict:
    response = call_llm(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": "You are a lead qualification agent..."},
            {"role": "user", "content": str(input)}
        ]
    )
    return {"category": "hot", "lead_score": 85, "reasoning": "..."}
```

### OverClaw Optimization Loop (7 Steps)

1. **Run** -- agent executes against all test cases with full traces
2. **Score** -- structural correctness, value accuracy, tool usage, LLM-as-Judge
3. **Diagnose** -- analyzer reviews traces + scores to find root causes
4. **Generate candidates** -- multiple fix candidates targeting different areas
5. **Validate** -- syntax check, smoke test on random subsets
6. **Evaluate** -- survivors scored on full dataset
7. **Accept/revert** -- only if beats global best, doesn't regress individual cases

### OverClaw Output Artifacts

```
.overclaw/agents/<name>/
  setup_spec/policies.md       # Human-editable policy doc
  setup_spec/eval_spec.json    # Machine-readable eval criteria
  setup_spec/dataset.json      # Test dataset
  experiments/best_agent.py    # Highest-scoring agent version
  experiments/results.tsv      # Score history
  experiments/traces/          # Detailed JSON traces
  experiments/report.md        # Summary with diffs
```

### OverClaw Safeguards

- Train/holdout split prevents overfitting
- Regression-aware acceptance: rejects candidates that tank individual cases
- Complexity penalty: quadratic penalty for excessive prompt/code growth
- Label leakage prevention: redacts expected outputs
- Temperature annealing: 0.8 (exploratory) -> 0.4 (focused), bump back on stall

---

## 5. TrueFoundry (AI Gateway)

**Prize: $600** | Judge: Sai Krishna (production deployment, observability, cost control)

### What It Is

Unified endpoint for 1000+ LLMs with rate limiting, cost control, observability, failover. OpenAI-compatible API -- route all LLM calls through it with zero code changes.

### Key Capabilities

- **Model routing:** Route to different models based on task (cheap for triage, expensive for analysis)
- **Cost tracking:** Per-request cost attribution
- **Failover:** Automatic model provider fallback
- **Rate limiting:** Prevent runaway agent loops
- **Observability:** Full request/response logging with latency/token/cost metrics
- **OpenAI-compatible:** Drop-in replacement for OpenAI client endpoint

### Integration Pattern

Point your OpenAI/Anthropic client's `base_url` to the TrueFoundry gateway endpoint. All calls are automatically logged, cost-tracked, and get failover for free.

```python
from openai import OpenAI

client = OpenAI(
    base_url="https://your-truefoundry-gateway-url/v1",
    api_key="your-truefoundry-api-key"
)

# Use normally -- all calls routed through gateway
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Hello"}]
)
```

### What Would Impress Judges

- Different models for different agent tasks (fast/cheap for triage, powerful for deep analysis)
- Cost dashboard showing per-investigation spend
- Automatic failover demonstrated during demo
- Production-grade observability across all LLM calls

### Gotchas

- TrueFoundry docs are a JS-rendered Mintlify site -- hard to scrape, better to use their dashboard directly
- Sign up at truefoundry.com/register for API access
- The gateway is OpenAI-compatible, so the integration is just changing the base_url

---

## 6. Aerospike (Real-Time Multi-Model DB)

**Prize: $650** | Judge: Lucas Beeler (values architectures that genuinely need high-performance data)

### Installation

```bash
# Docker (Community Edition)
docker run -d --name aerospike -p 3000-3002:3000-3002 aerospike

# Python client
pip install aerospike

# Vector Search client
pip install aerospike-vector-search
```

### Data Model

Schemaless hierarchy: **Namespace** (tablespace) > **Set** (table) > **Record** (row) > **Bin** (column)

### Python Client -- Basic CRUD

```python
import aerospike

config = {'hosts': [('127.0.0.1', 3000)]}
client = aerospike.client(config).connect()

# Write
key = ('test', 'demo', 'user1')  # (namespace, set, primary_key)
bins = {'name': 'Alice', 'score': 95, 'tags': ['security', 'agent']}
client.put(key, bins)

# Read
(key, metadata, record) = client.get(key)

# Delete
client.remove(key)

# Scan (full set)
scan = client.scan('test', 'demo')
records = scan.results()

# Query with secondary index
client.index_integer_create('test', 'demo', 'score', 'score_idx')
query = client.query('test', 'demo')
query.where(aerospike.predicates.between('score', 80, 100))
results = query.results()

client.close()
```

### Vector Search (AVS)

```bash
pip install aerospike-vector-search
```

```python
from aerospike_vector_search import Client as AVSClient

avs_client = AVSClient(seeds=[("127.0.0.1", 5000)])

# Create index
avs_client.index_create(
    namespace="test",
    name="embedding_idx",
    vector_field="embedding",
    dimensions=1536,
    distance_metric="COSINE"
)

# Upsert with vector
avs_client.upsert(
    namespace="test",
    set_name="vectors",
    key="doc1",
    record_data={"embedding": [0.1, 0.2, ...], "text": "document content"}
)

# Search
results = avs_client.vector_search(
    namespace="test",
    index_name="embedding_idx",
    query=[0.1, 0.2, ...],
    limit=10
)
```

### LangChain Integration

```python
from langchain_community.vectorstores import Aerospike

vectorstore = Aerospike(
    client=client,
    embedding=embeddings,
    namespace="test",
    set_name="vectors",
    index_name="embedding_idx",
    vector_key="embedding",
    text_key="text"
)

# Use as retriever
retriever = vectorstore.as_retriever(search_kwargs={"k": 5})
```

### Key Differentiators

- Multi-model: key-value + document + graph + vector in one database
- Sub-millisecond lookups at scale
- Agents can store intermediate results as micro-datasets
- Use cases: session state, vector search for RAG, caching, agent working memory

### AQL (Interactive Query)

```bash
docker run -ti aerospike/aerospike-tools:latest aql -h <host>
```

### Gotchas

- Namespace configuration (including default-ttl, max-ttl) is set at the server level, not per-record
- TTL of -1 means never expire
- The Python client uses tuple keys: (namespace, set, primary_key)
- Vector Search is a separate service (AVS) with its own client library
- Docker ports: 3000 (client), 3001 (fabric/mesh), 3002 (info)

---

## 7. Shipables / Agent Skills

### What It Is

Shipables.dev is "The npm for Agent Skills" -- a registry for discovering, installing, and publishing skills. Implements the Agent Skills open standard from agentskills.io (originated by Anthropic, adopted by 30+ platforms).

### Installing a Skill

```bash
npx @senso-ai/shipables install [skill-name]
```

### Skill Directory Structure

```
skill-name/
  SKILL.md          # Required: YAML frontmatter + markdown instructions
  scripts/          # Optional: executable code
  references/       # Optional: documentation
  assets/           # Optional: templates, resources
```

### SKILL.md Format

```markdown
---
name: my-skill-name
description: What this skill does and when to use it. Max 1024 chars.
license: Apache-2.0
compatibility: Requires Python 3.10+ and docker
metadata:
  author: team-name
  version: "1.0"
allowed-tools: Bash(git:*) Read
---

## Instructions

Step-by-step instructions for the agent...

## Examples

Input/output examples...
```

### Naming Rules

- `name`: 1-64 chars, lowercase alphanumeric + hyphens only
- No starting/ending/consecutive hyphens
- Must match parent directory name

### Progressive Disclosure

1. **Metadata** (~100 tokens): `name` + `description` loaded at startup
2. **Instructions** (< 5000 tokens recommended): Full `SKILL.md` loaded on activation
3. **Resources** (as needed): `scripts/`, `references/`, `assets/` loaded on demand

### Validation

```bash
skills-ref validate ./my-skill
```

### Compatible Agents

Claude Code, Cursor, Codex CLI, GitHub Copilot, Gemini CLI, VS Code, Roo Code, OpenHands, Goose, Letta, Spring AI, Databricks, Kiro, 30+ more.

### The Expectation

The hackathon likely expects you to package your project (or a component) as a publishable Agent Skill on Shipables.

---

## 8. Judging Criteria & Strategy

### Scoring Breakdown

| Criterion | Weight | What It Means |
|-----------|--------|---------------|
| Autonomy | 20% | Agent acts on real-time data without manual intervention. Multi-step planning, tool selection, error recovery. |
| Idea | 20% | Meaningful problem judges personally recognize as painful. Not a toy. |
| Technical Implementation | 20% | Clean architecture, error handling, no demo-ware. Code quality. |
| Tool Use | 20% | At least 3 sponsor tools used effectively and architecturally necessary. |
| Presentation | 20% | 3-minute demo. Story: problem, solution, live demo, results. |

### Judge Priorities

- **AWS (Jon Turdiev, Rakesh Kumar):** Enterprise architecture, scalability, cloud patterns
- **Bland AI (Spencer Small):** Voice AI, real-time voice interactions
- **Airbyte (Pedro Lopez, Patrick Nilan):** Multi-source data integration, "conquer with context"
- **TrueFoundry (Sai Krishna):** Production deployment, observability, cost control
- **Overmind (Tyler Edwards):** Agent supervision, learning loops, anomaly detection. Ex-MI5 -- security-minded
- **Macroscope (Ikshita Puri, Zhuolun Li):** Creative use beyond basic PR summaries. Zhuolun = AI Engineer (agent architecture), Ikshita = SWE (developer workflows)
- **Aerospike (Lucas Beeler):** Architectures that genuinely need high-performance real-time data
- **Letta (Devansh Jain):** Stateful agent memory that persists and evolves across sessions
- **LinkedIn (Sahil Sachdeva):** Professional/enterprise applications
- **Alacriti (Divyarani Raghupatruni):** FinTech, compliance, payments

### Past Winner Patterns

1. **Domain-specific real-world problems** beat generic demos (every winner)
2. **Multi-agent orchestration** is table stakes (parallel sub-agents + coordinator)
3. **Data grounding is mandatory** -- winners always ground LLM reasoning in structured data
4. **Polished frontend matters** -- judges need to SEE the agent working (React/Next.js dashboard)
5. **Production readiness signals** -- latency optimization, error handling, auth, logging

### LOCATR (Auth0 Prize Winner)

4 people, 46k LOC, used 3 Auth0 features (CIBA + Token Vault + Management API). Auth0 was architecturally load-bearing. Sub-3-second response via asyncio parallel execution. 52-dimensional aesthetic classifier.

---

## 9. Winning Architecture Concept

### Autonomous Security Posture Agent for Engineering Orgs

An autonomous agent that continuously monitors an engineering organization's security posture across code, infrastructure, data flows, and identity -- then investigates, triages, and remediates. Relevant to RSAC 2026 venue.

### How Each Tool Fits (Architecturally Essential)

| Tool | Role | Why It Cannot Be Removed |
|------|------|--------------------------|
| **Auth0** | Token Vault accesses GitHub/Jira/Slack on behalf of users. CIBA for human approval of high-risk remediation (revoking tokens, rotating creds). | Agent's ability to act across services depends on Auth0's identity layer |
| **Airbyte** | Pulls real-time data from GitHub (secrets alerts), Jira (tickets), Slack (incidents), cloud APIs (IAM configs) | Cross-source correlation is the core value prop |
| **Macroscope** | Traces vulnerability blast radius through dependency graph, identifies all callers of vulnerable functions | Deep code understanding vs. shallow regex scanning |
| **Ghost** | Each investigation gets ephemeral Postgres DB -- findings, evidence chain, intermediate reasoning. Memory Engine tracks posture over time | Agent workspace and investigation records |
| **Overmind** | Traces all agent actions. Detects triage drift. Learning loop improves security judgment from team's actual decisions | Agent supervision and continuous improvement |
| **TrueFoundry** | Routes LLM calls -- cheap models for triage, powerful for deep analysis. Failover, cost tracking, rate limiting | Production-grade LLM orchestration |
| **Aerospike** | Session state (sub-ms reads), vector embeddings of past vulnerabilities, cached CVE data, real-time dashboard scores | High-performance operational layer |

### Architecture Diagram

```
                    TrueFoundry AI Gateway
                    (LLM routing, cost, failover)
                           |
                    Overmind Supervision
                    (tracing, anomaly detection, optimization)
                           |
         +--------+--------+--------+
         |                 |                 |
    Scanner Agent    Analyzer Agent    Triager Agent
         |                 |                 |
    Airbyte            Macroscope        Aerospike
    (GitHub, Jira,     (code graph,      (session state,
     Slack, Cloud)     blast radius)     vector search,
         |                 |             CVE cache)
         +--------+--------+                 |
                  |                          |
             Ghost Postgres              Remediator
             (investigation DB,          Agent
              memory, files)                 |
                                        Auth0
                                        (Token Vault for
                                         API access, CIBA
                                         for human approval)
```

### 3-Minute Demo Script

- **0:00-0:20** -- "Engineering teams drown in security alerts across 10+ tools. Our agent watches everything, investigates autonomously, and only bothers you when it matters."
- **0:20-1:00** -- Live: test secret committed to GitHub. Airbyte detects it. Ghost investigation DB spins up. Agent begins correlating.
- **1:00-1:40** -- Macroscope traces where the leaked key is used (3 call sites in production). Aerospike vector search finds 2 similar past incidents. Overmind dashboard traces every decision.
- **1:40-2:20** -- Agent creates Jira ticket, posts to security Slack, requests credential rotation via Auth0 CIBA push. TrueFoundry shows $0.12 total LLM cost.
- **2:20-2:50** -- Team lead approves on phone. Agent rotates credential, verifies fix. Overmind records positive training signal.
- **2:50-3:00** -- "Published as an Agent Skill on Shipables. Any team can install this in one command."
