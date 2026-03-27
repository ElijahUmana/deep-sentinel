"""
Ghost (Postgres) integration for DeepSentinel.
Persistent storage for vulnerability findings, scan history,
audit trails, and cross-source correlations.
"""
import json
import os
import subprocess
from datetime import datetime


class GhostDB:
    """Ghost Postgres database for persistent agent storage."""

    SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    repo_owner TEXT NOT NULL,
    repo_name TEXT NOT NULL,
    pr_number INTEGER,
    trigger_type TEXT NOT NULL DEFAULT 'manual',
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    findings_count INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    status TEXT DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    scan_id TEXT NOT NULL,
    pr_number INTEGER,
    repo_owner TEXT NOT NULL,
    repo_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_number INTEGER,
    severity TEXT NOT NULL,
    cwe_id TEXT,
    title TEXT NOT NULL,
    description TEXT,
    fix_suggestion TEXT,
    slack_context TEXT,
    macroscope_context TEXT,
    status TEXT DEFAULT 'open',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS correlations (
    id SERIAL PRIMARY KEY,
    scan_id TEXT,
    correlation_type TEXT NOT NULL,
    github_ref TEXT,
    slack_ref TEXT,
    description TEXT NOT NULL,
    risk_score FLOAT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    action TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'agent',
    resource_type TEXT,
    resource_id TEXT,
    details TEXT
);
"""

    def __init__(self, connection_string: str = None, ghost_db_id: str = None):
        self.connection_string = connection_string or os.environ.get("GHOST_CONNECTION_STRING", "")
        self.ghost_db_id = ghost_db_id or os.environ.get("GHOST_DB_ID", "")
        self.pool = None
        self.connected = False

    async def connect(self):
        """Connect to Ghost Postgres database."""
        if not self.connection_string:
            print("[Ghost] No connection string, running in dry-run mode")
            return

        try:
            import asyncpg
            self.pool = await asyncpg.create_pool(self.connection_string, min_size=1, max_size=5)
            self.connected = True
            print("[Ghost] Connected to database")

            # Initialize schema
            async with self.pool.acquire() as conn:
                await conn.execute(self.SCHEMA)
            print("[Ghost] Schema initialized")
        except Exception as e:
            print(f"[Ghost] Connection failed: {e}")
            self.connected = False

    async def start_scan(self, scan_id: str, repo_owner: str, repo_name: str,
                         pr_number: int = None, trigger_type: str = "manual"):
        """Record a scan start."""
        if not self.connected:
            print(f"[Ghost] Scan started: {scan_id} ({repo_owner}/{repo_name} PR#{pr_number})")
            return

        async with self.pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO scans (id, repo_owner, repo_name, pr_number, trigger_type) VALUES ($1,$2,$3,$4,$5)",
                scan_id, repo_owner, repo_name, pr_number, trigger_type,
            )

    async def complete_scan(self, scan_id: str, findings_count: int, critical_count: int, high_count: int):
        """Mark a scan as completed."""
        if not self.connected:
            return

        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE scans SET status='completed', completed_at=NOW(), findings_count=$2, critical_count=$3, high_count=$4 WHERE id=$1",
                scan_id, findings_count, critical_count, high_count,
            )

    async def record_vulnerability(self, vuln: dict):
        """Store a vulnerability finding."""
        if not self.connected:
            print(f"[Ghost] Finding: [{vuln.get('severity')}] {vuln.get('title', 'Unknown')} in {vuln.get('file_path', '?')}")
            return

        async with self.pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO vulnerabilities
                   (scan_id, pr_number, repo_owner, repo_name, file_path, line_number,
                    severity, cwe_id, title, description, fix_suggestion, slack_context, macroscope_context)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)""",
                vuln.get("scan_id"), vuln.get("pr_number"), vuln.get("repo_owner", ""),
                vuln.get("repo_name", ""), vuln.get("file_path", ""), vuln.get("line_number"),
                vuln.get("severity", "MEDIUM"), vuln.get("cwe_id"), vuln.get("title", ""),
                vuln.get("description"), vuln.get("fix_suggestion"),
                json.dumps(vuln.get("slack_context")) if vuln.get("slack_context") else None,
                json.dumps(vuln.get("macroscope_context")) if vuln.get("macroscope_context") else None,
            )

    async def record_correlation(self, scan_id: str, correlation: dict):
        """Store a cross-source correlation."""
        if not self.connected:
            return

        # Ensure all values are strings (some correlations have list fields)
        def to_str(val):
            if val is None:
                return ""
            if isinstance(val, (list, dict)):
                return json.dumps(val)
            return str(val)

        try:
            async with self.pool.acquire() as conn:
                await conn.execute(
                    "INSERT INTO correlations (scan_id, correlation_type, github_ref, slack_ref, description, risk_score) VALUES ($1,$2,$3,$4,$5,$6)",
                    scan_id,
                    to_str(correlation.get("type", "")),
                    to_str(correlation.get("github_ref", correlation.get("context_ref", ""))),
                    to_str(correlation.get("slack_ref", "")),
                    to_str(correlation.get("risk_note", "")),
                    correlation.get("risk_score") if isinstance(correlation.get("risk_score"), (int, float)) else None,
                )
        except Exception as e:
            pass  # Don't crash on correlation storage errors

    async def log_audit(self, action: str, resource_type: str = None,
                        resource_id: str = None, details: dict = None):
        """Write to audit trail."""
        if not self.connected:
            return

        async with self.pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO audit_log (action, resource_type, resource_id, details) VALUES ($1,$2,$3,$4)",
                action, resource_type, resource_id,
                json.dumps(details) if details else None,
            )

    async def get_historical_patterns(self, repo_owner: str, repo_name: str) -> list:
        """Get vulnerability history for a repo."""
        if not self.connected:
            return []

        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT cwe_id, severity, COUNT(*) as count, MAX(created_at) as last_seen
                   FROM vulnerabilities
                   WHERE repo_owner = $1 AND repo_name = $2
                   GROUP BY cwe_id, severity ORDER BY count DESC LIMIT 20""",
                repo_owner, repo_name,
            )
            return [dict(r) for r in rows]

    async def get_scan_stats(self) -> dict:
        """Get overall scan statistics."""
        if not self.connected:
            return {"total_scans": 0, "total_findings": 0}

        async with self.pool.acquire() as conn:
            scans = await conn.fetchval("SELECT COUNT(*) FROM scans")
            findings = await conn.fetchval("SELECT COUNT(*) FROM vulnerabilities")
            critical = await conn.fetchval("SELECT COUNT(*) FROM vulnerabilities WHERE severity='CRITICAL'")
            return {"total_scans": scans, "total_findings": findings, "critical_findings": critical}

    async def get_trend_analysis(self, repo_owner: str, repo_name: str) -> dict:
        """Analyze vulnerability trends across scans to detect worsening patterns.

        This is Ghost's unique value for agentic security: the agent maintains
        persistent memory across scans. It can detect:
        - Recurring CWEs that the team keeps introducing
        - Severity trends (is the codebase getting more or less secure?)
        - Time-to-fix for known vulnerabilities
        """
        if not self.connected:
            return {"trends": [], "note": "Ghost not connected -- no historical data"}

        async with self.pool.acquire() as conn:
            # CWE recurrence: which vulnerabilities keep coming back?
            recurring = await conn.fetch(
                """SELECT cwe_id, COUNT(DISTINCT scan_id) as scan_appearances,
                          COUNT(*) as total_occurrences,
                          ARRAY_AGG(DISTINCT UPPER(severity)) as severities,
                          MIN(created_at) as first_seen,
                          MAX(created_at) as last_seen
                   FROM vulnerabilities
                   WHERE repo_owner = $1 AND repo_name = $2
                   GROUP BY cwe_id
                   HAVING COUNT(DISTINCT scan_id) > 1
                   ORDER BY scan_appearances DESC LIMIT 10""",
                repo_owner, repo_name,
            )

            # Severity trend per scan
            severity_trend = await conn.fetch(
                """SELECT s.id as scan_id, s.started_at::date as scan_date,
                          s.findings_count, s.critical_count, s.high_count
                   FROM scans s
                   WHERE s.repo_owner = $1 AND s.repo_name = $2
                   AND s.status = 'completed'
                   ORDER BY s.started_at DESC LIMIT 10""",
                repo_owner, repo_name,
            )

            # Open vs fixed ratio
            open_count = await conn.fetchval(
                "SELECT COUNT(*) FROM vulnerabilities WHERE repo_owner=$1 AND repo_name=$2 AND status='open'",
                repo_owner, repo_name,
            )
            total_count = await conn.fetchval(
                "SELECT COUNT(*) FROM vulnerabilities WHERE repo_owner=$1 AND repo_name=$2",
                repo_owner, repo_name,
            )

            return {
                "recurring_cwes": [dict(r) for r in recurring],
                "severity_trend": [dict(r) for r in severity_trend],
                "open_vulnerabilities": open_count,
                "total_vulnerabilities": total_count,
                "fix_rate": round((1 - open_count / total_count) * 100, 1) if total_count > 0 else 0,
                "note": "Trend analysis from Ghost persistent history",
            }

    async def compute_risk_score(self, repo_owner: str, repo_name: str,
                                  cross_source_correlations: int = 0) -> dict:
        """Compute a composite risk score that factors in historical patterns.

        This goes beyond single-scan scoring: it considers how many times
        the team has been warned about the same CWEs, whether fixes are
        happening, and how much cross-source context indicates unaddressed risk.
        """
        if not self.connected:
            return {"risk_score": 0, "note": "Ghost not connected"}

        async with self.pool.acquire() as conn:
            # Base score from current findings
            current = await conn.fetch(
                """SELECT UPPER(severity) as severity, COUNT(*) as cnt
                   FROM vulnerabilities
                   WHERE repo_owner=$1 AND repo_name=$2 AND status='open'
                   GROUP BY UPPER(severity)""",
                repo_owner, repo_name,
            )
            severity_weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}
            base_score = sum(
                severity_weights.get(r["severity"], 0) * r["cnt"]
                for r in current
            )

            # Recurrence multiplier: repeated CWEs are worse
            repeat_count = await conn.fetchval(
                """SELECT COUNT(*) FROM (
                       SELECT cwe_id FROM vulnerabilities
                       WHERE repo_owner=$1 AND repo_name=$2
                       GROUP BY cwe_id HAVING COUNT(DISTINCT scan_id) > 1
                   ) repeats""",
                repo_owner, repo_name,
            )
            recurrence_factor = 1.0 + (repeat_count * 0.15)

            # Cross-source factor: correlations with team discussions = confirmed risk
            cross_source_factor = 1.0 + (cross_source_correlations * 0.1)

            composite = round(base_score * recurrence_factor * cross_source_factor, 1)
            max_score = 100
            normalized = min(composite, max_score)

            return {
                "risk_score": normalized,
                "base_score": base_score,
                "recurrence_multiplier": round(recurrence_factor, 2),
                "cross_source_multiplier": round(cross_source_factor, 2),
                "repeated_cwes": repeat_count,
                "interpretation": (
                    "CRITICAL" if normalized >= 50 else
                    "HIGH" if normalized >= 25 else
                    "MEDIUM" if normalized >= 10 else
                    "LOW"
                ),
            }

    async def close(self):
        """Close database connection."""
        if self.pool:
            await self.pool.close()
            print("[Ghost] Connection closed")

    @staticmethod
    def ghost_cli(command: str) -> str:
        """Execute a Ghost CLI command."""
        try:
            result = subprocess.run(
                ["ghost"] + command.split(), capture_output=True, text=True, timeout=30
            )
            return result.stdout.strip() or result.stderr.strip()
        except FileNotFoundError:
            return "Ghost CLI not found"
        except subprocess.TimeoutExpired:
            return "Ghost command timed out"

    @staticmethod
    def fork_database(db_id: str, name: str) -> dict:
        """
        Fork the database for safe experimentation.
        Ghost's key feature: clone schema + data with one command.
        """
        result = subprocess.run(
            ["ghost", "fork", db_id, "--name", name],
            capture_output=True, text=True, timeout=60
        )
        output = result.stdout.strip()
        # Parse the connection string from output
        conn_match = None
        for line in output.split("\n"):
            if "postgresql://" in line:
                conn_match = line.split("Connection: ")[-1].strip() if "Connection:" in line else line.strip()
        return {"output": output, "connection": conn_match}

    @staticmethod
    def query_database(db_id: str, sql: str) -> str:
        """Execute SQL directly via Ghost CLI."""
        result = subprocess.run(
            ["ghost", "sql", db_id, sql],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout.strip()

    @staticmethod
    def get_schema(db_id: str) -> str:
        """Get database schema via Ghost CLI.

        Ghost returns the schema in a format optimized for LLM consumption --
        the agent uses this to understand what tables exist, what columns are
        available, and how to construct queries WITHOUT hardcoding SQL.
        This is a key Ghost differentiator: the schema IS the agent's context.
        """
        result = subprocess.run(
            ["ghost", "schema", db_id],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout.strip()

    @staticmethod
    def agent_introspect(db_id: str) -> dict:
        """Agent reads its own schema to decide what to query.

        This demonstrates Ghost's unique value for agentic applications:
        instead of hardcoding SQL, the agent reads the schema, understands
        the structure, and dynamically builds queries. This is impossible
        with vanilla Postgres -- Ghost's LLM-optimized schema format is
        designed for this exact pattern.
        """
        schema = GhostDB.get_schema(db_id)
        if not schema:
            return {"tables": [], "note": "Schema not available"}

        # Parse schema to understand available tables and columns
        # Ghost's schema format:
        #   TABLE: vulnerabilities
        #   id             SERIAL PRIMARY KEY
        #   severity       TEXT NOT NULL
        #   cwe_id         TEXT
        # Also handles: "Table:" prefix, CREATE TABLE, and pipe-delimited formats
        tables = []
        current_table = None
        for line in schema.split("\n"):
            stripped = line.strip()
            if not stripped:
                continue

            # Detect table header lines (case-insensitive)
            stripped_upper = stripped.upper()
            if stripped_upper.startswith("TABLE:") or stripped_upper.startswith("CREATE TABLE"):
                # Extract table name: "TABLE: vulnerabilities" -> "vulnerabilities"
                table_name = stripped.split(":")[-1].strip() if ":" in stripped else stripped.split()[-1]
                table_name = table_name.strip("(").strip('"').strip("'").strip()
                if table_name and table_name.upper() not in ("TABLE", "CREATE"):
                    current_table = {"name": table_name, "columns": []}
                    tables.append(current_table)
            elif current_table and not stripped_upper.startswith(("DATABASE:", "VIEW:", "INDEX ")):
                # Column definition line — either pipe-delimited or space-delimited
                if "|" in stripped:
                    parts = [p.strip() for p in stripped.split("|")]
                    if len(parts) >= 2:
                        current_table["columns"].append({
                            "name": parts[0],
                            "type": parts[1] if len(parts) > 1 else "unknown",
                        })
                else:
                    # Space-delimited: "severity  TEXT NOT NULL"
                    parts = stripped.split()
                    if len(parts) >= 2 and not parts[0].startswith(("--", "#", "//")):
                        current_table["columns"].append({
                            "name": parts[0],
                            "type": " ".join(parts[1:]),
                        })
            elif stripped_upper.startswith("VIEW:"):
                # Stop parsing into current table when we hit views
                current_table = None

        return {
            "tables": tables,
            "raw_schema": schema,
            "table_count": len(tables),
            "note": "Agent-readable schema from Ghost CLI",
        }

    @staticmethod
    def experiment_in_fork(fork_db_id: str, experiment_sql: str) -> str:
        """Run experimental SQL in a forked database.

        Ghost's fork-before-experiment pattern: the agent forks the DB,
        runs potentially destructive queries (DELETE, UPDATE, schema changes)
        in the fork, observes the results, and only applies changes to the
        main DB if the experiment succeeds. The fork is disposable.
        """
        print(f"[Ghost Fork] Running experiment in forked DB {fork_db_id}...")
        result = subprocess.run(
            ["ghost", "sql", fork_db_id, experiment_sql],
            capture_output=True, text=True, timeout=30,
        )
        output = result.stdout.strip()
        if result.returncode != 0:
            error = result.stderr.strip()
            print(f"[Ghost Fork] Experiment failed: {error}")
            return f"ERROR: {error}"
        print(f"[Ghost Fork] Experiment result: {output[:200]}")
        return output
