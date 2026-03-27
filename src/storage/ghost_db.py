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

        async with self.pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO correlations (scan_id, correlation_type, github_ref, slack_ref, description, risk_score) VALUES ($1,$2,$3,$4,$5,$6)",
                scan_id, correlation.get("type", ""), correlation.get("github_ref", ""),
                correlation.get("slack_ref", ""), correlation.get("risk_note", ""),
                correlation.get("risk_score"),
            )

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
        """Get database schema via Ghost CLI."""
        result = subprocess.run(
            ["ghost", "schema", db_id],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout.strip()
