"""
Aerospike integration for DeepSentinel.
Real-time cache for CVE lookups, scan deduplication, vulnerability patterns, and session state.
Uses Aerospike's key-value + document model with TTL-based expiration.
"""
import json
import time
import hashlib
import os

try:
    import aerospike
    from aerospike import exception as ae_exception

    AEROSPIKE_AVAILABLE = True
except ImportError:
    AEROSPIKE_AVAILABLE = False


# Preloaded vulnerability patterns (CWE-mapped)
VULNERABILITY_PATTERNS = [
    {
        "pattern_id": "cwe-798-hardcoded",
        "regex": r"(password|secret|api_key|token|private_key)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
        "cwe_id": "CWE-798",
        "severity": "CRITICAL",
        "description": "Hardcoded credentials in source code",
        "language": "any",
    },
    {
        "pattern_id": "cwe-89-sqli-concat",
        "regex": r"(SELECT|INSERT|UPDATE|DELETE).*[\+`\$].*\b(req|request|params|query|input)\b",
        "cwe_id": "CWE-89",
        "severity": "HIGH",
        "description": "SQL injection via string concatenation",
        "language": "any",
    },
    {
        "pattern_id": "cwe-78-cmdi",
        "regex": r"(exec|spawn|system|popen|child_process)\s*\(.*\b(req|request|input|params|user)\b",
        "cwe_id": "CWE-78",
        "severity": "CRITICAL",
        "description": "OS command injection via unsanitized input",
        "language": "any",
    },
    {
        "pattern_id": "cwe-79-xss",
        "regex": r"(innerHTML|document\.write|\.html\(|dangerouslySetInnerHTML)",
        "cwe_id": "CWE-79",
        "severity": "HIGH",
        "description": "Cross-site scripting via unsafe DOM manipulation",
        "language": "any",
    },
    {
        "pattern_id": "cwe-22-traversal",
        "regex": r"(readFile|readFileSync|open|fopen)\s*\(.*\b(req|request|path|filename|user)\b",
        "cwe_id": "CWE-22",
        "severity": "HIGH",
        "description": "Path traversal via unvalidated file paths",
        "language": "any",
    },
    {
        "pattern_id": "cwe-327-weak-crypto",
        "regex": r"(md5|sha1|createHash\(['\"]md5|createHash\(['\"]sha1|DES|RC4)",
        "cwe_id": "CWE-327",
        "severity": "MEDIUM",
        "description": "Use of weak cryptographic algorithm",
        "language": "any",
    },
    {
        "pattern_id": "cwe-502-deserialization",
        "regex": r"(pickle\.loads|yaml\.load\(|yaml\.unsafe_load|unserialize|eval\(.*JSON)",
        "cwe_id": "CWE-502",
        "severity": "HIGH",
        "description": "Insecure deserialization of untrusted data",
        "language": "any",
    },
    {
        "pattern_id": "cwe-918-ssrf",
        "regex": r"(fetch|axios|requests\.get|urllib|http\.get)\s*\(.*\b(req|request|url|input|user)\b",
        "cwe_id": "CWE-918",
        "severity": "HIGH",
        "description": "Server-side request forgery via user-controlled URL",
        "language": "any",
    },
    {
        "pattern_id": "cwe-400-no-ratelimit",
        "regex": r"(app\.post|router\.post|app\.get)\s*\(['\"]/(login|auth|api|token)",
        "cwe_id": "CWE-400",
        "severity": "MEDIUM",
        "description": "Sensitive endpoint potentially missing rate limiting",
        "language": "any",
    },
    {
        "pattern_id": "cwe-209-error-exposure",
        "regex": r"(res\.send|res\.json|return)\s*\(.*\b(err|error|stack|trace)\b",
        "cwe_id": "CWE-209",
        "severity": "LOW",
        "description": "Error details potentially exposed to users",
        "language": "any",
    },
]


class AerospikeCache:
    """Real-time cache using Aerospike for sub-ms lookups."""

    def __init__(self, host: str = None, port: int = None):
        self.host = host or os.environ.get("AEROSPIKE_HOST", "127.0.0.1")
        self.port = port or int(os.environ.get("AEROSPIKE_PORT", "3000"))
        self.namespace = "test"
        self.client = None
        self.connected = False

        # In-memory fallback if Aerospike unavailable
        self._memory_cache: dict = {}

    def connect(self):
        """Connect to Aerospike. Falls back to in-memory cache if unavailable."""
        if not AEROSPIKE_AVAILABLE:
            print("[Aerospike] Package not available, using in-memory fallback")
            return

        try:
            config = {"hosts": [(self.host, self.port)]}
            self.client = aerospike.client(config).connect()
            self.connected = True
            print(f"[Aerospike] Connected to {self.host}:{self.port}")
        except Exception as e:
            print(f"[Aerospike] Connection failed ({e}), using in-memory fallback")
            self.connected = False

    def _key(self, set_name: str, key_str: str):
        return (self.namespace, set_name, key_str)

    # =========================================
    # VULNERABILITY PATTERN STORE
    # =========================================

    def load_patterns(self):
        """Preload vulnerability patterns into cache."""
        for pattern in VULNERABILITY_PATTERNS:
            pid = pattern["pattern_id"]
            if self.connected:
                try:
                    self.client.put(
                        self._key("patterns", pid),
                        {
                            "pattern_id": pid,
                            "regex": pattern["regex"],
                            "cwe_id": pattern["cwe_id"],
                            "severity": pattern["severity"],
                            "description": pattern["description"],
                            "language": pattern["language"],
                        },
                    )
                except Exception:
                    self._memory_cache[f"pattern:{pid}"] = pattern
            else:
                self._memory_cache[f"pattern:{pid}"] = pattern

        print(f"[Aerospike] Loaded {len(VULNERABILITY_PATTERNS)} vulnerability patterns")

    def get_patterns(self) -> list[dict]:
        """Retrieve all vulnerability patterns."""
        if self.connected:
            try:
                scan = self.client.scan(self.namespace, "patterns")
                results = []

                def callback(record):
                    _, _, bins = record
                    results.append(bins)

                scan.foreach(callback)
                return results if results else VULNERABILITY_PATTERNS
            except Exception:
                return VULNERABILITY_PATTERNS
        return VULNERABILITY_PATTERNS

    # =========================================
    # SCAN RESULT CACHE
    # =========================================

    def cache_scan_result(self, repo: str, pr_number: int, commit_sha: str, results: dict, ttl: int = 3600):
        """Cache scan results keyed by repo:pr:sha. TTL 1 hour."""
        cache_key = f"{repo}:{pr_number}:{commit_sha[:8]}"
        data = {"results": json.dumps(results), "cached_at": int(time.time()), "hit_count": 0}

        if self.connected:
            try:
                self.client.put(self._key("scan_cache", cache_key), data, {"ttl": ttl})
            except Exception:
                self._memory_cache[f"scan:{cache_key}"] = {**data, "_ttl": time.time() + ttl}
        else:
            self._memory_cache[f"scan:{cache_key}"] = {**data, "_ttl": time.time() + ttl}

    def get_cached_scan(self, repo: str, pr_number: int, commit_sha: str) -> dict | None:
        """Get cached scan results. Returns None on miss."""
        cache_key = f"{repo}:{pr_number}:{commit_sha[:8]}"

        if self.connected:
            try:
                _, _, bins = self.client.get(self._key("scan_cache", cache_key))
                self.client.increment(self._key("scan_cache", cache_key), "hit_count", 1)
                return json.loads(bins.get("results", "{}"))
            except Exception:
                pass

        # Memory fallback
        mem_key = f"scan:{cache_key}"
        if mem_key in self._memory_cache:
            entry = self._memory_cache[mem_key]
            if entry.get("_ttl", 0) > time.time():
                entry["hit_count"] = entry.get("hit_count", 0) + 1
                return json.loads(entry.get("results", "{}"))
            else:
                del self._memory_cache[mem_key]

        return None

    # =========================================
    # CVE CACHE
    # =========================================

    def cache_cve(self, cve_id: str, cve_data: dict, ttl: int = 86400):
        """Cache a CVE entry. TTL 24 hours."""
        data = {
            "cve_id": cve_id,
            "severity": cve_data.get("severity", "UNKNOWN"),
            "description": cve_data.get("description", "")[:1000],
            "affected": json.dumps(cve_data.get("affected", [])),
            "cvss_score": float(cve_data.get("cvss_score", 0.0)),
            "cached_at": int(time.time()),
        }

        if self.connected:
            try:
                self.client.put(self._key("cves", cve_id), data, {"ttl": ttl})
            except Exception:
                self._memory_cache[f"cve:{cve_id}"] = data
        else:
            self._memory_cache[f"cve:{cve_id}"] = data

    def lookup_cve(self, cve_id: str) -> dict | None:
        """Look up a CVE by ID. Sub-millisecond when connected."""
        if self.connected:
            try:
                _, _, bins = self.client.get(self._key("cves", cve_id))
                bins["affected"] = json.loads(bins.get("affected", "[]"))
                return bins
            except Exception:
                pass

        return self._memory_cache.get(f"cve:{cve_id}")

    # =========================================
    # AGENT SESSION STATE
    # =========================================

    def save_session(self, session_id: str, state: dict, ttl: int = 7200):
        """Save agent session state. TTL 2 hours."""
        data = {"session_id": session_id, "state": json.dumps(state), "updated_at": int(time.time())}

        if self.connected:
            try:
                self.client.put(self._key("sessions", session_id), data, {"ttl": ttl})
            except Exception:
                self._memory_cache[f"session:{session_id}"] = data
        else:
            self._memory_cache[f"session:{session_id}"] = data

    def get_session(self, session_id: str) -> dict | None:
        """Retrieve agent session state."""
        if self.connected:
            try:
                _, _, bins = self.client.get(self._key("sessions", session_id))
                return json.loads(bins.get("state", "{}"))
            except Exception:
                pass

        entry = self._memory_cache.get(f"session:{session_id}")
        if entry:
            return json.loads(entry.get("state", "{}"))
        return None

    def close(self):
        """Clean up connection."""
        if self.connected and self.client:
            self.client.close()
            print("[Aerospike] Connection closed")
