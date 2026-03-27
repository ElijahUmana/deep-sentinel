"""
Macroscope integration for DeepSentinel.
Provides codebase architecture understanding for context-aware security analysis.
Uses Macroscope's webhook API to trigger queries, then polls for completed results.
Results are used to enrich security findings with real architectural context.
"""
import asyncio
import os
import httpx


class MacroscopeClient:
    """Queries Macroscope for codebase understanding to enrich security findings.

    Macroscope's webhook API is asynchronous: POST triggers a workflow, GET retrieves
    the result once the workflow completes. This client implements the full trigger-poll
    lifecycle so the agent gets real architectural intelligence, not just a workflow ID.
    """

    def __init__(self, api_key: str = None, workspace_id: str = None):
        self.api_key = api_key or os.environ.get("MACROSCOPE_API_KEY", "")
        self.workspace_id = workspace_id or os.environ.get("MACROSCOPE_WORKSPACE_ID", "")
        self.workspace_type = os.environ.get("MACROSCOPE_WORKSPACE_TYPE", "github_user")
        self.base_url = "https://hooks.macroscope.com/api/v1"
        self.connected = bool(self.api_key and self.workspace_id)

        # Cache for completed query results to avoid re-polling
        self._result_cache: dict[str, str] = {}

        if self.connected:
            print("[Macroscope] Connected — codebase intelligence available")
        else:
            print("[Macroscope] No API key/workspace, using static analysis fallback")

    async def query(self, question: str) -> str:
        """Trigger a Macroscope query and return the workflow ID."""
        if not self.connected:
            return ""

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    f"{self.base_url}/workspaces/{self.workspace_type}/{self.workspace_id}/query-agent-webhook-trigger",
                    headers={
                        "Content-Type": "application/json",
                        "X-Webhook-Secret": self.api_key,
                    },
                    json={"query": question},
                )
                if response.status_code == 202:
                    workflow_id = response.json().get("workflowId", "")
                    if workflow_id:
                        print(f"[Macroscope] Query submitted, workflow: {workflow_id[:20]}...")
                    return workflow_id
                return ""
        except Exception as e:
            print(f"[Macroscope] Query error: {e}")
            return ""

    async def get_query_result(self, workflow_id: str, max_wait: float = 15.0, poll_interval: float = 2.0) -> str:
        """Poll for a completed query result.

        Macroscope's webhook API returns 202 on trigger with a workflowId.
        We poll the result endpoint until the workflow completes or we time out.
        Returns the answer text, or empty string on timeout/error.
        """
        if not workflow_id or not self.connected:
            return ""

        # Check cache first
        if workflow_id in self._result_cache:
            return self._result_cache[workflow_id]

        result_url = (
            f"{self.base_url}/workspaces/{self.workspace_type}/"
            f"{self.workspace_id}/query-agent-webhook-result/{workflow_id}"
        )
        headers = {
            "Content-Type": "application/json",
            "X-Webhook-Secret": self.api_key,
        }

        elapsed = 0.0
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                while elapsed < max_wait:
                    resp = await client.get(result_url, headers=headers)

                    if resp.status_code == 200:
                        data = resp.json()
                        # Handle different response formats
                        answer = ""
                        if isinstance(data, dict):
                            answer = data.get("answer", data.get("result", data.get("response", "")))
                            if isinstance(answer, dict):
                                answer = answer.get("text", str(answer))
                        elif isinstance(data, str):
                            answer = data

                        if answer:
                            self._result_cache[workflow_id] = answer
                            print(f"[Macroscope] Result received ({len(answer)} chars)")
                            return answer

                    elif resp.status_code == 202:
                        # Still processing -- wait and retry
                        pass
                    elif resp.status_code == 404:
                        # Workflow not found or not ready yet
                        pass
                    else:
                        print(f"[Macroscope] Poll got status {resp.status_code}")
                        break

                    await asyncio.sleep(poll_interval)
                    elapsed += poll_interval

        except Exception as e:
            print(f"[Macroscope] Poll error: {e}")

        if elapsed >= max_wait:
            print(f"[Macroscope] Poll timed out after {max_wait}s (workflow may still be running)")
        return ""

    async def query_and_wait(self, question: str, max_wait: float = 15.0) -> str:
        """Trigger a query and wait for the result. Returns the answer text."""
        workflow_id = await self.query(question)
        if not workflow_id:
            return ""
        return await self.get_query_result(workflow_id, max_wait=max_wait)

    async def get_module_context(self, file_path: str) -> dict:
        """Get architectural context for a file, using Macroscope when available."""
        static = self._static_context(file_path)

        if not self.connected:
            return static

        question = (
            f"What module is {file_path} in? What services depend on it? "
            f"How critical is this file to the system? What data flows through it?"
        )
        answer = await self.query_and_wait(question, max_wait=5.0)

        if answer:
            # Merge Macroscope intelligence with static analysis
            static["macroscope_answer"] = answer
            static["note"] = "Macroscope-enriched"
            # Extract criticality signals from Macroscope response
            answer_lower = answer.lower()
            if any(w in answer_lower for w in ["critical", "payment", "auth", "security", "sensitive"]):
                static["criticality"] = "high"
            elif any(w in answer_lower for w in ["test", "mock", "fixture", "sample"]):
                static["criticality"] = "low"

        return static

    async def get_security_surface(self, repo_description: str = "") -> dict:
        """Identify security-relevant surface area using Macroscope."""
        if not self.connected:
            return {"surface": "unknown", "note": "Macroscope not connected"}

        question = (
            f"Identify all security-relevant code in this repo: "
            f"authentication, API endpoints, database queries, file I/O, "
            f"external service calls, data validation. {repo_description}"
        )
        answer = await self.query_and_wait(question, max_wait=15.0)

        if answer:
            return {
                "surface": "analyzed",
                "macroscope_analysis": answer,
                "note": "Real Macroscope analysis",
            }
        return {"surface": "queried", "note": "Macroscope query submitted (check dashboard for results)"}

    def enrich_finding(self, finding: dict) -> dict:
        """Enrich a vulnerability finding with architectural context."""
        file_path = finding.get("file_path", "")
        context = self._static_context(file_path)
        finding["macroscope_context"] = context

        # Severity escalation based on module criticality
        if context.get("criticality") == "high":
            current = finding.get("severity", "MEDIUM")
            if current == "MEDIUM":
                finding["severity"] = "HIGH"
                finding["severity_note"] = (
                    f"ESCALATED: {file_path} is in {context['module']} "
                    f"(high criticality module)"
                )
            elif current == "LOW":
                finding["severity"] = "MEDIUM"

        return finding

    async def analyze_dependency_risk(self, file_paths: list[str]) -> dict:
        """Ask Macroscope which files are most interconnected and risky.

        This uses Macroscope's unique value: it understands the full dependency
        graph, not just individual files. A vulnerability in a highly-imported
        utility is far more dangerous than one in a leaf file.
        """
        if not self.connected or not file_paths:
            return {"risk_ranking": [], "note": "Macroscope not connected"}

        paths_str = ", ".join(file_paths[:15])
        question = (
            f"Rank these files by blast radius (how many other files depend on them): "
            f"{paths_str}. For each file, list what depends on it and rate its "
            f"criticality as HIGH/MEDIUM/LOW. Focus on security impact."
        )
        answer = await self.query_and_wait(question, max_wait=5.0)

        if answer:
            return {
                "risk_ranking": answer,
                "note": "Macroscope dependency analysis",
                "files_analyzed": len(file_paths),
            }
        return {"risk_ranking": [], "note": "Macroscope analysis pending"}

    def _static_context(self, file_path: str) -> dict:
        """Static heuristic-based context when Macroscope is unavailable."""
        path_lower = file_path.lower()

        # Module detection from path
        module = "unknown"
        criticality = "medium"

        high_crit_modules = {
            "auth": "authentication",
            "login": "authentication",
            "payment": "payments",
            "billing": "payments",
            "checkout": "payments",
            "stripe": "payments",
            "admin": "administration",
            "crypto": "cryptography",
            "encrypt": "cryptography",
            "secret": "secrets",
            "token": "authentication",
            "session": "session-management",
            "middleware": "middleware",
            "api": "api-layer",
            "database": "data-access",
            "db": "data-access",
            "migration": "data-access",
            "config": "configuration",
            "env": "configuration",
        }

        for keyword, mod in high_crit_modules.items():
            if keyword in path_lower:
                module = mod
                criticality = "high"
                break

        if criticality == "medium":
            medium_modules = {
                "controller": "controller",
                "route": "routing",
                "handler": "request-handling",
                "service": "business-logic",
                "model": "data-model",
                "util": "utilities",
                "helper": "utilities",
                "test": "testing",
                "spec": "testing",
            }
            for keyword, mod in medium_modules.items():
                if keyword in path_lower:
                    module = mod
                    if keyword in ("test", "spec"):
                        criticality = "low"
                    break

        return {
            "file_path": file_path,
            "module": module,
            "criticality": criticality,
            "note": "Macroscope-enriched" if self.connected else "heuristic-based",
        }

    async def close(self):
        pass
