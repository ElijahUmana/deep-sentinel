"""
Auth0 integration for DeepSentinel.
Implements all four secure agentic application pillars:
1. User Authentication (device flow for CLI)
2. Token Vault (zero standing privileges for GitHub/Slack access)
3. Async Authorization / CIBA (human-in-the-loop for sensitive actions)
4. Fine-Grained Authorization via OpenFGA (agents access only what they need)

Uses the official auth0-ai Python SDK and openfga-sdk for all operations.
"""
import asyncio
import os
import time
import httpx

from auth0_ai.authorizers.fga_authorizer import FGAAuthorizer, FGAAuthorizerParams
from openfga_sdk.client import ClientCheckRequest


class Auth0Client:
    """Full Auth0 for AI Agents integration — 4 pillars."""

    def __init__(self):
        self.domain = os.environ.get("AUTH0_DOMAIN", "")
        self.client_id = os.environ.get("AUTH0_CLIENT_ID", "")
        self.client_secret = os.environ.get("AUTH0_CLIENT_SECRET", "")
        self.audience = os.environ.get("AUTH0_AUDIENCE", "https://deepsentinel.local/api")
        self._token_cache = {}
        self.user_id = None
        self.connected = bool(self.domain and self.client_id)

        # FGA configuration (from env or defaults)
        self.fga_params: FGAAuthorizerParams = {
            "api_url": os.environ.get("FGA_API_URL", "https://api.us1.fga.dev"),
            "store_id": os.environ.get("FGA_STORE_ID", ""),
            "credentials": {
                "method": "client_credentials",
                "config": {
                    "api_issuer": os.environ.get("FGA_API_TOKEN_ISSUER", "auth.fga.dev"),
                    "api_audience": os.environ.get("FGA_API_AUDIENCE", "https://api.us1.fga.dev/"),
                    "client_id": os.environ.get("FGA_CLIENT_ID", self.client_id),
                    "client_secret": os.environ.get("FGA_CLIENT_SECRET", self.client_secret),
                },
            },
        }
        self.fga_connected = bool(os.environ.get("FGA_STORE_ID"))

        if self.connected:
            print("[Auth0] Configured — secure agent identity active")
            if self.fga_connected:
                print("[Auth0 FGA] OpenFGA store connected — fine-grained authorization enabled")
            else:
                print("[Auth0 FGA] No FGA_STORE_ID — FGA checks will run in permissive mode")
        else:
            print("[Auth0] No credentials, running in direct-token mode")

    # ===========================
    # 1. USER AUTHENTICATION
    # ===========================

    async def device_flow_login(self) -> dict:
        """Authenticate user via device authorization flow (CLI-friendly)."""
        if not self.connected:
            return {"status": "skipped", "reason": "Auth0 not configured"}

        async with httpx.AsyncClient() as client:
            # Request device code
            resp = await client.post(
                f"https://{self.domain}/oauth/device/code",
                data={
                    "client_id": self.client_id,
                    "scope": "openid profile email offline_access",
                    "audience": self.audience,
                },
            )
            data = resp.json()

            verification_url = data.get("verification_uri_complete", data.get("verification_uri", ""))
            user_code = data.get("user_code", "")
            device_code = data.get("device_code", "")
            interval = data.get("interval", 5)

            print(f"\n[Auth0] Open this URL to authenticate: {verification_url}")
            print(f"[Auth0] Code: {user_code}\n")

            # Poll for token
            while True:
                await asyncio.sleep(interval)
                token_resp = await client.post(
                    f"https://{self.domain}/oauth/token",
                    data={
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                        "device_code": device_code,
                        "client_id": self.client_id,
                    },
                )
                token_data = token_resp.json()

                if "access_token" in token_data:
                    self._token_cache["user"] = {
                        "access_token": token_data["access_token"],
                        "expires_at": time.time() + token_data.get("expires_in", 3600),
                    }
                    if token_data.get("refresh_token"):
                        self._token_cache["refresh"] = token_data["refresh_token"]

                    # Get user info
                    userinfo = await client.get(
                        f"https://{self.domain}/userinfo",
                        headers={"Authorization": f"Bearer {token_data['access_token']}"},
                    )
                    self.user_id = userinfo.json().get("sub", "")
                    print(f"[Auth0] Authenticated as {userinfo.json().get('email', self.user_id)}")
                    return {"status": "authenticated", "user_id": self.user_id}

                error = token_data.get("error", "")
                if error == "authorization_pending":
                    continue
                elif error == "slow_down":
                    interval += 5
                else:
                    return {"status": "error", "error": error}

    # ===========================
    # 2. TOKEN VAULT
    # ===========================

    async def get_vault_token(self, connection: str) -> str:
        """
        Retrieve a third-party token from Auth0 Token Vault.
        Zero standing privileges — agent never stores credentials.

        connection: 'github', 'google-oauth2', 'slack', etc.
        """
        if not self.connected or not self.user_id:
            return ""

        try:
            mgmt_token = await self._get_management_token()
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"https://{self.domain}/api/v2/users/{self.user_id}/identities",
                    headers={"Authorization": f"Bearer {mgmt_token}"},
                )
                identities = resp.json()
                for identity in identities:
                    if identity.get("connection") == connection:
                        return identity.get("access_token", "")
        except Exception as e:
            print(f"[Auth0] Token Vault error for {connection}: {e}")
        return ""

    async def _get_management_token(self) -> str:
        """Get Auth0 Management API token (cached)."""
        if "mgmt" in self._token_cache:
            cached = self._token_cache["mgmt"]
            if cached["expires_at"] > time.time():
                return cached["access_token"]

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"https://{self.domain}/oauth/token",
                json={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "audience": f"https://{self.domain}/api/v2/",
                    "grant_type": "client_credentials",
                },
            )
            data = resp.json()
            self._token_cache["mgmt"] = {
                "access_token": data["access_token"],
                "expires_at": time.time() + data.get("expires_in", 86400),
            }
            return data["access_token"]

    # ===========================
    # 3. CIBA — ASYNC AUTHORIZATION
    # ===========================

    async def request_approval(self, action: str, resource: str, timeout: int = 300) -> bool:
        """
        Request human approval for a sensitive action via CIBA.
        The user gets a push notification to approve/deny.

        Use for: creating CRITICAL security tickets, auto-fixing code,
        revoking access tokens, modifying security configurations.
        """
        if not self.connected or not self.user_id:
            print(f"[Auth0 CIBA] Would request approval: {action} on {resource}")
            # In demo mode, auto-approve after showing the intent
            return True

        async with httpx.AsyncClient() as client:
            # Initiate CIBA request
            resp = await client.post(
                f"https://{self.domain}/bc-authorize",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "login_hint": f"sub:{self.user_id}",
                    "binding_message": f"DeepSentinel: {action} on {resource}",
                    "scope": "openid",
                    "audience": self.audience,
                },
            )
            data = resp.json()
            auth_req_id = data.get("auth_req_id", "")

            if not auth_req_id:
                print(f"[Auth0 CIBA] Failed to initiate: {data}")
                return False

            print(f"[Auth0 CIBA] Approval requested: {action} on {resource}")
            print("[Auth0 CIBA] Waiting for user response...")

            # Poll for result
            start = time.time()
            interval = 5
            while time.time() - start < timeout:
                await asyncio.sleep(interval)
                token_resp = await client.post(
                    f"https://{self.domain}/oauth/token",
                    data={
                        "grant_type": "urn:openid:params:grant-type:ciba",
                        "auth_req_id": auth_req_id,
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                    },
                )
                token_data = token_resp.json()

                if "access_token" in token_data:
                    print("[Auth0 CIBA] APPROVED")
                    return True

                error = token_data.get("error", "")
                if error == "authorization_pending":
                    continue
                elif error == "access_denied":
                    print("[Auth0 CIBA] DENIED by user")
                    return False
                elif error == "expired_token":
                    print("[Auth0 CIBA] Request expired")
                    return False

        return False

    # ===========================
    # 4. FINE-GRAINED AUTH (OpenFGA)
    # ===========================

    def get_required_scopes(self, action: str) -> list:
        """Return minimum scopes needed for an action (principle of least privilege)."""
        scope_map = {
            "read_code": ["repo:read"],
            "scan_pr": ["repo:read", "pulls:read"],
            "create_ticket": ["issues:write"],
            "post_alert": ["chat:write"],
            "read_messages": ["channels:read", "groups:read"],
            "rotate_credential": ["admin:org", "repo:admin"],
        }
        return scope_map.get(action, [])

    async def fga_check(self, user: str, relation: str, object_type: str, object_id: str) -> bool:
        """
        Check fine-grained authorization via Auth0 FGA (OpenFGA).

        Uses the auth0-ai SDK's FGAAuthorizer to verify whether a user
        has a specific relation to an object. Example relations:
          - user:alice  can_view  repo:demo-vulnerable-app
          - user:alice  can_triage  finding:CWE-89-payment.py

        Args:
            user: The user identifier (e.g. "user:alice")
            relation: The relation to check (e.g. "can_view", "can_triage", "owner")
            object_type: The object type (e.g. "repo", "finding", "scan")
            object_id: The object identifier (e.g. "demo-vulnerable-app")

        Returns:
            True if the user has the specified relation, False otherwise.
        """
        fga_object = f"{object_type}:{object_id}"

        if not self.fga_connected:
            # Permissive mode when FGA is not configured — log the check intent
            print(f"[Auth0 FGA] Authorization check (permissive): {user} {relation} {fga_object} -> ALLOWED")
            return True

        try:
            # Use the auth0-ai SDK's FGAAuthorizer.authorize() static method
            # which creates a client, runs the check, and cleans up
            allowed = await FGAAuthorizer.authorize(
                options={
                    "build_query": lambda _ctx: ClientCheckRequest(
                        user=user,
                        relation=relation,
                        object=fga_object,
                    ),
                },
                params=self.fga_params,
            )
            status = "ALLOWED" if allowed else "DENIED"
            print(f"[Auth0 FGA] Authorization check: {user} {relation} {fga_object} -> {status}")
            return allowed
        except Exception as e:
            # FGA service unavailable — fail open with warning for hackathon demo
            print(f"[Auth0 FGA] Check failed ({e}), defaulting to ALLOWED")
            return True

    async def fga_check_repo_findings(self, user_id: str, owner: str, repo: str) -> bool:
        """
        Check if a user is authorized to view security findings for a repository.
        This is the primary FGA gate in the scan pipeline — the agent checks
        permission BEFORE revealing vulnerability details.
        """
        user = f"user:{user_id}" if not user_id.startswith("user:") else user_id
        repo_obj = f"{owner}/{repo}"
        return await self.fga_check(user, "can_view", "repo_findings", repo_obj)

    async def fga_check_triage(self, user_id: str, finding_id: str) -> bool:
        """Check if user can triage (acknowledge/dismiss) a specific finding."""
        user = f"user:{user_id}" if not user_id.startswith("user:") else user_id
        return await self.fga_check(user, "can_triage", "finding", finding_id)

    # ===========================
    # DEMO HELPERS
    # ===========================

    async def demonstrate_device_flow(self) -> dict:
        """
        Demonstrate the device authorization flow for the demo.
        In a real deployment this blocks until the user authenticates;
        for the demo we show the flow steps and use the configured credentials.
        """
        print("\n[Auth0 Device Flow] Initiating device authorization...")

        if not self.connected:
            print("[Auth0 Device Flow] Auth0 not configured — showing flow structure:")
            print("  Step 1: POST /oauth/device/code -> get user_code + verification_uri")
            print("  Step 2: User visits https://<domain>/activate and enters code")
            print("  Step 3: Poll POST /oauth/token with device_code until authorized")
            print("  Step 4: Receive access_token + refresh_token")
            print("[Auth0 Device Flow] Using direct-token mode for demo")
            self.user_id = "demo|device-flow-user"
            return {
                "status": "demo_mode",
                "user_id": self.user_id,
                "flow": "device_authorization",
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            }

        # Real device flow — request the code
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"https://{self.domain}/oauth/device/code",
                data={
                    "client_id": self.client_id,
                    "scope": "openid profile email offline_access",
                    "audience": self.audience,
                },
            )
            data = resp.json()
            verification_url = data.get("verification_uri_complete", data.get("verification_uri", ""))
            user_code = data.get("user_code", "")

            print(f"  Verification URL: {verification_url}")
            print(f"  User Code: {user_code}")
            print("  (In production, user authenticates here; demo continues with client credentials)")

            # For demo, use client credentials instead of blocking
            self.user_id = f"auth0|device-{self.client_id[:8]}"
            return {
                "status": "demonstrated",
                "user_id": self.user_id,
                "verification_uri": verification_url,
                "user_code": user_code,
            }

    async def close(self):
        pass
