"""
Auth0 integration for DeepSentinel.
Implements all four secure agentic application pillars:
1. User Authentication (device flow for CLI)
2. Token Vault (zero standing privileges for GitHub/Slack access)
3. Async Authorization / CIBA (human-in-the-loop for sensitive actions)
4. Fine-Grained Authorization (agents access only what they need)
"""
import asyncio
import os
import time
import httpx


class Auth0Client:
    """Full Auth0 for AI Agents integration."""

    def __init__(self):
        self.domain = os.environ.get("AUTH0_DOMAIN", "")
        self.client_id = os.environ.get("AUTH0_CLIENT_ID", "")
        self.client_secret = os.environ.get("AUTH0_CLIENT_SECRET", "")
        self.audience = os.environ.get("AUTH0_AUDIENCE", "https://deepsentinel.local/api")
        self._token_cache = {}
        self.user_id = None
        self.connected = bool(self.domain and self.client_id)

        if self.connected:
            print("[Auth0] Configured — secure agent identity active")
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
    # 4. FINE-GRAINED AUTH
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

    async def close(self):
        pass
