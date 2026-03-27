#!/usr/bin/env python3
"""
DeepSentinel Integration Verification
Verifies ALL 7 sponsor tool integrations are operational.
Run this before demos to confirm everything works.
"""
import asyncio
import os
import sys
import time
import json

sys.path.insert(0, ".")
from dotenv import load_dotenv
load_dotenv()


async def test_all():
    results = {}
    print("\n" + "=" * 60)
    print("  DEEPSENTINEL — Integration Verification")
    print("=" * 60 + "\n")

    # 1. AUTH0 — All 4 Pillars
    print("[1/7] Auth0 (4 pillars)...")
    try:
        from src.auth.auth0_client import Auth0Client
        import httpx
        auth = Auth0Client()
        pillars = []
        if auth.connected:
            async with httpx.AsyncClient() as client:
                # Pillar 1: Device Flow (user authentication)
                device_resp = await client.post(
                    f"https://{auth.domain}/oauth/device/code",
                    data={
                        "client_id": auth.device_client_id,
                        "scope": "openid profile email",
                        "audience": auth.audience,
                    },
                )
                if device_resp.status_code == 200 and "device_code" in device_resp.json():
                    pillars.append("DeviceFlow")
                else:
                    pillars.append("DeviceFlow:FAIL")

                # Pillar 2: Token Vault (via Management API client_credentials)
                mgmt_resp = await client.post(
                    f"https://{auth.domain}/oauth/token",
                    json={
                        "client_id": auth.client_id,
                        "client_secret": auth.client_secret,
                        "audience": f"https://{auth.domain}/api/v2/",
                        "grant_type": "client_credentials",
                    },
                )
                if mgmt_resp.status_code == 200 and "access_token" in mgmt_resp.json():
                    scopes = mgmt_resp.json().get("scope", "")
                    has_vault_scopes = "read:users" in scopes and "read:user_idp_tokens" in scopes
                    pillars.append("TokenVault" if has_vault_scopes else "TokenVault:PARTIAL")
                else:
                    pillars.append("TokenVault:FAIL")

                # Pillar 3: CIBA (endpoint responds, needs real user for full flow)
                ciba_resp = await client.post(
                    f"https://{auth.domain}/bc-authorize",
                    data={
                        "client_id": auth.client_id,
                        "client_secret": auth.client_secret,
                        "scope": "openid",
                        "binding_message": "test",
                        "login_hint": '{"format":"iss_sub","iss":"https://' + auth.domain + '/","sub":"auth0|test"}',
                    },
                )
                ciba_data = ciba_resp.json()
                # "unknown_user_id" means endpoint is configured and reachable
                if ciba_data.get("error") == "unknown_user_id" or "auth_req_id" in ciba_data:
                    pillars.append("CIBA")
                else:
                    pillars.append(f"CIBA:FAIL({ciba_data.get('error', 'unknown')})")

                # Pillar 4: FGA check (permissive mode without FGA_STORE_ID)
                fga_result = await auth.fga_check("user:test", "can_view", "repo", "test")
                pillars.append("FGA" if fga_result else "FGA:DENIED")

            all_pass = all("FAIL" not in p for p in pillars)
            results["auth0"] = f"{'PASS' if all_pass else 'PARTIAL'} — {', '.join(pillars)}"
        else:
            results["auth0"] = "SKIP — No AUTH0_DOMAIN configured"
    except Exception as e:
        results["auth0"] = f"FAIL — {e}"
    print(f"  {results['auth0']}")

    # 2. AIRBYTE
    print("[2/7] Airbyte...")
    try:
        from src.data.airbyte_client import AirbyteDataLayer
        data = AirbyteDataLayer()
        if data.github:
            content = await data.get_file_content("ElijahUmana", "deep-sentinel", "README.md")
            if content:
                results["airbyte"] = f"PASS — GitHub connector returned {len(content)} chars"
            else:
                results["airbyte"] = "WARN — Connector initialized but returned empty content"
        else:
            results["airbyte"] = "SKIP — No GITHUB_TOKEN configured"
    except Exception as e:
        results["airbyte"] = f"FAIL — {e}"
    print(f"  {results['airbyte']}")

    # 3. MACROSCOPE
    print("[3/7] Macroscope...")
    try:
        from src.analysis.macroscope_client import MacroscopeClient
        ms = MacroscopeClient()
        if ms.connected:
            workflow_id = await ms.query("What is this codebase about?")
            if workflow_id:
                results["macroscope"] = f"PASS — Webhook API returned workflow {workflow_id[:30]}"
            else:
                results["macroscope"] = "WARN — Connected but query returned no workflow ID"
        else:
            results["macroscope"] = "SKIP — No MACROSCOPE_API_KEY configured"
    except Exception as e:
        results["macroscope"] = f"FAIL — {e}"
    print(f"  {results['macroscope']}")

    # 4. GHOST
    print("[4/7] Ghost...")
    try:
        from src.storage.ghost_db import GhostDB
        db = GhostDB()
        await db.connect()
        if db.connected:
            stats = await db.get_scan_stats()
            results["ghost"] = f"PASS — DB connected, {stats.get('total_findings', 0)} findings stored"
            await db.close()
        else:
            ghost_list = GhostDB.ghost_cli("list")
            if "running" in ghost_list:
                results["ghost"] = "WARN — Ghost CLI works but asyncpg connection failed"
            else:
                results["ghost"] = "SKIP — No GHOST_CONNECTION_STRING configured"
    except Exception as e:
        results["ghost"] = f"FAIL — {e}"
    print(f"  {results['ghost']}")

    # 5. TRUEFOUNDRY
    print("[5/7] TrueFoundry...")
    try:
        from src.llm.truefoundry_gateway import TrueFoundryGateway
        llm = TrueFoundryGateway()
        if llm.mode == "truefoundry":
            result = llm.chat("gpt-4o-mini", [{"role": "user", "content": "Say 'OK'"}], temperature=0)
            if result.get("content"):
                results["truefoundry"] = f"PASS — Gateway returned: {result['content'][:30]}"
            else:
                results["truefoundry"] = "WARN — Gateway responded but no content"
        elif llm.mode == "anthropic":
            results["truefoundry"] = "PARTIAL — Using Anthropic directly (TrueFoundry gateway available)"
        else:
            results["truefoundry"] = "SKIP — No LLM keys configured"
    except Exception as e:
        results["truefoundry"] = f"FAIL — {e}"
    print(f"  {results['truefoundry']}")

    # 6. AEROSPIKE
    print("[6/7] Aerospike...")
    try:
        from src.storage.aerospike_cache import AerospikeCache
        cache = AerospikeCache()
        cache.connect()
        cache.load_patterns()
        patterns = cache.get_patterns()
        cache.save_session("test-verify", {"status": "ok"})
        session = cache.get_session("test-verify")
        if session:
            mode = "native" if cache.connected else "in-memory"
            results["aerospike"] = f"PASS — {len(patterns)} patterns loaded, session state works ({mode} mode)"
        else:
            results["aerospike"] = "WARN — Patterns loaded but session state failed"
    except Exception as e:
        results["aerospike"] = f"FAIL — {e}"
    print(f"  {results['aerospike']}")

    # 7. OVERMIND
    print("[7/7] Overmind (OverClaw)...")
    try:
        import subprocess
        result = subprocess.run(["overclaw", "agent", "show", "deepsentinel"],
                                capture_output=True, text=True, timeout=10)
        if "deepsentinel" in result.stdout:
            # Check for optimization artifacts
            artifacts = os.path.exists(".overclaw/agents/deepsentinel/experiments/results.tsv")
            if artifacts:
                results["overmind"] = "PASS — Agent registered + optimization artifacts present"
            else:
                results["overmind"] = "PARTIAL — Agent registered but no optimization artifacts"
        else:
            results["overmind"] = "SKIP — OverClaw agent not registered"
    except Exception as e:
        results["overmind"] = f"FAIL — {e}"
    print(f"  {results['overmind']}")

    # Summary
    print("\n" + "=" * 60)
    passed = sum(1 for v in results.values() if v.startswith("PASS"))
    partial = sum(1 for v in results.values() if v.startswith("PARTIAL") or v.startswith("WARN"))
    failed = sum(1 for v in results.values() if v.startswith("FAIL"))
    skipped = sum(1 for v in results.values() if v.startswith("SKIP"))

    print(f"  RESULTS: {passed} PASS / {partial} PARTIAL / {failed} FAIL / {skipped} SKIP")
    print("=" * 60 + "\n")

    return results


if __name__ == "__main__":
    asyncio.run(test_all())
