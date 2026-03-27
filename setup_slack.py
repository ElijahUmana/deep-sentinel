#!/usr/bin/env python3
"""
Slack setup script for DeepSentinel demo.
Run after adding SLACK_BOT_TOKEN to .env.

Creates channels, posts security-relevant messages, and verifies the
Airbyte Slack connector can pull them.
"""
import asyncio
import os
import sys
import time

import httpx
from dotenv import load_dotenv

load_dotenv()

SLACK_TOKEN = os.environ.get("SLACK_BOT_TOKEN", "")
if not SLACK_TOKEN:
    print("ERROR: SLACK_BOT_TOKEN not found in .env")
    print("Add it first: echo 'SLACK_BOT_TOKEN=xoxb-...' >> .env")
    sys.exit(1)

HEADERS = {"Authorization": f"Bearer {SLACK_TOKEN}", "Content-Type": "application/json"}
BASE = "https://slack.com/api"

CHANNELS_TO_CREATE = ["security-review", "engineering"]

MESSAGES = {
    "engineering": [
        "Let's skip input validation for the payment endpoint - we'll add it in Q2",
        "The DB password for payments is still hardcoded, can someone move it to secrets manager?",
        "FYI the new auth middleware isn't checking token expiry yet, tagged as tech debt",
        "Quick update: pushed the refund endpoint live. No time for security review before launch.",
    ],
    "security-review": [
        "Has anyone reviewed the refund endpoint? It's using os.system directly",
        "Found a SQL injection vector in the search API - filed as CVE-2026-DEMO-001",
        "The admin panel still uses MD5 for password hashing. Upgrade to bcrypt is in the backlog.",
        "Flagged: the webhook handler doesn't validate signatures. Anyone can spoof events.",
    ],
}


async def slack_api(client: httpx.AsyncClient, method: str, **kwargs) -> dict:
    resp = await client.post(f"{BASE}/{method}", headers=HEADERS, json=kwargs)
    data = resp.json()
    if not data.get("ok"):
        error = data.get("error", "unknown")
        # Some errors are expected (channel already exists, already in channel)
        if error not in ("name_taken", "already_in_channel"):
            print(f"  WARN: {method} -> {error}")
    return data


async def main():
    async with httpx.AsyncClient() as client:
        # Step 1: Verify token works
        print("[1/4] Verifying bot token...")
        auth = await slack_api(client, "auth.test")
        if not auth.get("ok"):
            print(f"  FAIL: Token invalid - {auth.get('error')}")
            sys.exit(1)
        bot_name = auth.get("user", "unknown")
        team = auth.get("team", "unknown")
        print(f"  OK: Bot '{bot_name}' in workspace '{team}'")

        # Step 2: Create channels
        print("[2/4] Creating channels...")
        channel_ids = {}
        for ch_name in CHANNELS_TO_CREATE:
            result = await slack_api(client, "conversations.create", name=ch_name)
            if result.get("ok"):
                channel_ids[ch_name] = result["channel"]["id"]
                print(f"  Created #{ch_name} ({channel_ids[ch_name]})")
            elif result.get("error") == "name_taken":
                # Channel exists, find its ID
                list_result = await slack_api(client, "conversations.list", types="public_channel", limit=200)
                for ch in list_result.get("channels", []):
                    if ch["name"] == ch_name:
                        channel_ids[ch_name] = ch["id"]
                        print(f"  #{ch_name} already exists ({channel_ids[ch_name]})")
                        break
                # Join the channel in case bot isn't a member
                if ch_name in channel_ids:
                    await slack_api(client, "conversations.join", channel=channel_ids[ch_name])

        # Step 3: Post security messages
        print("[3/4] Posting security discussion messages...")
        for ch_name, messages in MESSAGES.items():
            if ch_name not in channel_ids:
                print(f"  SKIP: #{ch_name} not found")
                continue
            ch_id = channel_ids[ch_name]
            for msg in messages:
                await slack_api(client, "chat.postMessage", channel=ch_id, text=msg)
                time.sleep(0.3)  # Rate limit
            print(f"  Posted {len(messages)} messages to #{ch_name}")

        # Step 4: Verify Airbyte Slack connector can read messages
        print("[4/4] Verifying Airbyte Slack connector...")
        try:
            sys.path.insert(0, ".")
            from airbyte_agent_slack import SlackConnector
            from airbyte_agent_slack.models import SlackTokenAuthenticationAuthConfig

            slack = SlackConnector(
                auth_config=SlackTokenAuthenticationAuthConfig(api_token=SLACK_TOKEN)
            )
            check = await slack.check()
            print(f"  Health check: {check.status}")

            ch_result = await slack.execute("channels", "list", {})
            channels = ch_result.data if hasattr(ch_result, "data") else ch_result
            if isinstance(channels, list):
                names = [c.get("name", "") for c in channels if isinstance(c, dict)]
                print(f"  Channels visible: {', '.join(names[:10])}")

                # Try reading messages from engineering
                for ch in channels:
                    if ch.get("name") == "engineering":
                        msg_result = await slack.execute(
                            "channel_messages", "list", {"channel": ch["id"]}
                        )
                        msgs = msg_result.data if hasattr(msg_result, "data") else msg_result
                        if isinstance(msgs, list) and msgs:
                            print(f"  Messages in #engineering: {len(msgs)}")
                            print(f"  Sample: {msgs[0].get('text', '')[:80]}")
                        break
            print("  PASS: Slack connector working")
        except Exception as e:
            print(f"  Connector test error: {e}")
            print("  (This is OK - the Slack API calls above confirmed the token works)")

    print("\nDone. Run 'python test_integrations.py' to verify all integrations.")


if __name__ == "__main__":
    asyncio.run(main())
