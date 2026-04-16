#!/usr/bin/env python3
"""
basic_usage.py — End-to-end example using Mailpit as the mail server.

Prerequisites:
    docker compose -f src/examples/docker-compose.yml up -d
    pip install httpx

Then run:
    python src/examples/basic_usage.py
"""

from __future__ import annotations

import json
import sys

import httpx

GATEWAY = "http://localhost:3000"

# Mailpit defaults — no real authentication required when
# MP_SMTP_AUTH_ACCEPT_ANY=true
MAILPIT_IMAP_HOST = "localhost"
MAILPIT_SMTP_HOST = "localhost"

ACCOUNT_PAYLOAD = {
    "email": "alice@example.com",
    "imap": {
        "host": MAILPIT_IMAP_HOST,
        "port": 1143,
        "user": "alice@example.com",
        "password": "anypassword",
        "tls": False,
    },
    "smtp": {
        "host": MAILPIT_SMTP_HOST,
        "port": 1025,
        "user": "alice@example.com",
        "password": "anypassword",
        "tls": False,
    },
}


def pp(label: str, data) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {label}")
    print("=" * 60)
    print(json.dumps(data, indent=2, default=str))


def main() -> None:
    with httpx.Client(base_url=GATEWAY, timeout=30) as client:

        # ------------------------------------------------------------------
        # 1. Register account
        # ------------------------------------------------------------------
        print("1. Registering account …")
        resp = client.post("/v1/accounts", json=ACCOUNT_PAYLOAD)
        resp.raise_for_status()
        reg = resp.json()
        pp("Register response", reg)

        account_id = reg["account_id"]
        token = reg["token"]
        auth = {"Authorization": f"Bearer {token}"}

        # ------------------------------------------------------------------
        # 2. List mailboxes
        # ------------------------------------------------------------------
        print("\n2. Listing mailboxes …")
        resp = client.get(f"/v1/accounts/{account_id}/mailboxes", headers=auth)
        if resp.status_code == 200:
            pp("Mailboxes", resp.json())
        else:
            print(f"  WARNING: {resp.status_code} — {resp.text}")

        # ------------------------------------------------------------------
        # 3. Send a test email (so INBOX is not empty)
        # ------------------------------------------------------------------
        print("\n3. Sending a test email …")
        send_payload = {
            "to": ["alice@example.com"],
            "subject": "Hello from axymail-gateway",
            "text": "This is a test message sent via the axymail-gateway API.",
            "html": "<p>This is a <b>test message</b> sent via the axymail-gateway API.</p>",
        }
        resp = client.post(
            f"/v1/accounts/{account_id}/send", json=send_payload, headers=auth
        )
        if resp.status_code == 200:
            pp("Send response", resp.json())
        else:
            print(f"  WARNING: {resp.status_code} — {resp.text}")

        # ------------------------------------------------------------------
        # 4. List messages in INBOX
        # ------------------------------------------------------------------
        print("\n4. Listing messages in INBOX …")
        resp = client.get(
            f"/v1/accounts/{account_id}/messages",
            params={"mailbox": "INBOX", "page": 0, "page_size": 5},
            headers=auth,
        )
        if resp.status_code == 200:
            messages = resp.json()
            pp("Messages", messages)
        else:
            print(f"  WARNING: {resp.status_code} — {resp.text}")
            messages = []

        # ------------------------------------------------------------------
        # 5. Fetch the first message in full
        # ------------------------------------------------------------------
        if messages:
            uid = messages[0]["uid"]
            print(f"\n5. Fetching full message uid={uid} …")
            resp = client.get(
                f"/v1/accounts/{account_id}/messages/{uid}",
                params={"mailbox": "INBOX"},
                headers=auth,
            )
            if resp.status_code == 200:
                pp("Full message", resp.json())
            else:
                print(f"  WARNING: {resp.status_code} — {resp.text}")

            # ------------------------------------------------------------------
            # 6. Mark as read
            # ------------------------------------------------------------------
            print(f"\n6. Marking message uid={uid} as read …")
            resp = client.put(
                f"/v1/accounts/{account_id}/messages/{uid}",
                json={"seen": True},
                params={"mailbox": "INBOX"},
                headers=auth,
            )
            if resp.status_code == 200:
                pp("Updated message", resp.json())
            else:
                print(f"  WARNING: {resp.status_code} — {resp.text}")
        else:
            print("\n5-6. No messages found — skipping fetch and mark-as-read steps.")

        # ------------------------------------------------------------------
        # Done
        # ------------------------------------------------------------------
        print("\nDone.")
        print(f"  account_id : {account_id}")
        print(f"  token      : {token[:16]}…  (keep this safe)")
        print(
            f"\nView emails in the Mailpit web UI: http://localhost:8025"
        )


if __name__ == "__main__":
    try:
        main()
    except httpx.ConnectError:
        print(
            "\nERROR: Could not connect to axymail-gateway at http://localhost:3000\n"
            "Make sure the service is running:\n"
            "  docker compose -f src/examples/docker-compose.yml up -d\n",
            file=sys.stderr,
        )
        sys.exit(1)
