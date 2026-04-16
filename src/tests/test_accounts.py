from __future__ import annotations

import pytest
from httpx import AsyncClient
from unittest.mock import AsyncMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REGISTER_PAYLOAD = {
    "email": "alice@example.com",
    "imap": {
        "host": "imap.example.com",
        "port": 993,
        "user": "alice@example.com",
        "password": "secret",
        "tls": True,
    },
    "smtp": {
        "host": "smtp.example.com",
        "port": 587,
        "user": "alice@example.com",
        "password": "secret",
        "tls": True,
    },
}


async def _register(client: AsyncClient) -> tuple[str, str]:
    """Register an account and return (account_id, token)."""
    resp = await client.post("/v1/accounts", json=REGISTER_PAYLOAD)
    assert resp.status_code == 201, resp.text
    data = resp.json()
    return data["account_id"], data["token"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_register_account_returns_token(client: AsyncClient):
    resp = await client.post("/v1/accounts", json=REGISTER_PAYLOAD)

    assert resp.status_code == 201
    data = resp.json()
    assert "account_id" in data
    assert "token" in data
    assert len(data["token"]) > 20
    assert data["email"] == REGISTER_PAYLOAD["email"]


@pytest.mark.asyncio
async def test_get_account_info(client: AsyncClient):
    account_id, _token = await _register(client)

    resp = await client.get(f"/v1/accounts/{account_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["account_id"] == account_id
    assert data["email"] == REGISTER_PAYLOAD["email"]
    assert "created_at" in data


@pytest.mark.asyncio
async def test_list_accounts(client: AsyncClient):
    account_id, _token = await _register(client)

    resp = await client.get("/v1/accounts")
    assert resp.status_code == 200
    ids = [a["account_id"] for a in resp.json()]
    assert account_id in ids


@pytest.mark.asyncio
async def test_get_account_not_found(client: AsyncClient):
    resp = await client.get("/v1/accounts/nonexistent-id")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_account(client: AsyncClient):
    account_id, _token = await _register(client)

    resp = await client.delete(f"/v1/accounts/{account_id}")
    assert resp.status_code == 204

    # Confirm it is gone
    resp = await client.get(f"/v1/accounts/{account_id}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_account_not_found(client: AsyncClient):
    resp = await client.delete("/v1/accounts/does-not-exist")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_mailboxes_requires_auth(client: AsyncClient):
    account_id, _token = await _register(client)

    # No auth header
    resp = await client.get(f"/v1/accounts/{account_id}/mailboxes")
    assert resp.status_code == 403  # HTTPBearer returns 403 when header absent


@pytest.mark.asyncio
async def test_mailboxes_invalid_token(client: AsyncClient):
    account_id, _token = await _register(client)

    resp = await client.get(
        f"/v1/accounts/{account_id}/mailboxes",
        headers={"Authorization": "Bearer totally-wrong-token"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_list_mailboxes_success(client: AsyncClient):
    account_id, token = await _register(client)

    mock_folders = [
        {"path": "INBOX", "name": "INBOX"},
        {"path": "Sent", "name": "Sent"},
    ]

    with patch(
        "axymail_gateway.router.mailboxes.list_mailboxes",
        new=AsyncMock(return_value=mock_folders),
    ):
        resp = await client.get(
            f"/v1/accounts/{account_id}/mailboxes",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    assert data[0]["path"] == "INBOX"


@pytest.mark.asyncio
async def test_list_messages_success(client: AsyncClient):
    account_id, token = await _register(client)

    mock_messages = [
        {
            "uid": 1,
            "subject": "Hello",
            "from": "sender@example.com",
            "to": ["alice@example.com"],
            "date": "2024-01-01T12:00:00+00:00",
            "seen": False,
            "flagged": False,
            "size": 1024,
        }
    ]

    with patch(
        "axymail_gateway.router.messages.imap_service.list_messages",
        new=AsyncMock(return_value=mock_messages),
    ):
        resp = await client.get(
            f"/v1/accounts/{account_id}/messages",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["uid"] == 1
    assert data[0]["subject"] == "Hello"


@pytest.mark.asyncio
async def test_get_message_not_found(client: AsyncClient):
    account_id, token = await _register(client)

    with patch(
        "axymail_gateway.router.messages.imap_service.get_message",
        new=AsyncMock(return_value=None),
    ):
        resp = await client.get(
            f"/v1/accounts/{account_id}/messages/9999",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_send_email_success(client: AsyncClient):
    account_id, token = await _register(client)

    payload = {
        "to": ["bob@example.com"],
        "subject": "Test",
        "text": "Hello from tests",
    }

    with patch(
        "axymail_gateway.router.send.send_email",
        new=AsyncMock(return_value=True),
    ):
        resp = await client.post(
            f"/v1/accounts/{account_id}/send",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 200
    assert resp.json()["success"] is True


@pytest.mark.asyncio
async def test_send_email_smtp_error(client: AsyncClient):
    account_id, token = await _register(client)

    payload = {"to": ["bob@example.com"], "subject": "Fail"}

    with patch(
        "axymail_gateway.router.send.send_email",
        new=AsyncMock(side_effect=Exception("Connection refused")),
    ):
        resp = await client.post(
            f"/v1/accounts/{account_id}/send",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 502
    assert "SMTP error" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_update_flags(client: AsyncClient):
    account_id, token = await _register(client)

    mock_msg = {
        "uid": 1,
        "subject": "Hello",
        "from": "sender@example.com",
        "to": [],
        "cc": [],
        "date": None,
        "seen": True,
        "flagged": False,
        "text": None,
        "html": None,
        "attachments": [],
    }

    with patch(
        "axymail_gateway.router.messages.imap_service.set_flags",
        new=AsyncMock(return_value=True),
    ), patch(
        "axymail_gateway.router.messages.imap_service.get_message",
        new=AsyncMock(return_value=mock_msg),
    ):
        resp = await client.put(
            f"/v1/accounts/{account_id}/messages/1",
            json={"seen": True},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 200
    assert resp.json()["seen"] is True


@pytest.mark.asyncio
async def test_delete_message(client: AsyncClient):
    account_id, token = await _register(client)

    with patch(
        "axymail_gateway.router.messages.imap_service.delete_message",
        new=AsyncMock(return_value=True),
    ):
        resp = await client.delete(
            f"/v1/accounts/{account_id}/messages/1",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 204
