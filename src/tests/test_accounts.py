"""
Tests for account registration, retrieval, listing, and deletion.
Covers both unauthenticated access and auth-gated DELETE.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.conftest import REGISTER_PAYLOAD, TEST_ADMIN_KEY, register


# ── Registration ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_register_returns_token(client: AsyncClient):
    resp = await client.post("/v1/accounts", json=REGISTER_PAYLOAD)

    assert resp.status_code == 201
    data = resp.json()
    assert "account_id" in data
    assert "token" in data
    assert len(data["token"]) > 20
    assert data["email"] == REGISTER_PAYLOAD["email"]


@pytest.mark.asyncio
async def test_register_duplicate_email_creates_separate_account(client: AsyncClient):
    """Each registration creates a new independent account+token."""
    r1 = await client.post("/v1/accounts", json=REGISTER_PAYLOAD)
    r2 = await client.post("/v1/accounts", json=REGISTER_PAYLOAD)

    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r1.json()["account_id"] != r2.json()["account_id"]
    assert r1.json()["token"] != r2.json()["token"]


# ── GET /accounts/{id} ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_account_info(client: AsyncClient):
    account_id, _ = await register(client)

    resp = await client.get(f"/v1/accounts/{account_id}")

    assert resp.status_code == 200
    data = resp.json()
    assert data["account_id"] == account_id
    assert data["email"] == REGISTER_PAYLOAD["email"]
    assert "created_at" in data


@pytest.mark.asyncio
async def test_get_account_not_found(client: AsyncClient):
    resp = await client.get("/v1/accounts/nonexistent-id")
    assert resp.status_code == 404


# ── GET /accounts ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_accounts(client: AsyncClient):
    account_id, _ = await register(client)

    resp = await client.get("/v1/accounts")

    assert resp.status_code == 200
    ids = [a["account_id"] for a in resp.json()]
    assert account_id in ids


@pytest.mark.asyncio
async def test_list_accounts_multiple(client: AsyncClient):
    for i in range(3):
        payload = {**REGISTER_PAYLOAD, "email": f"user{i}@example.com"}
        await client.post("/v1/accounts", json=payload)

    resp = await client.get("/v1/accounts")
    assert resp.status_code == 200
    assert len(resp.json()) >= 3


# ── DELETE /accounts/{id} — auth-gated ───────────────────────────────────────

@pytest.mark.asyncio
async def test_delete_own_account(client: AsyncClient):
    """Account owner can delete their own account with their token."""
    account_id, token = await register(client)

    resp = await client.delete(
        f"/v1/accounts/{account_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204

    # Account is gone
    resp = await client.get(f"/v1/accounts/{account_id}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_account_with_admin_key(admin_client: AsyncClient):
    """Admin can delete any account using the admin key."""
    account_id, _ = await register(admin_client)

    resp = await admin_client.delete(
        f"/v1/accounts/{account_id}",
        headers={"Authorization": f"Bearer {TEST_ADMIN_KEY}"},
    )
    assert resp.status_code == 204

    resp = await admin_client.get(f"/v1/accounts/{account_id}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_account_wrong_token(client: AsyncClient):
    """A token belonging to a different account is rejected with 403."""
    account_id, _ = await register(client)
    _, other_token = await register(
        client, {**REGISTER_PAYLOAD, "email": "other@example.com"}
    )

    resp = await client.delete(
        f"/v1/accounts/{account_id}",
        headers={"Authorization": f"Bearer {other_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_delete_account_no_auth(client: AsyncClient):
    """Unauthenticated request is rejected."""
    account_id, _ = await register(client)

    resp = await client.delete(f"/v1/accounts/{account_id}")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_delete_account_invalid_token(client: AsyncClient):
    """Unknown token is rejected with 401."""
    account_id, _ = await register(client)

    resp = await client.delete(
        f"/v1/accounts/{account_id}",
        headers={"Authorization": "Bearer totally-invalid-token"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_delete_account_admin_not_found(admin_client: AsyncClient):
    """Admin gets 404 when deleting a non-existent account."""
    resp = await admin_client.delete(
        "/v1/accounts/does-not-exist",
        headers={"Authorization": f"Bearer {TEST_ADMIN_KEY}"},
    )
    assert resp.status_code == 404
