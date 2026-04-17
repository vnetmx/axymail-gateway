"""
Shared fixtures for the axymail-gateway test suite.

NOTE: ASGITransport does NOT trigger the FastAPI lifespan, so all app.state
values must be set explicitly here. Any new state added to main.py lifespan
must also be added to this fixture.
"""
from __future__ import annotations

import os
import tempfile

import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient

from axymail_gateway.database import init_db
from axymail_gateway.main import create_app

# ── Shared test credentials ──────────────────────────────────────────────────

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

TEST_ADMIN_KEY = "test-admin-key-super-secret"


# ── App fixture ───────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def client():
    """
    AsyncClient backed by an isolated temp-file SQLite DB.
    Guard is disabled. No admin key.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    key = Fernet.generate_key().decode()
    fernet = Fernet(key.encode())
    await init_db(db_path)

    app = create_app()
    app.state.db_path = db_path
    app.state.fernet = fernet
    app.state.admin_api_key = ""
    app.state.guard_config = {
        "enabled": False,
        "url": "",
        "timeout": 5.0,
        "fail_mode": "open",
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

    os.unlink(db_path)


@pytest_asyncio.fixture
async def admin_client():
    """
    AsyncClient with an admin key set — allows privileged operations.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    key = Fernet.generate_key().decode()
    fernet = Fernet(key.encode())
    await init_db(db_path)

    app = create_app()
    app.state.db_path = db_path
    app.state.fernet = fernet
    app.state.admin_api_key = TEST_ADMIN_KEY
    app.state.guard_config = {
        "enabled": False,
        "url": "",
        "timeout": 5.0,
        "fail_mode": "open",
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

    os.unlink(db_path)


@pytest_asyncio.fixture
async def guard_client_open():
    """
    AsyncClient with guard enabled + fail_mode=open.
    Guard URL points to a fake host — tests must mock scan_message_fields.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    key = Fernet.generate_key().decode()
    fernet = Fernet(key.encode())
    await init_db(db_path)

    app = create_app()
    app.state.db_path = db_path
    app.state.fernet = fernet
    app.state.admin_api_key = ""
    app.state.guard_config = {
        "enabled": True,
        "url": "http://llm-guard-test",
        "timeout": 5.0,
        "fail_mode": "open",
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

    os.unlink(db_path)


@pytest_asyncio.fixture
async def guard_client_closed():
    """
    AsyncClient with guard enabled + fail_mode=closed.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    key = Fernet.generate_key().decode()
    fernet = Fernet(key.encode())
    await init_db(db_path)

    app = create_app()
    app.state.db_path = db_path
    app.state.fernet = fernet
    app.state.admin_api_key = ""
    app.state.guard_config = {
        "enabled": True,
        "url": "http://llm-guard-test",
        "timeout": 5.0,
        "fail_mode": "closed",
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

    os.unlink(db_path)


# ── Helper ────────────────────────────────────────────────────────────────────

async def register(ac: AsyncClient, payload: dict | None = None) -> tuple[str, str]:
    """Register an account and return (account_id, token)."""
    resp = await ac.post("/v1/accounts", json=payload or REGISTER_PAYLOAD)
    assert resp.status_code == 201, resp.text
    data = resp.json()
    return data["account_id"], data["token"]
