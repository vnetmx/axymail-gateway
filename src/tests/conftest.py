from __future__ import annotations

import tempfile
import os
import pytest
import pytest_asyncio

from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient

from axymail_gateway.database import init_db
from axymail_gateway.main import create_app


@pytest_asyncio.fixture
async def client():
    """
    Provide an httpx.AsyncClient backed by a fresh in-memory (temp file) SQLite
    database and a known Fernet key so tests are fully isolated.
    """
    # Use a temporary file — aiosqlite does not support :memory: well across
    # multiple connections in the same process.
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    key = Fernet.generate_key().decode()
    fernet = Fernet(key.encode())

    await init_db(db_path)

    app = create_app()

    # Pre-populate app state before the lifespan runs so we control the DB.
    # We monkey-patch the lifespan by setting state directly on the app.
    app.state.db_path = db_path
    app.state.fernet = fernet

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    os.unlink(db_path)
