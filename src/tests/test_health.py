"""
Tests for health check endpoints: /health, /healthz, /readyz.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_healthz_always_200(client: AsyncClient):
    """/healthz returns 200 as long as the process is alive."""
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_healthz_contains_version(client: AsyncClient):
    resp = await client.get("/healthz")
    assert "version" in resp.json()


@pytest.mark.asyncio
async def test_readyz_with_healthy_db(client: AsyncClient):
    """/readyz returns 200 when the database is reachable."""
    resp = await client.get("/readyz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ready"


@pytest.mark.asyncio
async def test_health_full_report(client: AsyncClient):
    """/health returns full status report with component breakdown."""
    resp = await client.get("/health")
    assert resp.status_code == 200

    data = resp.json()
    assert data["status"] == "ok"
    assert "version" in data
    assert "uptime_seconds" in data
    assert "components" in data
    assert data["components"]["database"]["status"] == "ok"


@pytest.mark.asyncio
async def test_health_uptime_is_positive(client: AsyncClient):
    resp = await client.get("/health")
    assert resp.json()["uptime_seconds"] >= 0


@pytest.mark.asyncio
async def test_readyz_db_unreachable(client: AsyncClient):
    """/readyz returns 503 when the database cannot be reached."""
    from unittest.mock import patch, AsyncMock
    import aiosqlite

    with patch(
        "axymail_gateway.router.health._check_db",
        new=AsyncMock(return_value=(False, "unable to open database")),
    ):
        resp = await client.get("/readyz")

    assert resp.status_code == 503
    assert resp.json()["status"] == "not_ready"
    assert "unable to open" in resp.json()["reason"]


@pytest.mark.asyncio
async def test_health_degraded_when_db_unreachable(client: AsyncClient):
    """/health returns 503 and degraded status when DB is down."""
    from unittest.mock import patch, AsyncMock

    with patch(
        "axymail_gateway.router.health._check_db",
        new=AsyncMock(return_value=(False, "disk I/O error")),
    ):
        resp = await client.get("/health")

    assert resp.status_code == 503
    data = resp.json()
    assert data["status"] == "degraded"
    assert data["components"]["database"]["status"] == "error"
