"""
Health check endpoints.

  GET /health   — full breakdown: status + component health (DB, version)
  GET /healthz  — simple liveness probe (200 if the process is alive)
  GET /readyz   — readiness probe (200 only when the DB is reachable)

All three are excluded from OTel tracing and Prometheus metrics to avoid noise.
"""
from __future__ import annotations

import time

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse

from axymail_gateway import __version__
from axymail_gateway.database import get_db

router = APIRouter(tags=["observability"])

# Record startup time for uptime reporting
_STARTED_AT = time.time()


async def _check_db(db_path: str) -> tuple[bool, str]:
    """Run a trivial query against the SQLite database. Returns (ok, error_msg)."""
    try:
        async with get_db(db_path) as conn:
            await conn.execute("SELECT 1")
        return True, ""
    except Exception as exc:
        return False, str(exc)


# ── /health ───────────────────────────────────────────────────────────────────

@router.get(
    "/health",
    summary="Full health check",
    description=(
        "Returns the health of the service and all its components. "
        "HTTP 200 when fully healthy, 503 when any component is degraded."
    ),
    response_description="Service health report",
)
async def health(request: Request) -> JSONResponse:
    db_path: str = request.app.state.db_path
    db_ok, db_error = await _check_db(db_path)

    components: dict = {
        "database": {"status": "ok"} if db_ok else {"status": "error", "error": db_error},
    }

    overall_ok = db_ok
    http_status = status.HTTP_200_OK if overall_ok else status.HTTP_503_SERVICE_UNAVAILABLE

    return JSONResponse(
        status_code=http_status,
        content={
            "status": "ok" if overall_ok else "degraded",
            "version": __version__,
            "uptime_seconds": round(time.time() - _STARTED_AT, 1),
            "components": components,
        },
    )


# ── /healthz — liveness ───────────────────────────────────────────────────────

@router.get(
    "/healthz",
    summary="Liveness probe",
    description="Returns 200 as long as the process is running. Suitable for k8s livenessProbe.",
    include_in_schema=False,
)
async def healthz() -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"status": "ok", "version": __version__},
    )


# ── /readyz — readiness ───────────────────────────────────────────────────────

@router.get(
    "/readyz",
    summary="Readiness probe",
    description=(
        "Returns 200 when the service is ready to serve traffic (DB reachable). "
        "Returns 503 if the database is unavailable. "
        "Suitable for k8s readinessProbe."
    ),
    include_in_schema=False,
)
async def readyz(request: Request) -> JSONResponse:
    db_path: str = request.app.state.db_path
    db_ok, db_error = await _check_db(db_path)

    if db_ok:
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"status": "ready"},
        )

    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"status": "not_ready", "reason": db_error},
    )
