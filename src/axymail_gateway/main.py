from __future__ import annotations

import logging
import secrets
from contextlib import asynccontextmanager

from cryptography.fernet import Fernet
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware

from axymail_gateway.config import settings
from axymail_gateway.database import init_db
from axymail_gateway.router import accounts, mailboxes, messages, send
from axymail_gateway.router import admin, health
from axymail_gateway.telemetry import setup_metrics, setup_tracing

logger = logging.getLogger("axymail_gateway")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise shared state on startup, clean up on shutdown."""
    key = settings.get_encryption_key()
    if not settings.encryption_key:
        logger.warning(
            "ENCRYPTION_KEY not set — using an ephemeral key. "
            "All stored credentials will be unreadable after restart."
        )

    await init_db(settings.db_path)

    app.state.db_path = settings.db_path
    app.state.fernet = Fernet(key.encode())
    app.state.admin_api_key = settings.admin_api_key
    app.state.guard_config = {
        "enabled": settings.guard_enabled,
        "url": settings.guard_service_url,
        "timeout": settings.guard_timeout,
        "max_chunk_size": settings.guard_max_chunk_size,
    }

    logger.info("axymail-gateway started. DB: %s", settings.db_path)
    yield
    logger.info("axymail-gateway shutting down.")


def create_app() -> FastAPI:
    # Session signing key — ephemeral if not configured (sessions lost on restart)
    session_secret = settings.secret_key or secrets.token_hex(32)
    if not settings.secret_key:
        logger.warning(
            "SECRET_KEY not set — admin sessions are ephemeral and won't survive restarts."
        )

    app = FastAPI(
        title="axymail-gateway",
        description="Self-hosted IMAP/SMTP REST API gateway.",
        version="0.1.0",
        lifespan=lifespan,
    )

    # ── Middleware ────────────────────────────────────────────────────────────
    app.add_middleware(
        SessionMiddleware,
        secret_key=session_secret,
        session_cookie="amgw_session",
        same_site="strict",
        https_only=False,  # set True behind TLS in production
    )

    # ── API routers ───────────────────────────────────────────────────────────
    app.include_router(accounts.router, prefix="/v1")
    app.include_router(mailboxes.router, prefix="/v1")
    app.include_router(messages.router, prefix="/v1")
    app.include_router(send.router, prefix="/v1")

    # ── Admin dashboard ───────────────────────────────────────────────────────
    app.include_router(admin.router)

    # ── Observability ─────────────────────────────────────────────────────────
    app.include_router(health.router)

    if settings.otel_enabled:
        setup_tracing(
            app,
            service_name=settings.otel_service_name,
            otlp_endpoint=settings.otel_exporter_otlp_endpoint,
        )

    if settings.prometheus_enabled:
        setup_metrics(app)

    # ── Exception handlers ────────────────────────────────────────────────────

    @app.exception_handler(404)
    async def not_found_handler(request: Request, exc) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"detail": "Resource not found."},
        )

    @app.exception_handler(401)
    async def unauthorized_handler(request: Request, exc) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Unauthorized."},
            headers={"WWW-Authenticate": "Bearer"},
        )

    @app.exception_handler(500)
    async def internal_error_handler(request: Request, exc) -> JSONResponse:
        logger.exception("Unhandled error on %s %s", request.method, request.url)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error."},
        )

    return app


app = create_app()


def run() -> None:
    """Entry point for the `axymail-gateway` CLI command."""
    import uvicorn

    uvicorn.run(
        "axymail_gateway.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
    )


if __name__ == "__main__":
    run()
