"""
OAuth 2.0 router — Gmail XOAUTH2 account registration.

Endpoints:
  GET /v1/oauth/gmail/authorize   → returns the Google consent URL
  GET /v1/oauth/gmail/callback    → handles the redirect, registers the account
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from cryptography.fernet import Fernet
from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse

from axymail_gateway.config import settings
from axymail_gateway.database import get_db, insert_account
from axymail_gateway.models import OAuthAuthorizeResponse, RegisterAccountResponse
from axymail_gateway.services.oauth_service import build_auth_url, exchange_code
from axymail_gateway.services.token_service import (
    encrypt,
    generate_account_id,
    generate_token,
    hash_token,
)

logger = logging.getLogger("axymail_gateway.oauth")

router = APIRouter(prefix="/oauth", tags=["OAuth"])

# Gmail IMAP / SMTP defaults
_GMAIL_IMAP_HOST = "imap.gmail.com"
_GMAIL_IMAP_PORT = 993
_GMAIL_SMTP_HOST = "smtp.gmail.com"
_GMAIL_SMTP_PORT = 587


def _oauth_not_configured() -> bool:
    return not settings.google_client_id or not settings.google_client_secret


@router.get(
    "/gmail/authorize",
    response_model=OAuthAuthorizeResponse,
    summary="Start Gmail OAuth flow",
    description=(
        "Returns a Google OAuth consent URL. "
        "Redirect the user to `auth_url` — after granting access Google will "
        "redirect them to the configured callback URI."
    ),
)
async def gmail_authorize(
    state: str | None = Query(
        default=None,
        description="Optional opaque string returned verbatim in the callback.",
    ),
) -> OAuthAuthorizeResponse:
    if _oauth_not_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Google OAuth is not configured. "
                "Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables."
            ),
        )

    auth_url = build_auth_url(
        client_id=settings.google_client_id,
        redirect_uri=settings.google_redirect_uri,
        state=state,
    )
    return OAuthAuthorizeResponse(auth_url=auth_url)


@router.get(
    "/gmail/callback",
    response_model=RegisterAccountResponse,
    summary="Gmail OAuth callback",
    description=(
        "Google redirects here after the user grants access. "
        "Exchanges the authorization code for tokens, resolves the Gmail address, "
        "and registers a new account — returning an `account_id` and `token` "
        "identical in shape to the password-based registration response."
    ),
)
async def gmail_callback(
    request: Request,
    code: str = Query(..., description="Authorization code from Google."),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None, description="Set by Google on denial."),
) -> RegisterAccountResponse:
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Google OAuth error: {error}",
        )

    if _oauth_not_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google OAuth is not configured on this server.",
        )

    # Exchange code for tokens
    try:
        tokens = await exchange_code(
            code=code,
            client_id=settings.google_client_id,
            client_secret=settings.google_client_secret,
            redirect_uri=settings.google_redirect_uri,
        )
    except Exception as exc:
        logger.exception("OAuth code exchange failed")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to exchange authorization code: {exc}",
        ) from exc

    fernet: Fernet = request.app.state.fernet
    db_path: str = request.app.state.db_path

    account_id = generate_account_id()
    token = generate_token()

    # OAuth accounts have no IMAP/SMTP password — store empty encrypted strings.
    empty_enc = encrypt(fernet, "")

    record = {
        "id": account_id,
        "token_hash": hash_token(token),
        "email": tokens["email"],
        # IMAP — Gmail defaults
        "imap_host": _GMAIL_IMAP_HOST,
        "imap_port": _GMAIL_IMAP_PORT,
        "imap_user": tokens["email"],
        "imap_password_enc": empty_enc,
        "imap_tls": 1,
        # SMTP — Gmail defaults
        "smtp_host": _GMAIL_SMTP_HOST,
        "smtp_port": _GMAIL_SMTP_PORT,
        "smtp_user": tokens["email"],
        "smtp_password_enc": empty_enc,
        "smtp_tls": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        # OAuth fields
        "auth_type": "oauth",
        "oauth_provider": "google",
        "oauth_access_token_enc": encrypt(fernet, tokens["access_token"]),
        "oauth_refresh_token_enc": encrypt(fernet, tokens["refresh_token"]),
        "oauth_token_expiry": tokens["expires_at"],
    }

    async with get_db(db_path) as conn:
        await insert_account(conn, record)

    logger.info("OAuth account registered: %s (%s)", account_id, tokens["email"])

    return RegisterAccountResponse(
        account_id=account_id,
        token=token,
        email=tokens["email"],
    )
