"""
OAuth 2.0 router — multi-provider Gmail XOAUTH2.

Provider management:
  POST   /v1/oauth/providers              → register a new OAuth provider
  GET    /v1/oauth/providers              → list providers (no secrets)
  DELETE /v1/oauth/providers/{name}       → remove a provider

Per-provider OAuth flow:
  GET /v1/oauth/{provider_name}/authorize → returns Google consent URL
  GET /v1/oauth/{provider_name}/callback  → handles redirect, registers account
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from cryptography.fernet import Fernet
from fastapi import APIRouter, HTTPException, Query, Request, status

from axymail_gateway.database import (
    delete_provider,
    get_db,
    get_provider_by_name,
    insert_account,
    insert_provider,
    list_providers,
)
from axymail_gateway.models import (
    OAuthAuthorizeResponse,
    ProviderInfo,
    RegisterAccountResponse,
    RegisterProviderRequest,
    RegisterProviderResponse,
)
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


# ---------------------------------------------------------------------------
# Provider management
# ---------------------------------------------------------------------------

@router.post(
    "/providers",
    response_model=RegisterProviderResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register an OAuth provider",
    description=(
        "Register a Google OAuth 2.0 app (one per Google organization). "
        "The `name` becomes the URL slug used in the authorize/callback endpoints. "
        "The `client_secret` is stored encrypted and never returned after registration."
    ),
)
async def create_provider(
    body: RegisterProviderRequest,
    request: Request,
) -> RegisterProviderResponse:
    fernet: Fernet = request.app.state.fernet
    db_path: str = request.app.state.db_path

    async with get_db(db_path) as conn:
        existing = await get_provider_by_name(conn, body.name)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Provider '{body.name}' already exists.",
            )
        await insert_provider(conn, {
            "name": body.name,
            "client_id": body.client_id,
            "client_secret_enc": encrypt(fernet, body.client_secret),
            "redirect_uri": body.redirect_uri,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

    logger.info("OAuth provider registered: %s", body.name)
    return RegisterProviderResponse(
        name=body.name,
        redirect_uri=body.redirect_uri,
    )


@router.get(
    "/providers",
    response_model=list[ProviderInfo],
    summary="List OAuth providers",
)
async def get_providers(request: Request) -> list[ProviderInfo]:
    db_path: str = request.app.state.db_path
    async with get_db(db_path) as conn:
        rows = await list_providers(conn)
    return [ProviderInfo(**row) for row in rows]


@router.delete(
    "/providers/{name}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an OAuth provider",
    description=(
        "Removes the provider. Existing accounts that used this provider will "
        "no longer be able to refresh their tokens."
    ),
)
async def remove_provider(name: str, request: Request) -> None:
    db_path: str = request.app.state.db_path
    async with get_db(db_path) as conn:
        deleted = await delete_provider(conn, name)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Provider '{name}' not found.",
        )


# ---------------------------------------------------------------------------
# OAuth flow (per provider)
# ---------------------------------------------------------------------------

@router.get(
    "/{provider_name}/authorize",
    response_model=OAuthAuthorizeResponse,
    summary="Start OAuth flow for a provider",
    description=(
        "Returns the Google consent URL for the given provider. "
        "Redirect the user to `auth_url` — after granting access Google will "
        "redirect them to the provider's registered `redirect_uri`."
    ),
)
async def authorize(
    provider_name: str,
    request: Request,
    state: str | None = Query(
        default=None,
        description="Optional opaque string returned verbatim in the callback.",
    ),
) -> OAuthAuthorizeResponse:
    db_path: str = request.app.state.db_path
    async with get_db(db_path) as conn:
        provider = await get_provider_by_name(conn, provider_name)
    if not provider:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Provider '{provider_name}' not found.",
        )

    auth_url = build_auth_url(
        client_id=provider["client_id"],
        redirect_uri=provider["redirect_uri"],
        state=state,
    )
    return OAuthAuthorizeResponse(auth_url=auth_url)


@router.get(
    "/{provider_name}/callback",
    response_model=RegisterAccountResponse,
    summary="OAuth callback — registers the account",
    description=(
        "Google redirects here after the user grants access. "
        "Exchanges the authorization code for tokens, resolves the Gmail address, "
        "and registers a new account — returning the same `account_id` + `token` "
        "shape as password-based registration."
    ),
)
async def callback(
    provider_name: str,
    request: Request,
    code: str = Query(..., description="Authorization code from Google."),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
) -> RegisterAccountResponse:
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Google OAuth error: {error}",
        )

    db_path: str = request.app.state.db_path
    fernet: Fernet = request.app.state.fernet

    async with get_db(db_path) as conn:
        provider = await get_provider_by_name(conn, provider_name)
    if not provider:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Provider '{provider_name}' not found.",
        )

    client_secret = decrypt_secret(fernet, provider["client_secret_enc"])

    try:
        tokens = await exchange_code(
            code=code,
            client_id=provider["client_id"],
            client_secret=client_secret,
            redirect_uri=provider["redirect_uri"],
        )
    except Exception as exc:
        logger.exception("OAuth code exchange failed for provider '%s'", provider_name)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to exchange authorization code: {exc}",
        ) from exc

    account_id = generate_account_id()
    token = generate_token()
    empty_enc = encrypt(fernet, "")

    record = {
        "id": account_id,
        "token_hash": hash_token(token),
        "email": tokens["email"],
        "imap_host": _GMAIL_IMAP_HOST,
        "imap_port": _GMAIL_IMAP_PORT,
        "imap_user": tokens["email"],
        "imap_password_enc": empty_enc,
        "imap_tls": 1,
        "smtp_host": _GMAIL_SMTP_HOST,
        "smtp_port": _GMAIL_SMTP_PORT,
        "smtp_user": tokens["email"],
        "smtp_password_enc": empty_enc,
        "smtp_tls": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "auth_type": "oauth",
        "oauth_provider": provider_name,
        "oauth_access_token_enc": encrypt(fernet, tokens["access_token"]),
        "oauth_refresh_token_enc": encrypt(fernet, tokens["refresh_token"]),
        "oauth_token_expiry": tokens["expires_at"],
    }

    async with get_db(db_path) as conn:
        await insert_account(conn, record)

    logger.info(
        "OAuth account registered: %s (%s) via provider '%s'",
        account_id, tokens["email"], provider_name,
    )
    return RegisterAccountResponse(
        account_id=account_id,
        token=token,
        email=tokens["email"],
    )


def decrypt_secret(fernet: Fernet, enc: str) -> str:
    """Thin wrapper so imports stay clean."""
    from axymail_gateway.services.token_service import decrypt
    return decrypt(fernet, enc)
