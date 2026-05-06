"""
Google OAuth 2.0 service for Gmail XOAUTH2 IMAP/SMTP authentication.

Flow:
  1. build_auth_url()         → redirect the user to Google consent screen
  2. exchange_code()          → trade the auth code for access + refresh tokens
  3. refresh_access_token()   → get a new access token using the refresh token
  4. build_xoauth2_string()   → build the base64 SASL XOAUTH2 payload used by
                                both aioimaplib (AUTHENTICATE) and aiosmtplib (AUTH)

References:
  https://developers.google.com/workspace/gmail/imap/xoauth2-protocol
  https://developers.google.com/identity/protocols/oauth2/web-server
"""
from __future__ import annotations

import base64
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import TypedDict

import httpx

# ── Google OAuth endpoints ───────────────────────────────────────────────────
_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
_TOKEN_URL = "https://oauth2.googleapis.com/token"
_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"

# Full IMAP + SMTP access scope (XOAUTH2) + email identity
_GMAIL_SCOPE = "https://mail.google.com/ openid email"


# ── Public types ─────────────────────────────────────────────────────────────

class OAuthTokens(TypedDict):
    access_token: str
    refresh_token: str
    expires_at: str   # ISO-8601 UTC — when the access token expires
    email: str        # resolved from Google userinfo


# ── Auth URL ─────────────────────────────────────────────────────────────────

def build_auth_url(
    client_id: str,
    redirect_uri: str,
    state: str | None = None,
) -> str:
    """
    Build the Google OAuth consent URL to redirect the user to.

    ``state`` is an opaque string returned verbatim in the callback —
    useful for correlating requests (e.g. session ID, intended account).
    """
    params: dict[str, str] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": _GMAIL_SCOPE,
        "access_type": "offline",   # request a refresh_token
        "prompt": "consent",        # always show consent to guarantee refresh_token
    }
    if state:
        params["state"] = state
    return f"{_AUTH_URL}?{urllib.parse.urlencode(params)}"


# ── Code exchange ─────────────────────────────────────────────────────────────

async def exchange_code(
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
) -> OAuthTokens:
    """
    Exchange an authorization code for access + refresh tokens.
    Also resolves the user's email address via the userinfo endpoint.

    Raises ``ValueError`` if the exchange fails or no refresh token is returned
    (which can happen when ``prompt=consent`` is missing from the auth URL).
    """
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            _TOKEN_URL,
            data={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
        )
        resp.raise_for_status()
        data = resp.json()

    if "refresh_token" not in data:
        raise ValueError(
            "Google did not return a refresh_token. "
            "Revoke app access at https://myaccount.google.com/permissions and try again."
        )

    access_token: str = data["access_token"]
    refresh_token: str = data["refresh_token"]
    expires_in: int = data.get("expires_in", 3600)
    expires_at = _expiry_timestamp(expires_in)

    email = await _resolve_email(access_token)
    return OAuthTokens(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=expires_at,
        email=email,
    )


# ── Token refresh ─────────────────────────────────────────────────────────────

async def refresh_access_token(
    refresh_token: str,
    client_id: str,
    client_secret: str,
) -> tuple[str, str]:
    """
    Obtain a new access token using the stored refresh token.

    Returns ``(new_access_token, new_expires_at_iso)``.
    Raises ``httpx.HTTPStatusError`` on failure (e.g. refresh token revoked).
    """
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            _TOKEN_URL,
            data={
                "refresh_token": refresh_token,
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "refresh_token",
            },
        )
        resp.raise_for_status()
        data = resp.json()

    access_token: str = data["access_token"]
    expires_in: int = data.get("expires_in", 3600)
    return access_token, _expiry_timestamp(expires_in)


# ── XOAUTH2 payload ──────────────────────────────────────────────────────────

def build_xoauth2_string(email: str, access_token: str) -> str:
    """
    Build the base64-encoded XOAUTH2 SASL string used for Gmail IMAP/SMTP auth.

    Format (before base64):
        "user=<email>\\x01auth=Bearer <access_token>\\x01\\x01"

    References:
        https://developers.google.com/workspace/gmail/imap/xoauth2-protocol
    """
    raw = f"user={email}\x01auth=Bearer {access_token}\x01\x01"
    return base64.b64encode(raw.encode()).decode()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _expiry_timestamp(expires_in_seconds: int) -> str:
    """Return ISO-8601 UTC timestamp for when the access token will expire."""
    return (
        datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds)
    ).isoformat()


def is_token_expired(expires_at_iso: str, buffer_seconds: int = 300) -> bool:
    """
    Return True if the access token expires within ``buffer_seconds`` (default 5 min).
    Treats a missing/unparseable expiry as expired.
    """
    try:
        expiry = datetime.fromisoformat(expires_at_iso)
        # Ensure timezone-aware comparison
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) >= expiry - timedelta(seconds=buffer_seconds)
    except Exception:
        return True


async def _resolve_email(access_token: str) -> str:
    """Fetch the authenticated user's email from Google userinfo endpoint."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            _USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        resp.raise_for_status()
        return resp.json().get("email", "")
