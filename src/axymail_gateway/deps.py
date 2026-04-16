from __future__ import annotations

from dataclasses import dataclass

from cryptography.fernet import Fernet
from fastapi import HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from axymail_gateway.database import get_account_by_token_hash, get_db
from axymail_gateway.services.imap_service import ImapCredentials
from axymail_gateway.services.smtp_service import SmtpCredentials
from axymail_gateway.services.token_service import decrypt, hash_token

bearer_scheme = HTTPBearer(auto_error=True)


@dataclass
class AccountRecord:
    """Resolved account with decrypted credentials."""

    account_id: str
    email: str
    created_at: str
    imap: ImapCredentials
    smtp: SmtpCredentials


async def get_account(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
) -> AccountRecord:
    """
    FastAPI dependency that:
    1. Extracts the Bearer token from the Authorization header.
    2. SHA-256-hashes it and queries the database.
    3. Decrypts stored IMAP/SMTP passwords with the app-level Fernet key.
    4. Returns a fully-populated AccountRecord.

    Raises HTTP 401 if the token is missing or invalid.
    """
    token = credentials.credentials
    token_hash = hash_token(token)

    db_path: str = request.app.state.db_path
    fernet: Fernet = request.app.state.fernet

    async with get_db(db_path) as conn:
        row = await get_account_by_token_hash(conn, token_hash)

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    imap_creds = ImapCredentials(
        host=row["imap_host"],
        port=row["imap_port"],
        user=row["imap_user"],
        password=decrypt(fernet, row["imap_password_enc"]),
        tls=bool(row["imap_tls"]),
    )
    smtp_creds = SmtpCredentials(
        host=row["smtp_host"],
        port=row["smtp_port"],
        user=row["smtp_user"],
        password=decrypt(fernet, row["smtp_password_enc"]),
        tls=bool(row["smtp_tls"]),
    )

    return AccountRecord(
        account_id=row["id"],
        email=row["email"],
        created_at=row["created_at"],
        imap=imap_creds,
        smtp=smtp_creds,
    )
