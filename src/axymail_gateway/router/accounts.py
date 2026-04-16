from __future__ import annotations

from datetime import datetime, timezone

from cryptography.fernet import Fernet
from fastapi import APIRouter, HTTPException, Request, status

from axymail_gateway.database import (
    delete_account,
    get_account_by_id,
    get_db,
    insert_account,
    list_accounts,
)
from axymail_gateway.models import (
    AccountInfo,
    RegisterAccountRequest,
    RegisterAccountResponse,
)
from axymail_gateway.services.token_service import (
    decrypt,
    encrypt,
    generate_account_id,
    generate_token,
    hash_token,
)

router = APIRouter(prefix="/accounts", tags=["accounts"])


@router.post(
    "",
    response_model=RegisterAccountResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new mail account",
)
async def register_account(
    body: RegisterAccountRequest,
    request: Request,
) -> RegisterAccountResponse:
    """
    Store IMAP + SMTP credentials encrypted at rest.
    Returns a **one-time** bearer token — it is never stored in plaintext.
    """
    db_path: str = request.app.state.db_path
    fernet: Fernet = request.app.state.fernet

    token = generate_token()
    account_id = generate_account_id()
    created_at = datetime.now(timezone.utc).isoformat()

    record = {
        "id": account_id,
        "token_hash": hash_token(token),
        "email": body.email,
        "imap_host": body.imap.host,
        "imap_port": body.imap.port,
        "imap_user": body.imap.user,
        "imap_password_enc": encrypt(fernet, body.imap.password),
        "imap_tls": int(body.imap.tls),
        "smtp_host": body.smtp.host,
        "smtp_port": body.smtp.port,
        "smtp_user": body.smtp.user,
        "smtp_password_enc": encrypt(fernet, body.smtp.password),
        "smtp_tls": int(body.smtp.tls),
        "created_at": created_at,
    }

    async with get_db(db_path) as conn:
        await insert_account(conn, record)

    return RegisterAccountResponse(
        account_id=account_id,
        token=token,
        email=body.email,
    )


@router.get(
    "",
    response_model=list[AccountInfo],
    summary="List all registered accounts",
)
async def list_all_accounts(request: Request) -> list[AccountInfo]:
    db_path: str = request.app.state.db_path
    async with get_db(db_path) as conn:
        rows = await list_accounts(conn)
    return [
        AccountInfo(account_id=row["id"], email=row["email"], created_at=row["created_at"])
        for row in rows
    ]


@router.get(
    "/{account_id}",
    response_model=AccountInfo,
    summary="Get account info by ID",
)
async def get_account_info(account_id: str, request: Request) -> AccountInfo:
    db_path: str = request.app.state.db_path
    async with get_db(db_path) as conn:
        row = await get_account_by_id(conn, account_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found.")
    return AccountInfo(account_id=row["id"], email=row["email"], created_at=row["created_at"])


@router.delete(
    "/{account_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an account",
)
async def remove_account(account_id: str, request: Request) -> None:
    db_path: str = request.app.state.db_path
    async with get_db(db_path) as conn:
        deleted = await delete_account(conn, account_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found.")
