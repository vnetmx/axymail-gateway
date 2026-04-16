from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from axymail_gateway.database import get_account_by_id, get_db
from axymail_gateway.deps import AccountRecord, get_account
from axymail_gateway.models import Mailbox
from axymail_gateway.services.imap_service import list_mailboxes

router = APIRouter(tags=["mailboxes"])


@router.get(
    "/accounts/{account_id}/mailboxes",
    response_model=list[Mailbox],
    summary="List IMAP folders for an account",
)
async def get_mailboxes(
    account_id: str,
    request: Request,
    account: AccountRecord = Depends(get_account),
) -> list[Mailbox]:
    """
    The caller must own the account referenced by *account_id*.
    The bearer token identifies the account; if *account_id* does not match
    the token's account we return 403.
    """
    if account.account_id != account_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token does not belong to this account.",
        )

    try:
        folders = await list_mailboxes(account.imap)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"IMAP error: {exc}",
        ) from exc

    return [Mailbox(path=f["path"], name=f["name"]) for f in folders]
