from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from axymail_gateway.deps import AccountRecord, get_account
from axymail_gateway.models import FullMessage, MessageListItem, UpdateFlagsRequest
from axymail_gateway.services import imap_service
from axymail_gateway.services.sanitizer import sanitize_message, sanitize_message_summary

router = APIRouter(tags=["messages"])


def _assert_owner(account: AccountRecord, account_id: str) -> None:
    if account.account_id != account_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token does not belong to this account.",
        )


@router.get(
    "/accounts/{account_id}/messages",
    response_model=list[MessageListItem],
    summary="List messages in a mailbox",
)
async def list_messages(
    account_id: str,
    account: AccountRecord = Depends(get_account),
    mailbox: str = Query("INBOX", description="IMAP folder path"),
    page: int = Query(0, ge=0, description="Zero-based page index"),
    page_size: int = Query(20, ge=1, le=100, description="Messages per page"),
    sanitize: bool = Query(True, description="Sanitize content against XSS and prompt injection"),
) -> list[MessageListItem]:
    _assert_owner(account, account_id)

    try:
        msgs = await imap_service.list_messages(
            account.imap, mailbox=mailbox, page=page, page_size=page_size
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"IMAP error: {exc}",
        ) from exc

    result = []
    for m in msgs:
        warnings: list[str] = []
        if sanitize:
            m, warnings = sanitize_message_summary(m)
        result.append(
            MessageListItem(
                uid=m["uid"],
                subject=m.get("subject"),
                **{"from": m.get("from")},
                to=m.get("to", []),
                date=m.get("date"),
                seen=m.get("seen", False),
                flagged=m.get("flagged", False),
                size=m.get("size"),
                sanitized_warnings=warnings,
            )
        )
    return result


@router.get(
    "/accounts/{account_id}/messages/{uid}",
    response_model=FullMessage,
    summary="Fetch a single message by UID",
)
async def get_message(
    account_id: str,
    uid: int,
    account: AccountRecord = Depends(get_account),
    mailbox: str = Query("INBOX"),
    sanitize: bool = Query(True, description="Sanitize content against XSS and prompt injection"),
) -> FullMessage:
    _assert_owner(account, account_id)

    try:
        msg = await imap_service.get_message(account.imap, uid=uid, mailbox=mailbox)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"IMAP error: {exc}",
        ) from exc

    if msg is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found.")

    warnings: list[str] = []
    if sanitize:
        msg, warnings = sanitize_message(msg)

    return FullMessage(
        uid=msg["uid"],
        subject=msg.get("subject"),
        **{"from": msg.get("from")},
        to=msg.get("to", []),
        cc=msg.get("cc", []),
        date=msg.get("date"),
        seen=msg.get("seen", False),
        flagged=msg.get("flagged", False),
        text=msg.get("text"),
        html=msg.get("html"),
        attachments=msg.get("attachments", []),
        sanitized_warnings=warnings,
    )


@router.put(
    "/accounts/{account_id}/messages/{uid}",
    response_model=FullMessage,
    summary="Update flags on a message",
)
async def update_message_flags(
    account_id: str,
    uid: int,
    body: UpdateFlagsRequest,
    account: AccountRecord = Depends(get_account),
    mailbox: str = Query("INBOX"),
) -> FullMessage:
    _assert_owner(account, account_id)

    try:
        await imap_service.set_flags(
            account.imap,
            uid=uid,
            seen=body.seen,
            flagged=body.flagged,
            mailbox=mailbox,
        )
        msg = await imap_service.get_message(account.imap, uid=uid, mailbox=mailbox)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"IMAP error: {exc}",
        ) from exc

    if msg is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found.")

    return FullMessage(
        uid=msg["uid"],
        subject=msg.get("subject"),
        **{"from": msg.get("from")},
        to=msg.get("to", []),
        cc=msg.get("cc", []),
        date=msg.get("date"),
        seen=msg.get("seen", False),
        flagged=msg.get("flagged", False),
        text=msg.get("text"),
        html=msg.get("html"),
        attachments=msg.get("attachments", []),
    )


@router.delete(
    "/accounts/{account_id}/messages/{uid}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a message by UID",
)
async def delete_message(
    account_id: str,
    uid: int,
    account: AccountRecord = Depends(get_account),
    mailbox: str = Query("INBOX"),
) -> None:
    _assert_owner(account, account_id)

    try:
        deleted = await imap_service.delete_message(account.imap, uid=uid, mailbox=mailbox)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"IMAP error: {exc}",
        ) from exc

    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found.")
