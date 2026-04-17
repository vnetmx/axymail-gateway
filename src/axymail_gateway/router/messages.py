from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from axymail_gateway.deps import AccountRecord, get_account
from axymail_gateway.models import FullMessage, MessageListItem, UpdateFlagsRequest
from axymail_gateway.services import imap_service
from axymail_gateway.services.sanitizer import (
    sanitize_message,
    sanitize_message_summary,
    sanitize_message_summary_with_guard,
    sanitize_message_with_guard,
)

router = APIRouter(tags=["messages"])

_GUARD_UNAVAILABLE_DETAIL = (
    "Content guard service is unavailable and GUARD_FAIL_MODE=closed. "
    "Cannot serve unvalidated content."
)


def _assert_owner(account: AccountRecord, account_id: str) -> None:
    if account.account_id != account_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token does not belong to this account.",
        )


def _guard_config(request: Request) -> dict | None:
    """Return guard service config from app state, or None if disabled."""
    cfg = getattr(request.app.state, "guard_config", None)
    if cfg and cfg.get("enabled") and cfg.get("url"):
        return cfg
    return None


@router.get(
    "/accounts/{account_id}/messages",
    response_model=list[MessageListItem],
    summary="List messages in a mailbox",
    description=(
        "List messages with optional **server-side filtering** (IMAP SEARCH) "
        "and **client-side sorting**.\n\n"
        "Filters are evaluated on the IMAP server before any data is "
        "transferred, so they are efficient even on large mailboxes.  "
        "Sorting fetches all matching headers then sorts in Python — "
        "use filters to narrow the result set when sorting large folders."
    ),
)
async def list_messages(
    request: Request,
    account_id: str,
    account: AccountRecord = Depends(get_account),
    # Pagination
    mailbox: str = Query("INBOX", description="IMAP folder path"),
    page: int = Query(0, ge=0, description="Zero-based page index"),
    page_size: int = Query(20, ge=1, le=100, description="Messages per page"),
    # Filters
    q: str | None = Query(None, description="Free-text search in subject OR sender"),
    subject: str | None = Query(None, description="Subject contains"),
    from_addr: str | None = Query(None, alias="from", description="Sender contains"),
    since: str | None = Query(None, description="Messages on or after date (YYYY-MM-DD)"),
    before: str | None = Query(None, description="Messages before date (YYYY-MM-DD)"),
    seen: bool | None = Query(None, description="true = read only, false = unread only"),
    flagged: bool | None = Query(None, description="true = flagged only, false = unflagged only"),
    # Sort
    sort_by: str | None = Query(None, description="Sort field: date | subject | from | size"),
    sort_order: str = Query("desc", description="Sort direction: asc | desc"),
    sort_max: int = Query(500, ge=1, le=2000, description="Max messages to fetch when sorting (default 500)"),
    # Sanitization
    sanitize: bool = Query(True, description="Sanitize content against XSS and prompt injection"),
) -> list[MessageListItem]:
    _assert_owner(account, account_id)

    try:
        msgs = await imap_service.list_messages(
            account.imap,
            mailbox=mailbox,
            page=page,
            page_size=page_size,
            q=q,
            subject=subject,
            from_addr=from_addr,
            since=since,
            before=before,
            seen=seen,
            flagged=flagged,
            sort_by=sort_by,
            sort_order=sort_order,
            sort_max=sort_max,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"IMAP error: {exc}",
        ) from exc

    guard = _guard_config(request) if sanitize else None
    result = []
    for m in msgs:
        warnings: list[str] = []
        if sanitize:
            if guard:
                m, warnings, reachable = await sanitize_message_summary_with_guard(
                    m,
                    guard_url=guard["url"],
                    guard_timeout=guard["timeout"],
                )
                if not reachable and guard.get("fail_mode") == "closed":
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail=_GUARD_UNAVAILABLE_DETAIL,
                    )
            else:
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
    request: Request,
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
        guard = _guard_config(request)
        if guard:
            msg, warnings, reachable = await sanitize_message_with_guard(
                msg,
                guard_url=guard["url"],
                guard_timeout=guard["timeout"],
            )
            if not reachable and guard.get("fail_mode") == "closed":
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=_GUARD_UNAVAILABLE_DETAIL,
                )
        else:
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
