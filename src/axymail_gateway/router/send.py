from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from axymail_gateway.deps import AccountRecord, get_account
from axymail_gateway.models import SendEmailRequest, SendEmailResponse
from axymail_gateway.services.smtp_service import send_email

router = APIRouter(tags=["send"])


@router.post(
    "/accounts/{account_id}/send",
    response_model=SendEmailResponse,
    status_code=status.HTTP_200_OK,
    summary="Send an email via SMTP",
)
async def send(
    account_id: str,
    body: SendEmailRequest,
    account: AccountRecord = Depends(get_account),
) -> SendEmailResponse:
    if account.account_id != account_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token does not belong to this account.",
        )

    try:
        await send_email(
            creds=account.smtp,
            from_addr=account.email,
            to=body.to,
            cc=body.cc,
            bcc=body.bcc,
            subject=body.subject,
            text=body.text,
            html=body.html,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"SMTP error: {exc}",
        ) from exc

    return SendEmailResponse(success=True, message="Email sent successfully.")
