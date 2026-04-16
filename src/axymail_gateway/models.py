from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# IMAP / SMTP credential sub-models
# ---------------------------------------------------------------------------

class ImapConfig(BaseModel):
    host: str
    port: int = 993
    user: str
    password: str
    tls: bool = True


class SmtpConfig(BaseModel):
    host: str
    port: int = 587
    user: str
    password: str
    tls: bool = True  # STARTTLS


# ---------------------------------------------------------------------------
# Account registration
# ---------------------------------------------------------------------------

class RegisterAccountRequest(BaseModel):
    email: str
    imap: ImapConfig
    smtp: SmtpConfig


class RegisterAccountResponse(BaseModel):
    account_id: str
    token: str  # shown ONCE — not stored in plaintext
    email: str


class AccountInfo(BaseModel):
    account_id: str
    email: str
    created_at: str


# ---------------------------------------------------------------------------
# Mailbox
# ---------------------------------------------------------------------------

class Mailbox(BaseModel):
    path: str
    name: str
    messages: Optional[int] = None
    unseen: Optional[int] = None


# ---------------------------------------------------------------------------
# Message list
# ---------------------------------------------------------------------------

class MessageListItem(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    uid: int
    subject: Optional[str] = None
    from_: Optional[str] = Field(None, alias="from")
    to: list[str] = []
    date: Optional[str] = None
    seen: bool = False
    flagged: bool = False
    size: Optional[int] = None
    sanitized_warnings: list[str] = Field(
        default=[],
        description="Non-empty when sanitization removed or neutralized suspicious content.",
    )


# ---------------------------------------------------------------------------
# Full message
# ---------------------------------------------------------------------------

class Attachment(BaseModel):
    filename: Optional[str] = None
    content_type: str
    size: int


class FullMessage(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    uid: int
    subject: Optional[str] = None
    from_: Optional[str] = Field(None, alias="from")
    to: list[str] = []
    cc: list[str] = []
    date: Optional[str] = None
    seen: bool = False
    flagged: bool = False
    text: Optional[str] = None
    html: Optional[str] = None
    attachments: list[Attachment] = []
    sanitized_warnings: list[str] = Field(
        default=[],
        description="Non-empty when sanitization removed or neutralized suspicious content.",
    )


# ---------------------------------------------------------------------------
# Send email
# ---------------------------------------------------------------------------

class SendEmailRequest(BaseModel):
    to: list[str]
    cc: list[str] = []
    bcc: list[str] = []
    subject: str = ""
    text: Optional[str] = None
    html: Optional[str] = None


class SendEmailResponse(BaseModel):
    success: bool
    message: str = ""


# ---------------------------------------------------------------------------
# Flag update
# ---------------------------------------------------------------------------

class UpdateFlagsRequest(BaseModel):
    seen: Optional[bool] = None
    flagged: Optional[bool] = None
