from __future__ import annotations

from dataclasses import dataclass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

import aiosmtplib


@dataclass
class SmtpCredentials:
    host: str
    port: int
    user: str
    password: str
    tls: bool  # True = STARTTLS (unless port 465 which implies implicit SSL)
    # OAuth — set auth_type='xoauth2' and populate xoauth2_string instead of password
    auth_type: str = "password"   # 'password' | 'xoauth2'
    xoauth2_string: str = ""      # base64 XOAUTH2 SASL payload (see oauth_service)


async def send_email(
    creds: SmtpCredentials,
    from_addr: str,
    to: list[str],
    cc: list[str],
    bcc: list[str],
    subject: str,
    text: Optional[str],
    html: Optional[str],
) -> bool:
    """
    Send an email via SMTP.

    Port 465  → implicit SSL (use_tls=True, start_tls=False).
    Port 587  → STARTTLS   (use_tls=False, start_tls=True when creds.tls=True).
    Other     → follow creds.tls for STARTTLS; no implicit SSL.
    """
    msg = MIMEMultipart("alternative")
    msg["From"] = from_addr
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Subject"] = subject

    if text:
        msg.attach(MIMEText(text, "plain", "utf-8"))
    if html:
        msg.attach(MIMEText(html, "html", "utf-8"))

    all_recipients = to + cc + bcc

    # Decide TLS mode based on port
    use_tls = creds.port == 465
    start_tls = creds.tls and creds.port != 465

    if creds.auth_type == "xoauth2":
        # aiosmtplib AUTH XOAUTH2: the "password" is the raw base64 XOAUTH2 string.
        # We must connect manually to control the AUTH mechanism.
        smtp = aiosmtplib.SMTP(
            hostname=creds.host,
            port=creds.port,
            use_tls=use_tls,
            start_tls=start_tls,
        )
        await smtp.connect()
        if start_tls:
            await smtp.starttls()
        # Send AUTH XOAUTH2 directly — aiosmtplib passes the string as-is.
        await smtp.login(creds.user, creds.xoauth2_string, login_type="XOAUTH2")
        await smtp.sendmail(from_addr, all_recipients, msg.as_bytes())
        await smtp.quit()
        return True

    await aiosmtplib.send(
        msg,
        hostname=creds.host,
        port=creds.port,
        username=creds.user,
        password=creds.password,
        use_tls=use_tls,
        start_tls=start_tls,
        recipients=all_recipients,
    )
    return True
