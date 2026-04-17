"""
IMAP service — fully async via aioimaplib.

Each public function opens a fresh IMAP connection, performs its work,
and closes the connection (v1: no persistent pool).
"""
from __future__ import annotations

import email
import re
from dataclasses import dataclass
from email.header import decode_header, make_header
from email.message import Message

import aioimaplib

# ── IMAP flag constants ──────────────────────────────────────────────────────
_FLAG_SEEN = "\\Seen"
_FLAG_FLAGGED = "\\Flagged"
_FLAG_DELETED = "\\Deleted"

# Matches the start of a FETCH server-data line: e.g. b'3 FETCH (UID 42 ...'
_FETCH_LINE_RE = re.compile(rb"^\d+\s+FETCH\s+\(", re.IGNORECASE)

# Matches a LIST response line: (\flags) "delimiter" "mailbox-name"
_LIST_LINE_RE = re.compile(
    rb'\((?P<flags>[^)]*)\)\s+"(?P<delim>[^"]+)"\s+'
    rb'(?:"(?P<name_q>[^"]+)"|(?P<name_u>\S+))',
    re.IGNORECASE,
)


# ── credentials ─────────────────────────────────────────────────────────────
@dataclass
class ImapCredentials:
    host: str
    port: int
    user: str
    password: str
    tls: bool  # True = implicit TLS/SSL; False = plain or STARTTLS


# ── internal helpers ─────────────────────────────────────────────────────────

def _make_client(creds: ImapCredentials) -> aioimaplib.IMAP4_SSL | aioimaplib.IMAP4:
    if creds.tls:
        return aioimaplib.IMAP4_SSL(host=creds.host, port=creds.port)
    return aioimaplib.IMAP4(host=creds.host, port=creds.port)


async def _connect(creds: ImapCredentials) -> aioimaplib.IMAP4_SSL | aioimaplib.IMAP4:
    client = _make_client(creds)
    await client.wait_hello_from_server()
    await client.login(creds.user, creds.password)
    return client


async def _safe_logout(client: aioimaplib.IMAP4_SSL | aioimaplib.IMAP4) -> None:
    try:
        await client.logout()
    except Exception:
        pass


def _decode_header_str(value: str | None) -> str:
    """Decode RFC2047-encoded header value to a plain string."""
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _parse_flags_from_line(line: bytes) -> set[str]:
    """Extract IMAP flags from a FETCH response line, e.g. FLAGS (\\Seen \\Flagged)."""
    m = re.search(rb"FLAGS\s+\(([^)]*)\)", line, re.IGNORECASE)
    if not m:
        return set()
    return {f.decode() for f in m.group(1).split() if f}


def _extract_fetch_pairs(data: list) -> list[tuple[bytes, bytes]]:
    """
    Walk an aioimaplib FETCH response data list and return (header_line, literal_bytes)
    pairs for each fetched message.

    aioimaplib represents literal data (the actual message/header bytes) as a separate
    element immediately following the FETCH metadata line.  Critically, metadata lines
    come back as `bytes` while literal payloads come back as `bytearray` — so we must
    accept both types when looking for the literal.

        data[i]   = b'3 FETCH (UID 42 FLAGS (\\Seen) RFC822 {1234}'  ← bytes
        data[i+1] = bytearray(b'<raw email bytes ...>')              ← bytearray!
        data[i+2] = b')'                                             ← bytes
    """
    pairs: list[tuple[bytes, bytes]] = []
    i = 0
    while i < len(data):
        item = data[i]
        # FETCH metadata lines are always bytes
        if isinstance(item, bytes) and _FETCH_LINE_RE.match(item):
            literal = b""
            if i + 1 < len(data):
                candidate = data[i + 1]
                # Literals come back as bytearray; accept both bytes and bytearray
                if isinstance(candidate, (bytes, bytearray)):
                    candidate_b = bytes(candidate)
                    if not _FETCH_LINE_RE.match(candidate_b) and candidate_b.strip() != b")":
                        literal = candidate_b
                        i += 1  # consume the literal
            pairs.append((item, literal))
        i += 1
    return pairs


def _body_parts(msg: Message) -> tuple[str, str]:
    """Return (plain_text, html) extracted from a parsed email.Message."""
    texts: list[str] = []
    htmls: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            charset = part.get_content_charset() or "utf-8"
            decoded = payload.decode(charset, errors="replace")
            if ct == "text/plain":
                texts.append(decoded)
            elif ct == "text/html":
                htmls.append(decoded)
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            decoded = payload.decode(charset, errors="replace")
            if msg.get_content_type() == "text/html":
                htmls.append(decoded)
            else:
                texts.append(decoded)
    return "\n".join(texts), "\n".join(htmls)


def _attachments(msg: Message) -> list[dict]:
    result: list[dict] = []
    for part in msg.walk():
        if part.get_content_disposition() in ("attachment", "inline") and part.get_filename():
            payload = part.get_payload(decode=True) or b""
            result.append(
                {
                    "filename": _decode_header_str(part.get_filename()),
                    "content_type": part.get_content_type(),
                    "size": len(payload),
                }
            )
    return result


# ── public API ───────────────────────────────────────────────────────────────

async def list_mailboxes(creds: ImapCredentials) -> list[dict]:
    """Return all IMAP folders for the account."""
    client = await _connect(creds)
    try:
        result, data = await client.list('""', "*")
        folders: list[dict] = []
        if result == "OK":
            for line in data:
                if not isinstance(line, bytes):
                    continue
                m = _LIST_LINE_RE.search(line.strip())
                if not m:
                    continue
                delim = m.group("delim").decode()
                name_bytes = m.group("name_q") or m.group("name_u") or b""
                path = name_bytes.decode()
                folders.append(
                    {
                        "path": path,
                        "name": path.split(delim)[-1] if delim in path else path,
                    }
                )
        return folders
    finally:
        await _safe_logout(client)


async def list_messages(
    creds: ImapCredentials,
    mailbox: str = "INBOX",
    page: int = 0,
    page_size: int = 20,
) -> list[dict]:
    """
    List messages in *mailbox*, paginated by *page* / *page_size*.

    Fetches only headers + flags (no full body) for efficiency.

    Note: aioimaplib's uid() does not support SEARCH, so we use the regular
    SEARCH command (returns sequence numbers) then FETCH with UID in the data
    spec to get the stable message UIDs.
    """
    client = await _connect(creds)
    try:
        await client.select(mailbox)

        result, data = await client.search("ALL")
        if result != "OK" or not data or not data[0]:
            return []

        all_seqs: list[str] = data[0].decode().split()
        start = page * page_size
        page_seqs = all_seqs[start : start + page_size]
        if not page_seqs:
            return []

        seq_set = ",".join(page_seqs)
        result, fetch_data = await client.fetch(
            seq_set,
            "(UID FLAGS RFC822.SIZE BODY[HEADER.FIELDS (FROM TO SUBJECT DATE)])",
        )
        if result != "OK":
            return []

        messages: list[dict] = []
        for meta_line, header_bytes in _extract_fetch_pairs(fetch_data):
            flags = _parse_flags_from_line(meta_line)

            uid_m = re.search(rb"UID\s+(\d+)", meta_line, re.IGNORECASE)
            uid = uid_m.group(1).decode() if uid_m else ""

            size_m = re.search(rb"RFC822\.SIZE\s+(\d+)", meta_line, re.IGNORECASE)
            size = int(size_m.group(1)) if size_m else 0

            msg = email.message_from_bytes(header_bytes) if header_bytes else email.message_from_string("")
            messages.append(
                {
                    "uid": uid,
                    "subject": _decode_header_str(msg.get("Subject")),
                    "from": msg.get("From", ""),
                    "to": [a.strip() for a in (msg.get("To") or "").split(",") if a.strip()],
                    "date": msg.get("Date"),
                    "seen": _FLAG_SEEN in flags,
                    "flagged": _FLAG_FLAGGED in flags,
                    "size": size,
                }
            )
        return messages
    finally:
        await _safe_logout(client)


async def get_message(
    creds: ImapCredentials,
    uid: str | int,
    mailbox: str = "INBOX",
) -> dict | None:
    """Fetch a single full message (headers + body + attachments) by UID."""
    client = await _connect(creds)
    try:
        await client.select(mailbox)
        result, fetch_data = await client.uid("fetch", str(uid), "(UID FLAGS RFC822)")
        if result != "OK":
            return None

        pairs = _extract_fetch_pairs(fetch_data)
        if not pairs:
            return None

        meta_line, raw_body = pairs[0]
        if not raw_body:
            return None

        flags = _parse_flags_from_line(meta_line)
        msg = email.message_from_bytes(raw_body)
        text, html = _body_parts(msg)

        return {
            "uid": str(uid),
            "subject": _decode_header_str(msg.get("Subject")),
            "from": msg.get("From", ""),
            "to": [a.strip() for a in (msg.get("To") or "").split(",") if a.strip()],
            "cc": [a.strip() for a in (msg.get("Cc") or "").split(",") if a.strip()],
            "date": msg.get("Date"),
            "seen": _FLAG_SEEN in flags,
            "flagged": _FLAG_FLAGGED in flags,
            "text": text or None,
            "html": html or None,
            "attachments": _attachments(msg),
        }
    finally:
        await _safe_logout(client)


async def set_flags(
    creds: ImapCredentials,
    uid: str | int,
    seen: bool | None,
    flagged: bool | None,
    mailbox: str = "INBOX",
) -> bool:
    """Set or clear \\Seen / \\Flagged on a message by UID."""
    client = await _connect(creds)
    try:
        await client.select(mailbox)
        uid_str = str(uid)
        if seen is True:
            await client.uid("store", uid_str, "+FLAGS", f"({_FLAG_SEEN})")
        elif seen is False:
            await client.uid("store", uid_str, "-FLAGS", f"({_FLAG_SEEN})")
        if flagged is True:
            await client.uid("store", uid_str, "+FLAGS", f"({_FLAG_FLAGGED})")
        elif flagged is False:
            await client.uid("store", uid_str, "-FLAGS", f"({_FLAG_FLAGGED})")
        return True
    finally:
        await _safe_logout(client)


async def delete_message(
    creds: ImapCredentials,
    uid: str | int,
    mailbox: str = "INBOX",
) -> bool:
    """Delete a message by UID — marks \\Deleted then expunges."""
    client = await _connect(creds)
    try:
        await client.select(mailbox)
        await client.uid("store", str(uid), "+FLAGS", f"({_FLAG_DELETED})")
        await client.expunge()
        return True
    finally:
        await _safe_logout(client)
