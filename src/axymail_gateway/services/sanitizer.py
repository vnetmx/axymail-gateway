"""
Content sanitization for email fields.

Two protection layers:
  1. HTML sanitization  — strips scripts, event handlers, dangerous tags/attrs.
                          Keeps safe formatting so HTML emails remain readable.
  2. Prompt injection   — detects and neutralizes instruction-injection patterns
                          in subject, plain text, and HTML so AI consumers are
                          not manipulated by crafted email content.

Usage
-----
    from axymail_gateway.services.sanitizer import sanitize_message

    clean, warnings = sanitize_message(raw_msg_dict)
    # warnings: list of human-readable strings describing what was found
"""
from __future__ import annotations

import re
from html.parser import HTMLParser

# ── HTML sanitization (via nh3) ──────────────────────────────────────────────

# Safe HTML tags for email rendering — no scripting, no embeds, no forms.
_ALLOWED_TAGS: frozenset[str] = frozenset(
    [
        "a", "abbr", "b", "blockquote", "br", "caption", "cite", "code",
        "col", "colgroup", "dd", "del", "details", "div", "dl", "dt",
        "em", "figure", "figcaption", "h1", "h2", "h3", "h4", "h5", "h6",
        "hr", "i", "img", "ins", "kbd", "li", "mark", "ol", "p", "pre",
        "q", "s", "small", "span", "strong", "sub", "summary", "sup",
        "table", "tbody", "td", "tfoot", "th", "thead", "time", "tr",
        "u", "ul",
    ]
)

# Per-tag attribute allowlist — strip everything else (event handlers, etc.)
_ALLOWED_ATTRIBUTES: dict[str, list[str]] = {
    "a":    ["href", "title"],          # href: nh3 strips javascript: URIs automatically
    "abbr": ["title"],
    "col":  ["span"],
    "colgroup": ["span"],
    "img":  ["src", "alt", "width", "height"],
    "td":   ["colspan", "rowspan", "align", "valign"],
    "th":   ["colspan", "rowspan", "scope", "align"],
    "time": ["datetime"],
    # Allow basic style-adjacent attrs on structural tags (no style= allowed)
    "div":  ["align"],
    "p":    ["align"],
}


def sanitize_html(html: str | None) -> str | None:
    """Strip unsafe HTML. Returns None if input is None."""
    if not html:
        return html
    try:
        import nh3
        return nh3.clean(
            html,
            tags=_ALLOWED_TAGS,
            attributes={tag: frozenset(attrs) for tag, attrs in _ALLOWED_ATTRIBUTES.items()},
            link_rel="noopener noreferrer",   # safe default for all <a href>
            strip_comments=True,
        )
    except ImportError:
        # nh3 not installed — fall back to stripping all tags
        return _strip_all_tags(html)


def _strip_all_tags(html: str) -> str:
    """Minimal fallback: strip every HTML tag."""
    class _Stripper(HTMLParser):
        def __init__(self):
            super().__init__()
            self._parts: list[str] = []
        def handle_data(self, data: str) -> None:
            self._parts.append(data)
        def get_text(self) -> str:
            return "".join(self._parts)

    s = _Stripper()
    s.feed(html)
    return s.get_text()


def sanitize_text(text: str | None) -> str | None:
    """Strip any stray HTML tags from plain-text parts."""
    if not text:
        return text
    return _strip_all_tags(text)


# ── Prompt injection detection ───────────────────────────────────────────────
#
# Patterns are (regex, category) pairs.  When a pattern matches, the
# matching span is replaced with a visible marker so AI consumers see
# that content was removed rather than silently missing it.
#
# We use re.IGNORECASE | re.DOTALL so multi-line injections are caught.

_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # "Ignore / disregard / forget previous instructions"
    (
        re.compile(
            r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+"
            r"(instructions?|prompts?|context|messages?|rules?|constraints?)",
            re.I,
        ),
        "ignore-instructions",
    ),
    # "Forget everything / forget your instructions"
    (
        re.compile(r"forget\s+(everything|all(\s+\w+)?\s+instructions?|your\s+\w+)", re.I),
        "ignore-instructions",
    ),
    # "Disregard / override everything above"
    (
        re.compile(
            r"(disregard|override)\s+(all|everything|your|previous|prior)\b", re.I
        ),
        "ignore-instructions",
    ),
    # "You are now a / Your new role is / Act as"
    (
        re.compile(
            r"(you\s+are\s+now\s+(a|an|the)\s+\w+"
            r"|your\s+(new\s+)?(role|persona|identity|purpose)\s+is"
            r"|(act|behave|respond)\s+as\s+(a|an|if)"
            r"|pretend\s+(you\s+are|to\s+be|that\s+you))",
            re.I,
        ),
        "role-reassignment",
    ),
    # "New instructions: / Updated prompt:"
    (
        re.compile(
            r"(new|updated|revised|actual|real|true|secret)\s+"
            r"(instructions?|prompt|task|goal|mission|objective)\s*:",
            re.I,
        ),
        "instruction-injection",
    ),
    # Fake system/instruction XML or markdown tags
    (
        re.compile(
            r"<\s*/?\s*(system|instructions?|prompt|context|override|assistant|user)\s*>",
            re.I,
        ),
        "system-tag",
    ),
    (
        re.compile(r"\[\s*(system|instructions?|prompt|override|context)\s*\]", re.I),
        "system-tag",
    ),
    (
        re.compile(r"#{1,3}\s*(system|instruction|prompt|override)\b", re.I),
        "system-tag",
    ),
    # LLM special tokens (Llama, Mistral, GPT, Claude-style)
    (
        re.compile(
            r"(<\|.*?\|>"                           # <|im_start|>, <|endoftext|>
            r"|\[INST\]|\[/INST\]"                  # Llama/Mistral
            r"|<<SYS>>|<</SYS>>"                    # Llama system block
            r"|\bHUMAN:\s|\bASSISTANT:\s"           # conversation role markers
            r"|\bUSER:\s|\bSYSTEM:\s)",             # idem
            re.I,
        ),
        "special-tokens",
    ),
    # Jailbreak / DAN keywords
    (
        re.compile(
            r"(\bjailbreak\b"
            r"|\bDAN\b.{0,20}\bmode\b"
            r"|\bdeveloper\s+mode\b"
            r"|\bgrandma\s+(exploit|trick|jailbreak)\b"
            r"|\bdo\s+anything\s+now\b)",
            re.I,
        ),
        "jailbreak",
    ),
]

# Replacement marker — visible, unambiguous, not itself an instruction
_MARKER = "[⚠ CONTENT REDACTED: potential prompt injection]"


def _neutralize_injections(text: str) -> tuple[str, list[str]]:
    """
    Replace matched injection patterns with _MARKER.
    Returns (sanitized_text, list_of_category_strings_that_were_detected).
    """
    detected: list[str] = []
    for pattern, category in _INJECTION_PATTERNS:
        if pattern.search(text):
            text = pattern.sub(_MARKER, text)
            if category not in detected:
                detected.append(category)
    return text, detected


def _strip_tags_for_injection_scan(html: str) -> str:
    """Convert HTML to plain text for injection scanning."""
    return _strip_all_tags(html)


# ── Public API ───────────────────────────────────────────────────────────────

def sanitize_message(msg: dict) -> tuple[dict, list[str]]:
    """
    Sanitize all user-controlled text fields in a full message dict.

    Returns:
        (sanitized_msg, warnings)

        warnings — list of human-readable strings, one per detected issue.
        Empty list means nothing suspicious was found.
    """
    msg = dict(msg)  # shallow copy — don't mutate caller's dict
    warnings: list[str] = []

    # ── Subject ──────────────────────────────────────────────────────────────
    if msg.get("subject"):
        subject = sanitize_text(msg["subject"]) or ""
        subject, found = _neutralize_injections(subject)
        msg["subject"] = subject
        for c in found:
            warnings.append(f"subject: {c}")

    # ── Plain text ────────────────────────────────────────────────────────────
    if msg.get("text"):
        text = sanitize_text(msg["text"]) or ""
        text, found = _neutralize_injections(text)
        msg["text"] = text
        for c in found:
            warnings.append(f"text: {c}")

    # ── HTML ──────────────────────────────────────────────────────────────────
    if msg.get("html"):
        # 1. Strip unsafe HTML structure
        clean_html = sanitize_html(msg["html"]) or ""
        # 2. Scan the text content (not raw HTML) for injection patterns
        visible_text = _strip_tags_for_injection_scan(clean_html)
        _, found = _neutralize_injections(visible_text)
        if found:
            # Re-run neutralization on the raw HTML text so markers appear
            # in the rendered output, not just in stripped text
            clean_html, _ = _neutralize_injections(clean_html)
            for c in found:
                warnings.append(f"html: {c}")
        msg["html"] = clean_html

    return msg, warnings


async def sanitize_message_with_guard(
    msg: dict,
    guard_url: str,
    guard_timeout: float = 5.0,
) -> tuple[dict, list[str], bool]:
    """
    Full sanitization pipeline — Layer 1 (local) + Layer 2 (LLM Guard API).

    1. Local: nh3 HTML sanitization + regex prompt injection detection.
    2. Guard: POST each field to /analyze/prompt — runs PromptInjection and
       Secrets scanners. The `sanitized_prompt` from each response is used as
       the replacement content (secrets are redacted by the guard service).

    For HTML: the guard scans the visible text. If the guard flags or modifies
    the content, the HTML body is replaced with the sanitized plain text.

    Returns:
        (sanitized_msg, warnings, guard_reachable)
    """
    from axymail_gateway.services.guard_client import scan_message_fields

    # Layer 1 — local
    msg, warnings = sanitize_message(msg)

    # Layer 2 — LLM Guard
    result = await scan_message_fields(
        base_url=guard_url,
        subject=msg.get("subject"),
        text=msg.get("text"),
        html=msg.get("html"),
        timeout=guard_timeout,
    )

    if result.reachable:
        for field_result in result.results:
            if field_result.field_id == "subject":
                msg["subject"] = field_result.sanitized_content
            elif field_result.field_id == "text":
                msg["text"] = field_result.sanitized_content
            elif field_result.field_id == "html":
                # If the guard flagged or redacted the HTML visible content,
                # replace the HTML body with the sanitized plain text (safe fallback)
                original_visible = _strip_tags_for_injection_scan(msg.get("html") or "")
                if field_result.is_poisoned or field_result.sanitized_content != original_visible:
                    msg["html"] = field_result.sanitized_content

    warnings.extend(result.warnings())
    return msg, warnings, result.reachable


async def sanitize_message_summary_with_guard(
    msg: dict,
    guard_url: str,
    guard_timeout: float = 5.0,
) -> tuple[dict, list[str], bool]:
    """
    Lighter sanitization for list items — Layer 1 + LLM Guard on subject only.

    Returns:
        (sanitized_msg, warnings, guard_reachable)
    """
    from axymail_gateway.services.guard_client import scan_message_fields

    # Layer 1 — local
    msg, warnings = sanitize_message_summary(msg)

    # Layer 2 — LLM Guard (subject only for list items)
    result = await scan_message_fields(
        base_url=guard_url,
        subject=msg.get("subject"),
        text=None,
        html=None,
        timeout=guard_timeout,
    )

    if result.reachable:
        for field_result in result.results:
            if field_result.field_id == "subject":
                msg["subject"] = field_result.sanitized_content

    warnings.extend(result.warnings())
    return msg, warnings, result.reachable


def sanitize_message_summary(msg: dict) -> tuple[dict, list[str]]:
    """
    Lighter sanitization for message list items (no body, just headers).
    Only processes subject and sender fields.
    """
    msg = dict(msg)
    warnings: list[str] = []

    if msg.get("subject"):
        subject = msg["subject"]
        # 1. Detect injections on raw text first (catches HTML-wrapped patterns like <system>)
        subject, found = _neutralize_injections(subject)
        for c in found:
            warnings.append(f"subject: {c}")
        # 2. Then sanitize/strip HTML
        subject = sanitize_text(subject) or ""
        msg["subject"] = subject

    # From/To are plain strings — strip any HTML and check for injection
    for field in ("from", "to"):
        val = msg.get(field)
        if isinstance(val, str) and val:
            val = sanitize_text(val) or ""
            val, found = _neutralize_injections(val)
            msg[field] = val
            for c in found:
                warnings.append(f"{field}: {c}")
        elif isinstance(val, list):
            cleaned = []
            for addr in val:
                addr = sanitize_text(addr) or ""
                addr, found = _neutralize_injections(addr)
                cleaned.append(addr)
                for c in found:
                    warnings.append(f"{field}: {c}")
            msg[field] = cleaned

    return msg, warnings
