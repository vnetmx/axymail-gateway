"""
Async HTTP client for the LLM Guard API.

Service: https://llmguard.axgot.tools  (internal — Colossus 10.1.12.99)
Docs:    /home/piuser/projects/llm-guard-api/docs/integration-guide.md

Endpoint: POST /analyze/prompt

Each email field (subject, text, html) is scanned independently.
The API runs two scanners per call unless suppressed:
  - PromptInjection: detects injection attacks and jailbreaks (ML-based, DeBERTa)
  - Secrets:         detects and redacts credentials, API keys, tokens (100+ providers)

The `sanitized_prompt` in the response is used as the replacement content —
this means secrets are automatically redacted in the output (e.g. AKIAIO… → AK..LE).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from html.parser import HTMLParser

import httpx

logger = logging.getLogger("axymail_gateway.guard_client")

_ANALYZE_PATH = "/analyze/prompt"

# Score threshold above which a scanner is considered to have fired.
# -1.0 means clean; anything >= 0.0 is a risk signal.
_CLEAN_SCORE = -1.0


# ── Data types ───────────────────────────────────────────────────────────────

@dataclass
class FieldResult:
    """Result for a single scanned field."""
    field_id: str
    is_valid: bool
    sanitized_content: str       # use this as the replacement — secrets are redacted
    scanner_scores: dict[str, float] = field(default_factory=dict)

    @property
    def is_poisoned(self) -> bool:
        return not self.is_valid

    @property
    def fired_scanners(self) -> list[str]:
        """Return scanner names that flagged this field (score > -1.0)."""
        return [name for name, score in self.scanner_scores.items() if score > _CLEAN_SCORE]


@dataclass
class GuardResult:
    """Aggregated result for a full message scan."""
    results: list[FieldResult] = field(default_factory=list)
    reachable: bool = True
    error: str | None = None

    @property
    def is_poisoned(self) -> bool:
        return any(r.is_poisoned for r in self.results)

    def warnings(self) -> list[str]:
        warns: list[str] = []
        for r in self.results:
            for scanner in r.fired_scanners:
                score = r.scanner_scores[scanner]
                warns.append(
                    f"guard:{r.field_id}:{scanner}: score={score:.2f}"
                )
        if not self.reachable:
            warns.append(f"guard: service unreachable ({self.error})")
        return warns


# ── HTML helpers ─────────────────────────────────────────────────────────────

def _strip_tags(html: str) -> str:
    """Extract visible text from HTML — sent to the guard for scanning."""
    class _S(HTMLParser):
        def __init__(self):
            super().__init__()
            self._p: list[str] = []
        def handle_data(self, d: str) -> None:
            self._p.append(d)
        def text(self) -> str:
            return "".join(self._p)
    s = _S()
    s.feed(html)
    return s.text()


def build_fields(
    subject: str | None,
    text: str | None,
    html: str | None,
) -> list[tuple[str, str]]:
    """
    Build the list of (field_id, content) pairs to scan.
    HTML is converted to visible text before being included.
    """
    fields: list[tuple[str, str]] = []
    if subject and subject.strip():
        fields.append(("subject", subject))
    if text and text.strip():
        fields.append(("text", text))
    if html and html.strip():
        visible = _strip_tags(html)
        if visible.strip():
            fields.append(("html", visible))
    return fields


# ── HTTP client ──────────────────────────────────────────────────────────────

async def _scan_field(
    client: httpx.AsyncClient,
    base_url: str,
    field_id: str,
    content: str,
    scanners_suppress: list[str] | None = None,
) -> FieldResult:
    """
    Scan a single field by posting to /analyze/prompt.
    Returns a FieldResult with the sanitized content and scanner scores.
    """
    payload: dict = {
        "prompt": content,
        "scanners_suppress": scanners_suppress or ["Secrets"],  # PromptInjection only by default
    }

    url = f"{base_url.rstrip('/')}{_ANALYZE_PATH}"
    resp = await client.post(url, json=payload)
    resp.raise_for_status()
    data = resp.json()

    return FieldResult(
        field_id=field_id,
        is_valid=bool(data.get("is_valid", True)),
        sanitized_content=data.get("sanitized_prompt", content),
        scanner_scores=data.get("scanners", {}),
    )


async def scan_message_fields(
    base_url: str,
    subject: str | None,
    text: str | None,
    html: str | None,
    timeout: float = 5.0,
) -> GuardResult:
    """
    Scan subject, text, and html fields independently against the LLM Guard API.

    For HTML, the visible text is extracted and scanned. If the guard flags it
    or redacts secrets, the sanitized plain text replaces the HTML body entirely.

    Returns a GuardResult with per-field verdicts and sanitized content.
    On any network/timeout error, returns GuardResult(reachable=False).
    """
    fields_to_scan = build_fields(subject, text, html)

    if not fields_to_scan:
        return GuardResult()

    results: list[FieldResult] = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            for field_id, content in fields_to_scan:
                result = await _scan_field(client, base_url, field_id, content)
                results.append(result)
    except httpx.TimeoutException as exc:
        logger.warning("LLM Guard timeout: %s", exc)
        return GuardResult(reachable=False, error=f"timeout ({timeout}s)")
    except httpx.HTTPStatusError as exc:
        logger.warning("LLM Guard HTTP %s: %s", exc.response.status_code, exc)
        return GuardResult(reachable=False, error=f"HTTP {exc.response.status_code}")
    except Exception as exc:
        logger.warning("LLM Guard error: %s", exc)
        return GuardResult(reachable=False, error=str(exc))

    return GuardResult(results=results)
