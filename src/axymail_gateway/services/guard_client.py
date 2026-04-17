"""
Async HTTP client for the external content-guard service.

The guard service is a separate project (e.g. LLM Guard) that performs
ML-based prompt injection detection.  This client sends the full email
fields (subject, text, html) and receives a verdict per field.

Request / response contract
---------------------------

POST {GUARD_SERVICE_URL}/v1/scan

Request body:
    {
        "fields": [
            {"id": "subject", "content": "Re: Meeting tomorrow"},
            {"id": "text",    "content": "full plain text body..."},
            {"id": "html",    "content": "visible text extracted from HTML body..."}
        ]
    }

Response body:
    {
        "results": [
            {"id": "subject", "verdict": "clean",    "score": 0.02},
            {"id": "text",    "verdict": "poisoned", "score": 0.95, "categories": ["prompt-injection"]},
            {"id": "html",    "verdict": "clean",    "score": 0.11}
        ]
    }

Verdicts: "clean" | "poisoned"
Score:    0.0 (safe) → 1.0 (malicious)

If the guard service is unreachable, this client returns an empty result
so the caller can fall back to local (regex-based) detection.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from html.parser import HTMLParser

import httpx

logger = logging.getLogger("axymail_gateway.guard_client")


# ── Data types ───────────────────────────────────────────────────────────────

@dataclass
class FieldVerdict:
    """Verdict for a single field returned by the guard service."""
    field_id: str
    verdict: str          # "clean" | "poisoned"
    score: float          # 0.0–1.0
    categories: list[str] = field(default_factory=list)

    @property
    def is_poisoned(self) -> bool:
        return self.verdict == "poisoned"


@dataclass
class GuardResult:
    """Aggregated result for an entire message scan."""
    verdicts: list[FieldVerdict] = field(default_factory=list)
    reachable: bool = True      # False when the guard service was unreachable
    error: str | None = None    # error detail if unreachable

    @property
    def is_poisoned(self) -> bool:
        return any(v.is_poisoned for v in self.verdicts)

    @property
    def poisoned_fields(self) -> list[str]:
        """Return field names that were flagged."""
        return [v.field_id for v in self.verdicts if v.is_poisoned]

    def warnings(self) -> list[str]:
        """Human-readable warnings suitable for sanitized_warnings."""
        warns: list[str] = []
        for v in self.verdicts:
            if v.is_poisoned:
                cats = ", ".join(v.categories) if v.categories else "suspicious"
                warns.append(f"guard:{v.field_id}: {cats} (score={v.score:.2f})")
        if not self.reachable:
            warns.append(f"guard: service unreachable ({self.error})")
        return warns


# ── Helpers ──────────────────────────────────────────────────────────────────

def _strip_tags(html: str) -> str:
    """Extract visible text from HTML for scanning."""
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
) -> list[dict]:
    """
    Build the ``fields`` list to POST to the guard service.

    HTML is converted to visible text before sending (tags stripped) so
    the ML model sees actual content, not markup.
    """
    fields: list[dict] = []

    if subject:
        fields.append({"id": "subject", "content": subject})

    if text:
        fields.append({"id": "text", "content": text})

    if html:
        visible = _strip_tags(html)
        if visible.strip():
            fields.append({"id": "html", "content": visible})

    return fields


# ── HTTP client ──────────────────────────────────────────────────────────────

async def scan(
    base_url: str,
    fields: list[dict],
    timeout: float = 5.0,
) -> GuardResult:
    """
    POST fields to the guard service and return the aggregated result.

    On any network/timeout/parse error, returns a GuardResult with
    ``reachable=False`` so the caller can fall back to local detection.
    """
    if not fields:
        return GuardResult()

    url = f"{base_url.rstrip('/')}/v1/scan"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, json={"fields": fields})
            resp.raise_for_status()
            data = resp.json()
    except httpx.TimeoutException as exc:
        logger.warning("Guard service timeout: %s", exc)
        return GuardResult(reachable=False, error=f"timeout ({timeout}s)")
    except httpx.HTTPStatusError as exc:
        logger.warning("Guard service HTTP %s: %s", exc.response.status_code, exc)
        return GuardResult(reachable=False, error=f"HTTP {exc.response.status_code}")
    except Exception as exc:
        logger.warning("Guard service error: %s", exc)
        return GuardResult(reachable=False, error=str(exc))

    verdicts: list[FieldVerdict] = []
    for item in data.get("results", []):
        verdicts.append(
            FieldVerdict(
                field_id=item.get("id", "?"),
                verdict=item.get("verdict", "clean"),
                score=float(item.get("score", 0.0)),
                categories=item.get("categories", []),
            )
        )

    return GuardResult(verdicts=verdicts)
