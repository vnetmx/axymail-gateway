"""
Async HTTP client for the external content-guard service.

The guard service is a separate project (e.g. LLM Guard) that performs
ML-based prompt injection detection.  This client sends text content in
chunks and receives a verdict per chunk.

Request / response contract
---------------------------

POST {GUARD_SERVICE_URL}/v1/scan

Request body:
    {
        "chunks": [
            {"id": "subject",   "content": "Re: Meeting tomorrow"},
            {"id": "text:0",    "content": "first 2000 chars of plain text..."},
            {"id": "text:1",    "content": "next 2000 chars..."},
            {"id": "html:0",    "content": "first 2000 chars of visible HTML text..."}
        ]
    }

Response body:
    {
        "results": [
            {"id": "subject",  "verdict": "clean",    "score": 0.02},
            {"id": "text:0",   "verdict": "poisoned", "score": 0.95, "categories": ["prompt-injection"]},
            {"id": "text:1",   "verdict": "clean",    "score": 0.08},
            {"id": "html:0",   "verdict": "clean",    "score": 0.11}
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
class ChunkVerdict:
    """Verdict for a single chunk returned by the guard service."""
    chunk_id: str
    verdict: str          # "clean" | "poisoned"
    score: float          # 0.0–1.0
    categories: list[str] = field(default_factory=list)

    @property
    def is_poisoned(self) -> bool:
        return self.verdict == "poisoned"


@dataclass
class GuardResult:
    """Aggregated result for an entire message scan."""
    verdicts: list[ChunkVerdict] = field(default_factory=list)
    reachable: bool = True      # False when the guard service was unreachable
    error: str | None = None    # error detail if unreachable

    @property
    def is_poisoned(self) -> bool:
        return any(v.is_poisoned for v in self.verdicts)

    @property
    def poisoned_fields(self) -> list[str]:
        """Return de-duped field names (without chunk index) that were flagged."""
        fields: list[str] = []
        for v in self.verdicts:
            if v.is_poisoned:
                name = v.chunk_id.split(":")[0]  # "text:1" → "text"
                if name not in fields:
                    fields.append(name)
        return fields

    def warnings(self) -> list[str]:
        """Human-readable warnings suitable for sanitized_warnings."""
        warns: list[str] = []
        for v in self.verdicts:
            if v.is_poisoned:
                cats = ", ".join(v.categories) if v.categories else "suspicious"
                warns.append(f"guard:{v.chunk_id}: {cats} (score={v.score:.2f})")
        if not self.reachable:
            warns.append(f"guard: service unreachable ({self.error})")
        return warns


# ── Chunking ─────────────────────────────────────────────────────────────────

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


def _chunk(text: str, max_size: int) -> list[str]:
    """Split text into chunks of at most *max_size* characters."""
    if not text:
        return []
    return [text[i : i + max_size] for i in range(0, len(text), max_size)]


def build_chunks(
    subject: str | None,
    text: str | None,
    html: str | None,
    max_chunk_size: int = 2000,
) -> list[dict]:
    """
    Build the ``chunks`` list to POST to the guard service.

    Long fields are split into numbered sub-chunks:
      subject     → "subject"
      text part 0 → "text:0", part 1 → "text:1", …
      html part 0 → "html:0", …

    HTML is converted to visible text before chunking (tags stripped) so
    the ML model sees actual content, not markup.
    """
    chunks: list[dict] = []

    if subject:
        chunks.append({"id": "subject", "content": subject})

    if text:
        for i, part in enumerate(_chunk(text, max_chunk_size)):
            chunks.append({"id": f"text:{i}", "content": part})

    if html:
        visible = _strip_tags(html)
        if visible.strip():
            for i, part in enumerate(_chunk(visible, max_chunk_size)):
                chunks.append({"id": f"html:{i}", "content": part})

    return chunks


# ── HTTP client ──────────────────────────────────────────────────────────────

async def scan(
    base_url: str,
    chunks: list[dict],
    timeout: float = 5.0,
) -> GuardResult:
    """
    POST chunks to the guard service and return the aggregated result.

    On any network/timeout/parse error, returns a GuardResult with
    ``reachable=False`` so the caller can fall back to local detection.
    """
    if not chunks:
        return GuardResult()

    url = f"{base_url.rstrip('/')}/v1/scan"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, json={"chunks": chunks})
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

    verdicts: list[ChunkVerdict] = []
    for item in data.get("results", []):
        verdicts.append(
            ChunkVerdict(
                chunk_id=item.get("id", "?"),
                verdict=item.get("verdict", "clean"),
                score=float(item.get("score", 0.0)),
                categories=item.get("categories", []),
            )
        )

    return GuardResult(verdicts=verdicts)
