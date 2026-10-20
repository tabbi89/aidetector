"""Episodic memory for the heavy lane — what worked on this target before.

Phase 3 slice 4. Each heavy run remembers its findings keyed by fingerprint and
target host, and the next heavy run against the same target recalls them so the
bounded agent can spend its small budget where a weakness has shown up before.

Two halves, split by the layering rule:

- **This module is pure** (in ``PURE_MODULES``): the offline, deterministic
  embedding, cosine similarity, and the recall-selection and prioritisation
  logic the agent loop uses. No database, no network, no model call — the
  embedding is a token-hashing bag-of-words, so recall works on the DB-free
  runner and in a test with nothing installed.
- **Persistence lives server-side** (``app/scans/agent_memory.py`` over the
  ``agent_memory`` table). The runner has no database, so it recalls through the
  ingest API and never writes memory itself; the server writes it at run
  completion, *after* ``append_finding`` has stamped fingerprints, so identity
  is the server's exactly like every other finding property.

A memory row never stores a target value — only the fingerprint (already free of
harvested ids and values), the check, the grade and a short redacted title. The
same discipline as the findings table it is derived from.

pgvector is the obvious scale path for similarity; at the scale one tenant's
heavy runs produce, an in-process cosine over a bounded candidate set is enough,
and it keeps the feature off the Postgres image's extension list.
"""
from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

#: Embedding width. Small on purpose — this discriminates "same kind of weakness
#: on a similar endpoint", not fine semantic nuance.
EMBED_DIM = 64
#: Below this cosine, a recalled memory is not considered relevant to a query.
DEFAULT_MIN_SCORE = 0.25

#: Which producing-tool a remembered check suggests re-running. An injection
#: lead or a past sqlmap confirmation both argue for sqlmap; a past shadow-path
#: or template hit argues for the discovery/template tools.
_CHECK_TO_TOOL = {
    "reflected_injection": "sqlmap",
    "signature_injection": "sqlmap",
    "sqlmap_confirm": "sqlmap",
    "kali_nuclei": "nuclei",
    "kali_discovery": "ffuf",
    "kali_crawl": "ffuf",
}


def host_of(url: str) -> str:
    """The target key memory is grouped by: scheme+host(+port), path dropped."""
    parts = urlsplit(url)
    if not parts.netloc:
        return url.strip().lower()[:255]
    return f"{parts.scheme}://{parts.netloc}".lower()[:255]


def _tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


def embed(text: str, dim: int = EMBED_DIM) -> list[float]:
    """A deterministic, offline bag-of-tokens embedding, L2-normalised.

    Each token is hashed into a bucket with a sign; identical text embeds
    identically on any machine and any run, which is what makes recall testable
    without a model or a vector service.
    """
    vec = [0.0] * dim
    for tok in _tokens(text):
        h = int.from_bytes(hashlib.blake2b(tok.encode(), digest_size=8).digest(), "big")
        bucket = h % dim
        sign = 1.0 if (h >> 8) & 1 else -1.0
        vec[bucket] += sign
    norm = math.sqrt(sum(v * v for v in vec))
    if norm == 0.0:
        return vec
    return [v / norm for v in vec]


def cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity of two equal-length vectors; 0 when either is empty."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    # Vectors from embed() are already normalised; guard anyway.
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(y * y for y in b)) or 1.0
    return dot / (na * nb)


@dataclass(frozen=True)
class MemoryRecord:
    """One remembered finding, derived server-side from a stamped finding."""

    fingerprint: str
    check: str
    severity: str
    confidence: str
    title: str
    embedding: list[float]

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "check": self.check,
            "severity": self.severity,
            "confidence": self.confidence,
            "title": self.title,
            "embedding": self.embedding,
        }


def record_from_finding(
    *,
    fingerprint: str,
    check: str,
    severity: str,
    confidence: str,
    title: str,
    evidence: dict | None = None,
) -> MemoryRecord | None:
    """Build a memory record from a stamped finding. None without a fingerprint."""
    if not fingerprint:
        return None
    evidence = evidence or {}
    subject = " ".join(
        str(evidence.get(k, "")) for k in ("route", "path", "param", "field", "issue", "kind")
    )
    return MemoryRecord(
        fingerprint=fingerprint,
        check=check,
        severity=severity,
        confidence=confidence,
        title=title[:255],
        embedding=embed(f"{check} {title} {subject}"),
    )


def recall(
    rows: list[dict],
    query: str,
    *,
    limit: int = 8,
    min_score: float = DEFAULT_MIN_SCORE,
) -> list[dict]:
    """Rank stored memory rows by relevance to ``query``, best first.

    ``rows`` are memory dicts (``embedding`` optional); ``query`` is free text
    describing the current scan (its operations, say). A row with no usable
    embedding falls back to its stored ``hits`` so a frequently-seen weakness is
    still surfaced. Returns the rows with a ``score`` attached.
    """
    q = embed(query) if query else []
    scored: list[tuple[float, int, dict]] = []
    for row in rows:
        emb = row.get("embedding")
        score = cosine(q, emb) if (q and isinstance(emb, list)) else 0.0
        hits = int(row.get("hits") or 0)
        if score < min_score and not (not q and hits > 0):
            continue
        out = {k: v for k, v in row.items() if k != "embedding"}
        out["score"] = round(score, 4)
        scored.append((score, hits, out))
    scored.sort(key=lambda s: (-s[0], -s[1], s[2].get("fingerprint", "")))
    return [r for _, _, r in scored[:limit]]


def prior_productive_tools(recalls: list[dict]) -> set[str]:
    """Sandbox tools a recalled weakness argues for re-running on this target."""
    tools: set[str] = set()
    for row in recalls:
        tool = _CHECK_TO_TOOL.get(str(row.get("check")))
        if tool:
            tools.add(tool)
    return tools
