"""Rotating payload library.

Each scan draws a rotating subset of payloads keyed by a per-scan seed, so
repeated scans of the same target exercise different payloads over time (the
approach Detectify describes as "randomized, rotating payloads with each scan").
The unique marker embedded in each payload lets a reflection check confirm the
exact payload that came back.

Payloads come from two sources behind one :class:`PayloadProvider`:

- the **curated library** in this file (``_LIBRARY``) — small, hand-authored,
  the detection baseline; and
- the **vendored corpus** (``app/engine/payload_corpus.py``) — a larger offline
  dataset merged in per family.

The provider only grows the *rotation pool*: the injection checks still draw one
payload per family per scan (``rotating_set(..., per_family=1)``), so per-scan
request volume — and the request budget — is unchanged. A bigger pool means more
variety across scans, not more traffic within one.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any

from app.engine.payload_corpus import reflection_templates


@dataclass(frozen=True)
class Payload:
    family: str            # "xss", "sqli", "traversal", "ssti", ...
    template: str          # contains "{m}" where the unique marker is inserted
    reflect_marker: bool   # True if a raw reflection of the marker is a signal


# Templates use {m} for the per-request unique marker. Kept deliberately benign —
# these probe for reflection/echo, not exploitation.
_LIBRARY: list[Payload] = [
    # Cross-site scripting
    Payload("xss", "<aidx{m}>", True),
    Payload("xss", "\"><svg/onload=aidx{m}>", True),
    Payload("xss", "'><img src=x onerror=aidx{m}>", True),
    Payload("xss", "javascript:aidx{m}", True),
    # SQL injection (error/echo probes)
    Payload("sqli", "' OR aidx{m}='{m}", True),
    Payload("sqli", "1; SELECT 'aidx{m}'--", True),
    Payload("sqli", "\" UNION SELECT aidx{m}--", True),
    # Path traversal
    Payload("traversal", "../../aidx{m}", True),
    Payload("traversal", "..%2f..%2faidx{m}", True),
    # Server-side template injection
    Payload("ssti", "${{aidx{m}}}", True),
    Payload("ssti", "{{aidx{m}}}", True),
    # Command injection
    Payload("cmdi", ";echo aidx{m}", True),
    Payload("cmdi", "|echo aidx{m}", True),
    # CRLF
    Payload("crlf", "%0d%0aX-aidx{m}:1", True),
]

#: The canonical family set — defined by the curated library. The vendored corpus
#: is restricted to these families so a stray family in a data file cannot
#: introduce one the engine has no confirmation contract or copy for.
FAMILIES = sorted({p.family for p in _LIBRARY})


class PayloadProvider:
    """A per-family payload pool with deterministic, seed-rotated selection.

    Merges the curated ``base`` library with any vendored corpus templates for
    the same families. The corpus never introduces a new family (it is loaded
    restricted to ``FAMILIES``); it only deepens an existing family's pool.
    """

    def __init__(
        self,
        base: list[Payload],
        corpus: dict[str, list[str]] | None = None,
    ) -> None:
        by_family: dict[str, list[Payload]] = {}
        for p in base:
            by_family.setdefault(p.family, []).append(p)
        for family, templates in (corpus or {}).items():
            if family not in by_family:
                continue  # defensive: base defines the family set
            existing = {p.template for p in by_family[family]}
            for template in templates:
                if template not in existing:
                    by_family[family].append(Payload(family, template, True))
                    existing.add(template)
        self._by_family = by_family
        self.families = sorted(by_family)

    def rotating_set(self, seed: int, per_family: int = 1) -> list[Payload]:
        """Deterministically pick ``per_family`` payloads from each family for
        this seed.

        Deterministic in ``seed`` so a scan is reproducible, but different seeds
        (a new scan run) rotate to different payloads. The selection is stable
        under corpus growth in the sense that matters — every payload picked is a
        real, metacharacter-bearing probe of its family.
        """
        rng = random.Random(seed)
        chosen: list[Payload] = []
        for family in self.families:
            pool = self._by_family[family]
            k = min(per_family, len(pool))
            chosen.extend(rng.sample(pool, k))
        return chosen


#: The default provider: curated library + vendored corpus, families pinned to
#: the curated set. Built once at import.
_DEFAULT_PROVIDER = PayloadProvider(
    _LIBRARY, reflection_templates(frozenset(FAMILIES))
)


def rotating_set(seed: int, per_family: int = 1) -> list[Payload]:
    """Curated + corpus payloads, ``per_family`` per family, rotated by ``seed``.

    Thin wrapper over the default :class:`PayloadProvider` so the injection
    checks keep calling one stable function.
    """
    return _DEFAULT_PROVIDER.rotating_set(seed, per_family)


def build_families_payload() -> list[dict[str, object]]:
    """Compact per-family view for the AI payload designer: family + examples.

    Examples are drawn from the curated library so the model sees the ``aidx{m}``
    marker convention and the shape expected of each family. No target data.
    """
    by_family: dict[str, list[str]] = {}
    for p in _LIBRARY:
        by_family.setdefault(p.family, []).append(p.template)
    return [{"family": family, "examples": by_family[family]} for family in FAMILIES]


def augmented_provider(extra: dict[str, list[str]] | None) -> PayloadProvider:
    """A provider of curated ∪ corpus ∪ ``extra`` payloads.

    ``extra`` is a per-family map of already-validated templates (the AI payload
    phase runs its proposals through ``payload_corpus.sanitize_family_map``
    first). It is *added* to the pool, never replaces it — so the AI can only
    deepen the rotation, and a family it omits keeps its curated + corpus depth.
    Unknown families in ``extra`` are ignored by :class:`PayloadProvider`.
    """
    corpus = dict(reflection_templates(frozenset(FAMILIES)))
    if extra:
        for family, templates in extra.items():
            corpus[family] = list(corpus.get(family, [])) + list(templates)
    return PayloadProvider(_LIBRARY, corpus)


def apply_ai_payloads(ctx: Any, planner: Any, emit: Any) -> None:
    """Install AI-designed reflection-payload variants onto ``ctx``, DB-free.

    The server lane meters this in ``ai_phases.generate_payloads``; here the
    planner is remote (the service prices each call), so this does only the
    DB-free half: ask for variants, re-validate every string, and deepen the
    rotation pool. Any failure or unusable output leaves the curated + corpus
    rotation and the scan proceeds — a bad or hostile response cannot inject an
    unchecked payload (``sanitize_family_map`` enforces marker/metachar/length).
    """
    from app.engine.payload_corpus import sanitize_family_map

    emit("genai_payloads", getattr(ctx, "progress", 0), "AI designing payload variants")
    try:
        variants_raw, _usages = planner.generate_payloads(build_families_payload())
    except Exception:  # noqa: BLE001 — AI is optional, never fail the scan
        emit("genai_payloads_skipped", 0, "AI payload design unavailable")
        return
    try:
        variants = sanitize_family_map(variants_raw, allowed=frozenset(FAMILIES))
    except Exception:  # noqa: BLE001 — unusable output is a skip
        variants = {}
    if not variants:
        emit("genai_payloads_skipped", 0, "no usable AI payload variants")
        return
    ctx.payload_provider = augmented_provider(variants)
    added = sum(len(v) for v in variants.values())
    emit(
        "genai_payloads_ready", 0,
        f"AI added {added} payload variants across {len(variants)} families",
    )
