"""The vendored payload corpus and the provider that merges it.

These are pure, DB-free tests. They pin the two load-bearing properties of the
corpus (the ``aidx`` marker travels, every payload carries a neutralizable
metacharacter), that families stay within the engine's known set, that the
provider only *grows* the rotation pool, and that ``rotating_set`` keeps its
deterministic, one-per-family-per-scan contract.
"""
from __future__ import annotations

from app.engine import payload_corpus
from app.engine.payloads import (
    _LIBRARY,
    FAMILIES,
    PayloadProvider,
    augmented_provider,
    rotating_set,
)
from app.engine.signatures import SIGNATURE_CLASSES


def _has_metacharacter(s: str) -> bool:
    return any(not (c.isalnum() or c.isspace()) for c in s)


# ---- corpus loader -----------------------------------------------------------

def test_reflection_corpus_loads_and_maps_to_known_families():
    corpus = payload_corpus.reflection_templates(frozenset(FAMILIES))
    assert corpus, "reflection corpus should not be empty"
    assert set(corpus) <= set(FAMILIES)


def test_signature_classes_do_not_draw_from_the_corpus():
    # Signature findings key on family identity, so their presence must be stable
    # across seed rotation; a rotating corpus would make presence payload-dependent.
    # Guard that the classes stay the curated, hand-authored set.
    for sc in SIGNATURE_CLASSES:
        assert 1 <= len(sc.payloads) <= 6, f"{sc.family} payload count looks corpus-sized"


def test_every_corpus_template_carries_the_marker_and_a_metacharacter():
    for family, templates in payload_corpus.reflection_templates(frozenset(FAMILIES)).items():
        for t in templates:
            assert "{m}" in t, f"{family}: {t!r} lost the marker token"
            assert _has_metacharacter(t), f"{family}: {t!r} has no metacharacter"
            assert len(t) <= payload_corpus.MAX_TEMPLATE_LEN + len("aidx{m}")


def test_no_corpus_template_carries_a_raw_control_character():
    # A raw CR/LF/tab in a payload cannot be placed in a URL — httpx raises
    # InvalidURL — which would abort the whole injection check for that point.
    # CRLF probes must be percent-encoded. Pin it so a data edit cannot regress.
    for family, templates in payload_corpus.reflection_templates(None).items():
        for t in templates:
            assert not any(ord(c) < 0x20 for c in t), f"{family}: control char in {t!r}"


def test_per_family_cap_is_respected():
    for family, templates in payload_corpus.reflection_templates().items():
        assert len(templates) <= payload_corpus.MAX_PER_FAMILY, family


def test_bare_marker_without_the_aidx_anchor_is_rejected():
    # A payload carrying `{m}` but not `aidx{m}` would substitute to a markerless
    # token, so the reflection needle never appears — a silently dead payload.
    assert payload_corpus._template("<svg>{m}</svg>") is None
    # The full anchor is kept; a marker-less payload gets the anchor appended.
    assert payload_corpus._template("<svg>aidx{m}</svg>") == "<svg>aidx{m}</svg>"
    assert payload_corpus._template("<svg>") == "<svg>aidx{m}"


def test_plain_alphanumeric_payload_is_dropped():
    # The precision rule: a payload with no neutralizable metacharacter would
    # echo verbatim from a correct target, so it must not survive normalisation.
    assert payload_corpus._template("plainword") is None
    assert payload_corpus._template("") is None
    assert payload_corpus._template("x" * 500) is None
    assert payload_corpus._template("<script>") is not None


def test_missing_file_degrades_to_empty(monkeypatch, tmp_path):
    # A broken/missing data dir must never raise at import or load time.
    monkeypatch.setattr(payload_corpus, "_DATA_DIR", tmp_path)
    assert payload_corpus._load("nope.json", None) == {}


# ---- provider ----------------------------------------------------------------

def test_provider_merges_corpus_and_only_grows_the_pool():
    base = PayloadProvider(_LIBRARY, corpus=None)
    merged = PayloadProvider(
        _LIBRARY, payload_corpus.reflection_templates(frozenset(FAMILIES))
    )
    for family in FAMILIES:
        base_pool = [p for p in base.rotating_set(0, per_family=999) if p.family == family]
        merged_pool = [p for p in merged.rotating_set(0, per_family=999) if p.family == family]
        assert len(merged_pool) >= len(base_pool)
    # No new family is introduced by the corpus.
    assert set(merged.families) == set(FAMILIES)


def test_corpus_never_introduces_a_new_family():
    provider = PayloadProvider(_LIBRARY, {"totally_unknown_family": ["<x>aidx{m}"]})
    assert "totally_unknown_family" not in provider.families


def test_rotating_set_is_deterministic_and_one_per_family():
    a = rotating_set(1234, per_family=1)
    b = rotating_set(1234, per_family=1)
    assert [p.template for p in a] == [p.template for p in b]
    # Exactly one payload per family at per_family=1.
    families = [p.family for p in a]
    assert sorted(families) == sorted(FAMILIES)
    assert len(families) == len(set(families))


def test_different_seeds_rotate():
    # Not a guarantee for every pair, but across a spread the selections differ,
    # which is the whole point of seed rotation.
    sets = {tuple(p.template for p in rotating_set(s, per_family=1)) for s in range(20)}
    assert len(sets) > 1


def test_every_curated_payload_also_carries_marker_and_metacharacter():
    for p in _LIBRARY:
        assert "{m}" in p.template
        assert _has_metacharacter(p.template)


# ---- AI payload sanitisation (Phase 4) --------------------------------------

def test_sanitize_family_map_enforces_the_same_rules_as_the_corpus():
    raw = {
        "xss": [
            "<svg/onload=aidx{m}>",   # good: marker + metachar
            "plainword",              # dropped: no metachar
            "<x>aidx{m}",             # good (has {m} + metachar)
            "<svg/onload=aidx{m}>",   # duplicate of the first, dropped
            "bad\r\nheader",          # dropped: raw control char
            123,                       # dropped: not a string
        ],
        "unknown_family": ["<x>aidx{m}"],  # dropped: not an allowed family
        "sqli": "not-a-list",             # dropped: not a list
    }
    clean = payload_corpus.sanitize_family_map(raw, allowed=frozenset(FAMILIES))
    assert set(clean) == {"xss"}
    assert clean["xss"] == ["<svg/onload=aidx{m}>", "<x>aidx{m}"]


def test_sanitize_family_map_handles_junk_input():
    assert payload_corpus.sanitize_family_map(None) == {}
    assert payload_corpus.sanitize_family_map("nope") == {}
    assert payload_corpus.sanitize_family_map({"xss": ["plainword"]}, frozenset(FAMILIES)) == {}


def test_augmented_provider_adds_variants_without_replacing_the_pool():
    base = augmented_provider(None)
    aug = augmented_provider({"xss": ["<marquee onstart=aidx{m}>"]})
    base_xss = [p for p in base.rotating_set(0, per_family=999) if p.family == "xss"]
    aug_xss = [p for p in aug.rotating_set(0, per_family=999) if p.family == "xss"]
    assert len(aug_xss) == len(base_xss) + 1
    assert any("marquee onstart=aidx{m}" in p.template for p in aug_xss)
    # Other families are untouched, and no new family appears.
    assert set(aug.families) == set(FAMILIES)


def test_augmented_provider_ignores_unknown_family():
    aug = augmented_provider({"totally_unknown": ["<x>aidx{m}"]})
    assert set(aug.families) == set(FAMILIES)
