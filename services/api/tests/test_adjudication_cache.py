"""The AI verdict cache: one identity, shared with triage and the run diff.

A re-scan replaces every finding row, so without a durable cache the same
findings would be re-adjudicated — and re-paid for — on every run. The cache is
keyed on ``Finding.fingerprint``, the identity ``append_finding`` stamps and
``engine/fingerprint.py`` governs.

It used to have a scheme of its own: ``sha256(check|owasp_id|title)``. Titles are
not stable for every check — the header checks carry endpoint counts and
``mass_assignment`` carries the probed field name — so editing a title for
readability silently invalidated a paid cache, and no test failed. Grown from
``test_char_adjudication_cache.py``, which recorded that divergence.

The tests that mattered then still matter now: a re-run over unchanged findings
must call the cascade zero times.
"""
from __future__ import annotations

from app.ai.types import HYBRID_CHECKS
from app.domain.enums import Verdict
from app.engine.fingerprint import fingerprint
from app.engine.runner import run_scan
from app.models.adjudication import AdjudicationCache
from app.scans.run_options import RunOptions
from tests.fakes import FakeCascade

ADJUDICATE = RunOptions(adjudicate=True)


def _hybrid(scan) -> list:
    return [f for f in scan.findings if f.check in HYBRID_CHECKS]


def _cache_rows(db_session, scan) -> list[AdjudicationCache]:
    return db_session.query(AdjudicationCache).filter_by(scan_id=scan.id).all()


# ---- the cache does its job ---------------------------------------------------


def test_first_run_adjudicates_and_populates_the_cache(
    db_session, make_scan, engine_client
):
    scan = make_scan()
    cascade = FakeCascade()
    run_scan(db_session, scan, options=ADJUDICATE, client=engine_client, cascade=cascade)

    assert cascade.calls == 1
    assert _hybrid(scan), "vulnapp must produce at least one HYBRID finding"
    assert all(f.verdict is Verdict.confirmed for f in _hybrid(scan))

    cached = _cache_rows(db_session, scan)
    assert len(cached) == len({f.fingerprint for f in _hybrid(scan)})


def test_rerun_over_unchanged_findings_spends_nothing(
    db_session, make_scan, engine_client
):
    """The property the cache exists for.

    A re-scan replaces every finding row, so the verdicts can only come back
    from the cache. If this fails, re-running a scan silently costs tokens.
    """
    scan = make_scan()
    cascade = FakeCascade()
    run_scan(db_session, scan, options=ADJUDICATE, client=engine_client, cascade=cascade)
    assert cascade.calls == 1

    run_scan(db_session, scan, options=ADJUDICATE, client=engine_client, cascade=cascade)
    assert cascade.calls == 1, (
        "the second run called the cascade again — every re-scan now re-spends "
        "tokens on findings that were already adjudicated"
    )
    assert all(f.verdict is Verdict.confirmed for f in _hybrid(scan))


def test_cached_verdicts_survive_the_findings_being_replaced(
    db_session, make_scan, engine_client
):
    """Findings are new rows each run; the cache is what carries the verdict."""
    scan = make_scan()
    run_scan(db_session, scan, options=ADJUDICATE, client=engine_client,
             cascade=FakeCascade())
    first_ids = {f.id for f in _hybrid(scan)}

    run_scan(db_session, scan, options=ADJUDICATE, client=engine_client,
             cascade=FakeCascade(verdict_for=lambda check: "dismissed"))
    second = _hybrid(scan)

    assert first_ids.isdisjoint({f.id for f in second})   # genuinely new rows
    # ...and the cache answered, so the second cascade's verdict was never used.
    assert all(f.verdict is Verdict.confirmed for f in second)


# ---- one identity, not two ----------------------------------------------------


def test_the_cache_is_keyed_on_the_finding_fingerprint(
    db_session, make_scan, engine_client
):
    """The regression guard for the scheme this file grew out of.

    Two identity schemes meant the cache could drift from triage and the diff
    without anything failing. Asserted directly: every cached key is a
    fingerprint of a finding this run recorded.
    """
    scan = make_scan()
    run_scan(db_session, scan, options=ADJUDICATE, client=engine_client,
             cascade=FakeCascade())

    cached_keys = {row.fingerprint for row in _cache_rows(db_session, scan)}
    finding_keys = {f.fingerprint for f in _hybrid(scan)}

    assert cached_keys
    assert cached_keys <= finding_keys
    # The canonical fingerprint is 32 hex; the retired title hash was 64, which
    # is what migration 0016 keys its cleanup on.
    assert all(len(k) == 32 for k in cached_keys)


def test_the_cache_key_ignores_a_title_that_only_carries_run_detail() -> None:
    """Why the title was the wrong basis.

    A grouped header finding's title contains how many endpoints were affected,
    so putting one endpoint back in scope changed the old key and re-spent
    tokens on a finding nothing about which had actually changed. The identity
    the cache now uses is built from evidence and ignores exactly that.
    """
    evidence = {"missing": ["content-security-policy"], "weak": {}}
    before = fingerprint("security_headers", "API8:2023", "Missing on 11/40 endpoints", evidence)
    after = fingerprint("security_headers", "API8:2023", "Missing on 12/40 endpoints", evidence)
    assert before == after


def test_a_finding_with_no_fingerprint_is_adjudicated_but_not_cached(
    db_session, make_scan, engine_client
):
    """Rows predating the fingerprint column must not collide in the cache.

    ``AdjudicationCache`` is unique on ``(scan_id, fingerprint)``, so caching
    two such findings under an empty key would raise. They are still reviewed —
    they simply do not persist a verdict.
    """
    scan = make_scan()
    run_scan(db_session, scan, options=ADJUDICATE, client=engine_client,
             cascade=FakeCascade())

    # Simulate legacy rows: blank the fingerprints and clear the cache, then
    # re-adjudicate. Nothing should be written, and nothing should raise.
    for f in _hybrid(scan):
        f.fingerprint = ""
    for row in _cache_rows(db_session, scan):
        db_session.delete(row)
    db_session.commit()

    from app.engine.ai_phases import adjudicate_findings

    cascade = FakeCascade()
    adjudicate_findings(db_session, scan, cascade, lambda *a: None)
    db_session.commit()

    assert cascade.calls == 1
    assert all(f.verdict is Verdict.confirmed for f in _hybrid(scan))
    assert _cache_rows(db_session, scan) == []
