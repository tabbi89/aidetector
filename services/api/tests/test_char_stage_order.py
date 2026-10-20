"""Characterization: the order a run does things in, read from its events.

``run_scan`` is 159 lines with no seam between stages, so the run-level
invariants it exists to guarantee — plan before the checks, adjudication after
them, triage last, discovery only under ``kali`` — are asserted nowhere. The
event stream is the one place the order is observable from outside, so it is
what these tests pin before ``run_scan`` is restructured into a stage list.

Order is deterministic here because the tests inject a client, which sets engine
concurrency to 1 (``runner.run_scan``: ``concurrency = ... if client is None
else 1``). A production run with the thread pool interleaves the parallel
checks' events; the *phase* markers below are ordered either way, which is why
the strict-sequence assertions are confined to the injected-client path.

These tests are DB-backed and skip when Postgres is unavailable — which is
itself the argument for the ``RunJournal`` port: with a fake journal, every
assertion here becomes a unit test.
"""
from __future__ import annotations

from app.engine.runner import run_scan
from app.models.scan import ScanStatus
from app.scans.run_options import RunOptions
from tests.fakes import FakeCascade, FakePlanner

#: Stages that mark a phase boundary rather than an individual check completing.
PHASE_MARKERS = {
    "start", "identities_unavailable", "plan", "planned", "plan_skipped",
    "genai_payloads", "genai_payloads_ready", "genai_payloads_skipped",
    # Not a phase boundary — a check declining to run. Excluded from
    # ``_phases`` deliberately, so the phase assertions stay about the run's
    # shape rather than about which checks this fixture happens to starve.
    "zap", "zap_done", "zap_skipped",
    "kali", "kali_done", "kali_skipped",
    "adjuncts_skipped", "discovery_probe", "discovery_probed",
    "adjudicate", "adjudicated", "ai_skipped",
    "triage", "cancelled", "error", "done",
}


def _stages(scan) -> list[str]:
    return [e.stage for e in scan.events]


def _phases(scan) -> list[str]:
    return [s for s in _stages(scan) if s in PHASE_MARKERS]


def test_default_run_stage_sequence(db_session, make_scan, engine_client):
    """A bare run: start, the checks that can run in registry order, done.

    A check with nothing to work against is **skipped with a reason** rather
    than run to no effect. That is a deliberate change from emitting its stage
    like any other: a completed stage and an empty findings list read as "we
    looked and it was clean", which for the write oracles on a default run is
    the opposite of the truth — ``mutate`` was off, so nobody looked. The
    ``check_skipped`` events below carry that, and carry what to change.
    """
    scan = make_scan()
    run_scan(db_session, scan, client=engine_client)

    assert scan.status == ScanStatus.completed
    assert _stages(scan) == [
        "start",
        # Read-only id seeding runs before any check is dispatched.
        "id_seed",
        # Declined before the pool is built, so they lead the stream.
        "check_skipped",   # bfla — no privileged operation in this fixture
        "check_skipped",   # resource_consumption — no size parameter
        "check_skipped",   # write_authz — writes off
        "check_skipped",   # seeded_bola — writes off
        "check_skipped",   # mass_assignment — writes off
        "check_skipped",   # race_condition — writes off
        "check_skipped",   # business_flow — writes off
        "check_skipped",   # ssrf — no url-shaped parameter
        "check_skipped",   # oob_injection — no OAST collector
        "check_skipped",   # schema_fuzz — fuzzing off
        "check_skipped",   # unsafe_consumption — premium/OAST off
        # parallel group, in registry order
        "bola", "broken_auth", "security_headers", "info_disclosure",
        "data_exposure", "potential_secrets", "enumeration", "reflected_injection",
        "signature_injection", "tls_config",
        "host_header",
        "design_review",
        "advanced_rate_limit",
        "xxe_confirmation",
        "jwt_confusion",
        "deserialization",
        "graphql_introspection",
        "graphql_behavior",
        "request_smuggling",
        "grpc_reflection",
        "done",
    ], [(event.stage, event.message) for event in scan.events]


def test_a_default_run_says_why_the_write_checks_did_not_run(
    db_session, make_scan, engine_client
):
    """The report must not let "never ran" pass for "found nothing"."""
    scan = make_scan()
    run_scan(db_session, scan, client=engine_client)

    skipped = {
        e.message.split(" did not run: ")[0]: e.message.split(" did not run: ")[1]
        for e in scan.events
        if e.stage == "check_skipped"
    }
    assert "mutate" in skipped["write_authz"]
    assert "OAST_SERVER" in skipped["oob_injection"]
    # And the checks that *did* run are not in there.
    assert "bola" not in skipped


def test_mutating_run_moves_the_writing_checks_into_the_serial_group(
    db_session, make_scan, engine_client
):
    """The concurrency partition, pinned through observable behaviour.

    Under ``mutate`` these may write, so the runner moves them out of the thread
    pool. ``test_char_serial_partition.py`` pins the same fact from the
    constants; this pins it from the outside, which is what must not change when
    those constants move onto the checks.

    ``race_condition`` and ``schema_fuzz`` are absent even here, and correctly:
    a burst needs a transport that can fire one (the sync test client cannot)
    and fuzzing needs its own flag. Both now say so instead of running to no
    effect — which is what the assertion on ``check_skipped`` below pins.
    """
    scan = make_scan()
    run_scan(db_session, scan, options=RunOptions(mutate=True), client=engine_client)

    stages = _stages(scan)
    assert stages.index("bola") > stages.index("tls_config")
    assert stages.index("mass_assignment") > stages.index("tls_config")
    assert stages[-1] == "done"

    skipped = {
        e.message.split(" did not run: ")[0]
        for e in scan.events
        if e.stage == "check_skipped"
    }
    assert {"race_condition", "schema_fuzz"} <= skipped
    # ``write_authz`` joins them: this fixture's minimal spec declares no
    # create-plus-read-back pair, so there is no way to prove a write persisted.
    # That is the diagnosis a user of a real spec needs, and it used to be
    # indistinguishable from a clean result.
    assert "write_authz" in skipped
    # The writing checks that *can* run are not among them.
    assert not ({"seeded_bola", "mass_assignment"} & skipped)


def test_all_flags_phase_order(db_session, make_scan, engine_client):
    """Every optional phase on: planning first, adjudication after the engine.

    ZAP and Kali are unconfigured in tests, so they degrade to ``*_skipped``
    — which is the graceful-degradation property, and it also places the adjunct
    phase between the engine tier and adjudication.
    """
    scan = make_scan()
    run_scan(
        db_session, scan,
        options=RunOptions(
            plan=True, adjudicate=True, mutate=True, fuzz=True,
            zap=True, kali=True, confirm=True,
        ),
        client=engine_client,
        planner=FakePlanner(priority_for=lambda path: "high"),
        cascade=FakeCascade(),
    )

    assert scan.status == ScanStatus.completed
    assert _phases(scan) == [
        "start",
        "plan", "planned",          # before the engine tier — it reorders operations
        "zap_skipped", "kali_skipped",   # adjunct phase, after the engine tier
        "adjudicate", "adjudicated",     # AI last, over the findings the engine made
        "done",
    ]


def test_discovery_probe_does_not_run_without_kali(db_session, make_scan, engine_client):
    """Discovery is fed by the Kali adjuncts, so it cannot run without them."""
    scan = make_scan()
    run_scan(db_session, scan, options=RunOptions(mutate=True), client=engine_client)
    assert "discovery_probe" not in _stages(scan)


def test_single_identity_scan_says_so_before_the_checks_run(
    db_session, make_scan, engine_client
):
    """A run that cannot do cross-identity work reports that, rather than
    looking like a run that did it and found nothing.

    Emitted up front, before any check, so it reads as a property of the scan's
    inputs rather than as a per-check failure.
    """
    scan = make_scan(identities=[("alice", "user")])
    run_scan(db_session, scan, options=RunOptions(mutate=True), client=engine_client)

    stages = _stages(scan)
    assert "identities_unavailable" in stages
    assert stages.index("identities_unavailable") < stages.index("bola")


def test_two_identities_do_not_emit_the_warning(db_session, make_scan, engine_client):
    scan = make_scan()   # the default fixture supplies alice + admin
    run_scan(db_session, scan, client=engine_client)
    assert "identities_unavailable" not in _stages(scan)


def test_same_role_identities_do_not_emit_the_warning(
    db_session, make_scan, engine_client
):
    """Two names, one role, is two identities — the C2 fix, seen from the runner."""
    scan = make_scan(identities=[("alice", "user"), ("bob", "user")])
    run_scan(db_session, scan, options=RunOptions(mutate=True), client=engine_client)
    assert "identities_unavailable" not in _stages(scan)


def test_cancel_lands_at_a_stage_boundary(db_session, make_scan, engine_client):
    """A cancel requested before the run stops it and records ``cancelled``."""
    scan = make_scan(cancel=True)
    run_scan(db_session, scan, client=engine_client)

    assert scan.status == ScanStatus.cancelled
    assert _stages(scan)[-1] == "cancelled"
    assert "done" not in _stages(scan)


def test_progress_is_monotonic_and_completes_at_100(db_session, make_scan, engine_client):
    scan = make_scan()
    run_scan(db_session, scan, client=engine_client)
    pcts = [e.pct for e in scan.events]
    assert pcts == sorted(pcts)
    assert scan.progress == 100


def test_disallowed_grant_url_is_blocked_not_fetched(db_session, make_scan, engine_client):
    """A credential grant/refresh URL is egress; the runner blocks cloud metadata.

    The scan target is guarded at the run endpoint, but a grant's ``token_url``
    (and ``refresh_url``) are fetched by the worker too. A blocked URL is
    neutered and removed from the run — never firing a request at the forbidden
    host, never reusing its client secret as a bearer token, and never aborting.
    """
    from app.core.vault import encrypt
    from app.domain.enums import AuthType, GrantType
    from app.models.credential import CredentialProfile

    scan = make_scan()
    scan.credential_profiles.append(
        CredentialProfile(
            name="svc",
            role="service",
            auth_type=AuthType.bearer,
            header_name=None,
            secret_ref=encrypt("sh"),
            grant_type=GrantType.client_credentials,
            token_url="http://169.254.169.254/latest/meta-data",
            grant_params={"client_id": "svc"},
        )
    )
    db_session.commit()

    run_scan(db_session, scan, client=engine_client)

    assert scan.status == ScanStatus.completed
    assert any(e.stage == "egress_blocked" for e in scan.events)
    assert any(e.stage == "auth_grant_failed" for e in scan.events)
    assert all(row.get("identity") != "svc" for row in scan.runs[-1].mutations)
    assert "Bearer sh" not in str(scan.runs[-1].mutations)


def test_a_grant_mints_through_the_runner(db_session, make_scan, engine_client):
    """A grant credential mints its token at scan start (the happy path)."""
    from app.core.vault import encrypt
    from app.domain.enums import AuthType, GrantType
    from app.models.credential import CredentialProfile

    scan = make_scan()
    scan.credential_profiles.append(
        CredentialProfile(
            name="svc",
            role="service",
            auth_type=AuthType.bearer,
            header_name=None,
            secret_ref=encrypt("sh"),
            grant_type=GrantType.client_credentials,
            token_url="http://testserver/oauth/token",
            grant_params={"client_id": "svc"},
        )
    )
    db_session.commit()

    run_scan(db_session, scan, client=engine_client)

    assert scan.status == ScanStatus.completed
    # A successful mint emits no failure and no egress block.
    assert not any(e.stage == "auth_grant_failed" for e in scan.events)
    assert not any(e.stage == "egress_blocked" for e in scan.events)


def test_a_routing_warning_reaches_the_log_of_the_run_it_explains(
    db_session, make_scan, engine_client
):
    """A spec/target path mismatch is re-emitted per run, not only at upload.

    ``ingest_spec`` records the warning when the spec lands, but ``begin``
    clears events because an event describes one run. Without re-emitting, the
    one warning that explains a wall of 404s would be missing from exactly the
    run that produced them.
    """
    import json

    from app.scans.operations import ingest_spec

    spec = {
        "openapi": "3.0.0",
        "info": {"title": "t", "version": "1"},
        "servers": [{"url": "https://api.example.com/v2"}],
        "paths": {"/users": {"get": {"responses": {"200": {"description": "ok"}}}}},
    }
    scan = make_scan()
    scan.target_base_url = "http://testserver/api"
    db_session.commit()
    ingest_spec(db_session, scan, json.dumps(spec))
    db_session.commit()
    assert any(e.stage == "spec_warning" for e in scan.events)

    run_scan(db_session, scan, client=engine_client)

    warnings = [e.message for e in scan.events if e.stage == "spec_warning"]
    assert warnings and "/v2" in warnings[0]
    # "start" still leads the stream; the warning follows it.
    assert _stages(scan)[0] == "start"
