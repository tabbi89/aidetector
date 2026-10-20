"""Ownership verification for public targets, and pinning the address it judged.

The threat these pin down: a target exempt from proof *because* it is private
(``localhost``) must not become a public machine through a second DNS answer or
an edited ``/etc/hosts``, and a name the workspace owns must not prove anything
about an address it doesn't (``victim.attacker.com A <someone else>``).
"""
from __future__ import annotations

import json
from ipaddress import ip_address

import httpx
import pytest

from app.core import ownership
from app.core.config import settings
from app.core.ownership import OwnershipNotProven
from app.core.pinning import PinnedTransport, PinPolicy, pinned_request
from app.core.target_guard import TargetNotAllowed
from app.models.domain import DomainVerification
from app.scans import domains, workspace

PUBLIC = "93.184.216.34"
TOKEN = "a" * 32


def _resolver(monkeypatch, module, answers: dict[str, list[str]]):
    calls: list[str] = []

    def resolve(host: str):
        calls.append(host)
        return [ip_address(a) for a in answers.get(host, [])]

    monkeypatch.setattr(module, "resolve_host", resolve)
    return calls


# ---- pinning -------------------------------------------------------------------


def test_pinned_request_keeps_host_header_and_sni():
    request = httpx.Request("GET", "https://api.example.com:8443/items?x=1")
    pinned = pinned_request(request, PUBLIC)
    assert pinned.url.host == PUBLIC
    assert pinned.url.port == 8443 and pinned.url.path == "/items"
    assert pinned.headers["host"] == "api.example.com:8443"
    assert pinned.extensions["sni_hostname"] == "api.example.com"


def test_pinned_transport_connects_to_the_judged_address(monkeypatch):
    import app.core.pinning as pinning

    _resolver(monkeypatch, pinning, {"api.example.com": [PUBLIC]})
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text="ok")

    transport = PinnedTransport(PinPolicy(allow_private=True), httpx.MockTransport(handler))
    with httpx.Client(transport=transport) as client:
        response = client.get("http://api.example.com/x")
    assert seen[0].url.host == PUBLIC
    assert seen[0].headers["host"] == "api.example.com"
    # Downstream code still sees the name it asked for.
    assert response.request.url.host == "api.example.com"


def test_private_only_target_refuses_a_public_answer(monkeypatch):
    """The /etc/hosts case: ``localhost`` was exempt because it was private."""
    import app.core.pinning as pinning

    _resolver(monkeypatch, pinning, {"localhost": [PUBLIC]})
    policy = PinPolicy(allow_private=True, private_only=["localhost"])
    with pytest.raises(TargetNotAllowed, match="public address"):
        policy.address_for("localhost")


def test_first_resolution_wins_against_rebinding(monkeypatch):
    import app.core.pinning as pinning

    answers = {"lab.internal": ["10.0.0.5"]}
    calls = _resolver(monkeypatch, pinning, answers)
    policy = PinPolicy(allow_private=True, private_only=["lab.internal"])
    assert policy.address_for("lab.internal") == "10.0.0.5"
    answers["lab.internal"] = [PUBLIC]  # the rebinding answer
    assert policy.address_for("lab.internal") == "10.0.0.5"
    assert calls == ["lab.internal"]


def test_pinning_never_reaches_metadata(monkeypatch):
    import app.core.pinning as pinning

    _resolver(monkeypatch, pinning, {"idp.example.com": ["169.254.169.254"]})
    with pytest.raises(TargetNotAllowed, match="metadata"):
        PinPolicy(allow_private=True).address_for("idp.example.com")
    with pytest.raises(TargetNotAllowed, match="metadata"):
        PinPolicy(allow_private=True).address_for("[::ffff:169.254.169.254]")


def test_seeded_pin_is_not_re_resolved(monkeypatch):
    import app.core.pinning as pinning

    calls = _resolver(monkeypatch, pinning, {})
    policy = PinPolicy(pins={"api.example.com": PUBLIC})
    assert policy.address_for("API.example.com.") == PUBLIC
    assert calls == []


# ---- the two proofs ------------------------------------------------------------


def _doh(status: int, *answers: str) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["type"] == "TXT"
        assert request.url.params["name"] == "_aidetector-challenge.api.example.com"
        return httpx.Response(
            200,
            content=json.dumps(
                {"Status": status, "Answer": [{"type": 16, "data": a} for a in answers]}
            ),
        )

    return httpx.MockTransport(handler)


def test_dns_txt_matches_a_split_record():
    # A long TXT value arrives as several quoted character-strings.
    data = f'"aidetector-verify={TOKEN[:10]}" "{TOKEN[10:]}"'
    ownership.check_dns_txt(
        "api.example.com", TOKEN, doh_url="https://doh.test/q", transport=_doh(0, data)
    )


@pytest.mark.parametrize(
    "status,answers,match",
    [
        (3, (), "no TXT record"),
        (0, ('"aidetector-verify=someone-else"',), "does not contain"),
        (0, ('"v=spf1 -all"',), "does not contain"),
    ],
)
def test_dns_txt_rejects(status, answers, match):
    with pytest.raises(OwnershipNotProven, match=match):
        ownership.check_dns_txt(
            "api.example.com",
            TOKEN,
            doh_url="https://doh.test/q",
            transport=_doh(status, *answers),
        )


def test_dns_txt_is_not_asked_of_an_ip_literal():
    ownership.check_dns_txt(PUBLIC, TOKEN, doh_url="https://doh.test/q", transport=None)


def _serving(status: int, body: str, seen: list[httpx.Request]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, text=body, headers={"location": "https://elsewhere/"})

    return httpx.MockTransport(handler)


def test_http_token_is_fetched_from_the_pinned_address():
    seen: list[httpx.Request] = []
    ownership.check_http_token(
        "https://api.example.com/v1/base",
        TOKEN,
        address=PUBLIC,
        inner=_serving(200, TOKEN + "\n", seen),
    )
    (request,) = seen
    assert request.url.host == PUBLIC
    assert request.headers["host"] == "api.example.com"
    # The origin's well-known path, never under the API's base path.
    assert request.url.path == f"/.well-known/aidetector-verify/{TOKEN}"


def test_http_token_accepts_the_txt_value():
    # The page may show the TXT record's own string; it carries the same token.
    ownership.check_http_token(
        "https://api.example.com",
        TOKEN,
        address=PUBLIC,
        inner=_serving(200, f"aidetector-verify={TOKEN}\n", []),
    )


@pytest.mark.parametrize(
    "status,body,match",
    [
        (301, "", "redirects are not followed"),
        (404, "", "answered 404"),
        (200, "", "empty body"),
        (200, f"prefix {TOKEN} suffix", "wrapped in other content"),
        (200, "<html>welcome</html>", "did not return"),
    ],
)
def test_http_token_rejects(status, body, match):
    with pytest.raises(OwnershipNotProven, match=match):
        ownership.check_http_token(
            "https://api.example.com",
            TOKEN,
            address=PUBLIC,
            inner=_serving(status, body, []),
        )


@pytest.mark.parametrize(
    "address,allow_private,match",
    [
        ("10.0.0.5", False, "non-public address"),
        ("169.254.169.254", True, "metadata"),
    ],
)
def test_http_token_never_dials_an_address_its_policy_refuses(address, allow_private, match):
    # A pinned address is not re-judged by the transport, so the proof judges it
    # before the fetch: the server never probes a network its own flag protects.
    seen: list[httpx.Request] = []
    with pytest.raises(TargetNotAllowed, match=match):
        ownership.check_http_token(
            "https://api.example.com",
            TOKEN,
            address=address,
            inner=_serving(200, TOKEN, seen),
            allow_private=allow_private,
        )
    assert seen == []


@pytest.mark.parametrize("raw", ["https://api.example.com", "api.example.com/x", "a.b:443", ""])
def test_host_must_be_a_host(raw):
    with pytest.raises(ValueError):
        ownership.normalize_host(raw)


def test_host_is_normalised():
    assert ownership.normalize_host(" API.Example.com. ") == "api.example.com"
    assert ownership.normalize_host("[2606:2800:220:1::]") == "2606:2800:220:1::"


# ---- each proof reported separately ---------------------------------------------


def test_prove_each_reports_dns_passing_and_http_failing():
    results = domains.prove_each(
        "https://api.example.com",
        TOKEN,
        address=PUBLIC,
        transports=domains.ProofTransports(
            dns=_doh(0, f'"aidetector-verify={TOKEN}"'),
            http=_serving(404, "", []),
        ),
    )
    assert [(r.proof, r.ok) for r in results] == [("dns", True), ("http", False)]
    assert results[0].detail is None
    assert "answered 404" in results[1].detail


def test_prove_each_runs_the_http_proof_even_when_dns_fails():
    results = domains.prove_each(
        "https://api.example.com",
        TOKEN,
        address=PUBLIC,
        transports=domains.ProofTransports(
            dns=_doh(3),
            http=_serving(200, "<html>welcome</html>", []),
        ),
    )
    assert [(r.proof, r.ok) for r in results] == [("dns", False), ("http", False)]
    assert "no TXT record" in results[0].detail
    assert "did not return" in results[1].detail


def test_prove_each_skips_dns_for_an_ip_literal():
    def never(request: httpx.Request) -> httpx.Response:
        pytest.fail("an IP literal has no name to prove")

    results = domains.prove_each(
        f"https://{PUBLIC}",
        TOKEN,
        address=PUBLIC,
        transports=domains.ProofTransports(
            dns=httpx.MockTransport(never),
            http=_serving(200, TOKEN + "\n", []),
        ),
    )
    assert [(r.proof, r.ok) for r in results] == [("http", True)]


# ---- the gate ------------------------------------------------------------------


def _record(db_session, host: str, tenant: str = "default") -> DomainVerification:
    workspace.ensure_tenant(db_session, tenant)
    row = DomainVerification(tenant_slug=tenant, host=host, token=TOKEN)
    db_session.add(row)
    db_session.commit()
    return row


def test_public_target_without_proof_is_refused(db_session, monkeypatch):
    _resolver(monkeypatch, domains, {"api.example.com": [PUBLIC]})
    with pytest.raises(OwnershipNotProven, match="Workspace → Domains"):
        domains.clear_target(db_session, "default", "https://api.example.com")


def test_a_name_resolving_partly_public_needs_proof(db_session, monkeypatch):
    _resolver(monkeypatch, domains, {"mixed.example.com": ["10.0.0.5", PUBLIC]})
    with pytest.raises(OwnershipNotProven):
        domains.clear_target(db_session, "default", "https://mixed.example.com")


def test_proven_target_is_cleared_and_pinned(db_session, monkeypatch):
    _resolver(monkeypatch, domains, {"api.example.com": [PUBLIC]})
    _record(db_session, "api.example.com")
    seen: list[httpx.Request] = []
    data = f'"aidetector-verify={TOKEN}"'

    def doh(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=json.dumps({"Status": 0, "Answer": [{"type": 16, "data": data}]})
        )

    clearance = domains.clear_target(
        db_session,
        "default",
        "https://api.example.com/v1",
        transports=domains.ProofTransports(
            dns=httpx.MockTransport(doh), http=_serving(200, TOKEN, seen)
        ),
    )
    assert clearance.exempt is None and clearance.address == PUBLIC
    assert seen[0].url.host == PUBLIC
    assert clearance.runner_policy() == {"private_only": False, "verification_token": TOKEN}


def test_a_private_lane_override_never_proves_through_a_private_address(
    db_session, monkeypatch
):
    # The local-runner claim lets a private target past the egress check, but a
    # name that also resolves publicly still needs proof — and this server
    # fetches it. With the server's own flag off, it must dial the public
    # address, not probe the private network on a tenant's behalf.
    monkeypatch.setattr(settings, "target_allow_private", False)
    _resolver(monkeypatch, domains, {"mixed.example.com": ["10.0.0.5", PUBLIC]})
    _record(db_session, "mixed.example.com")
    seen: list[httpx.Request] = []
    data = f'"aidetector-verify={TOKEN}"'

    def doh(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=json.dumps({"Status": 0, "Answer": [{"type": 16, "data": data}]})
        )

    clearance = domains.clear_target(
        db_session,
        "default",
        "https://mixed.example.com",
        transports=domains.ProofTransports(
            dns=httpx.MockTransport(doh), http=_serving(200, TOKEN, seen)
        ),
        allow_private=True,
    )
    assert [r.url.host for r in seen] == [PUBLIC]
    assert clearance.address == PUBLIC and clearance.token == TOKEN


def test_another_workspace_s_record_proves_nothing(db_session, monkeypatch):
    _resolver(monkeypatch, domains, {"api.example.com": [PUBLIC]})
    _record(db_session, "api.example.com", tenant="someone-else")
    with pytest.raises(OwnershipNotProven):
        domains.clear_target(db_session, "default", "https://api.example.com")


def test_private_target_is_exempt_but_pinned_private(db_session, monkeypatch):
    _resolver(monkeypatch, domains, {"localhost": ["127.0.0.1"]})
    clearance = domains.clear_target(db_session, "default", "http://localhost:9000")
    assert clearance.exempt == "private" and clearance.address == "127.0.0.1"
    assert clearance.runner_policy() == {"private_only": True, "verification_token": None}
    assert clearance.pin_policy().address_for("localhost") == "127.0.0.1"


def test_unresolvable_lab_name_is_exempt_private(db_session, monkeypatch):
    _resolver(monkeypatch, domains, {})
    clearance = domains.clear_target(db_session, "default", "http://target:9000")
    assert clearance.exempt == "private" and clearance.address is None


def test_allowlisted_and_disabled_are_exempt(db_session, monkeypatch):
    _resolver(monkeypatch, domains, {"api.example.com": [PUBLIC]})
    monkeypatch.setattr(settings, "target_allowlist", ".example.com")
    assert domains.clear_target(db_session, "default", "https://api.example.com").exempt == (
        "allowlist"
    )
    monkeypatch.setattr(settings, "target_allowlist", "")
    monkeypatch.setattr(settings, "target_require_verification", False)
    assert domains.clear_target(db_session, "default", "https://api.example.com").exempt == (
        "disabled"
    )


def test_gate_still_answers_egress_policy(db_session, monkeypatch):
    _resolver(monkeypatch, domains, {"evil.example.com": ["169.254.169.254"]})
    with pytest.raises(TargetNotAllowed, match="metadata"):
        domains.clear_target(db_session, "default", "http://evil.example.com")


def test_worker_repeats_the_gate_at_scan_start(db_session, make_scan, engine_client):
    from app.engine.runner import run_scan

    scan = make_scan(target_base_url=f"http://{PUBLIC}")
    with pytest.raises(OwnershipNotProven):
        run_scan(db_session, scan, client=engine_client)


# ---- routes --------------------------------------------------------------------


def test_run_and_schedule_refuse_an_unproven_public_target(client, scan_with_spec):
    sid = scan_with_spec(f"http://{PUBLIC}")
    for method, path, body in (
        ("post", f"/scans/{sid}/run", {"authorized": True}),
        ("put", f"/scans/{sid}/schedule", {"minutes": 60, "authorized": True}),
    ):
        r = getattr(client, method)(path, json=body)
        assert r.status_code == 422, r.text
        assert "target not verified" in r.json()["detail"]


def test_schedule_accepts_a_proven_public_target(client, scan_with_spec, monkeypatch):
    proofs: list[tuple[str, str | None]] = []
    monkeypatch.setattr(
        domains, "prove", lambda url, token, *, address, transports=None: proofs.append(
            (url, address)
        )
    )
    sid = scan_with_spec(f"http://{PUBLIC}")
    assert client.post("/workspace/domains", json={"host": PUBLIC}).status_code == 201
    r = client.put(f"/scans/{sid}/schedule", json={"minutes": 60, "authorized": True})
    assert r.status_code == 200, r.text
    assert proofs == [(f"http://{PUBLIC}", PUBLIC)]


def test_local_claim_carries_the_target_policy(client, scan_with_spec, monkeypatch):
    monkeypatch.setattr(settings, "local_runner_enabled", True)
    sid = scan_with_spec("http://127.0.0.1:9000")
    r = client.post(f"/scans/{sid}/local-runs", json={"authorized": True})
    assert r.status_code == 201, r.text
    assert r.json()["target_policy"] == {"private_only": True, "verification_token": None}


def test_ownership_status_answers_before_the_run(client, scan_with_spec, monkeypatch):
    """The run panel learns a public target needs proving before a run is refused."""

    def never(*args, **kwargs):
        pytest.fail("the status check must not fetch proof from the target")

    monkeypatch.setattr(domains, "prove", never)
    sid = scan_with_spec(f"http://{PUBLIC}")
    assert client.get(f"/scans/{sid}/ownership").json() == {
        "host": PUBLIC,
        "allowed": True,
        "required": True,
        "exempt": None,
        "domain_id": None,
        "verified_at": None,
        "last_error": None,
        "reason": None,
    }

    added = client.post("/workspace/domains", json={"host": PUBLIC}).json()
    listed = client.get(f"/scans/{sid}/ownership").json()
    assert listed["required"] and listed["domain_id"] == added["id"]
    assert listed["verified_at"] is None

    private = client.get(f"/scans/{scan_with_spec('http://127.0.0.1:9000')}/ownership").json()
    assert private["allowed"] and not private["required"] and private["exempt"] == "private"

    monkeypatch.setattr(settings, "target_require_verification", False)
    off = client.get(f"/scans/{sid}/ownership").json()
    assert not off["required"] and off["exempt"] == "disabled"


def test_ownership_status_reports_a_refused_target(client, scan_with_spec, monkeypatch):
    sid = scan_with_spec("http://10.0.0.5")
    monkeypatch.setattr(settings, "target_allow_private", False)
    status = client.get(f"/scans/{sid}/ownership").json()
    assert not status["allowed"] and not status["required"]
    assert status["host"] == "10.0.0.5" and status["reason"]


def test_domain_routes(client, monkeypatch):
    r = client.post("/workspace/domains", json={"host": "API.example.com."})
    assert r.status_code == 201, r.text
    row = r.json()
    assert row["host"] == "api.example.com" and row["verified_at"] is None
    assert row["dns_record_name"] == "_aidetector-challenge.api.example.com"
    assert row["dns_record_value"] == f"aidetector-verify={row['token']}"
    assert row["http_path"] == f"/.well-known/aidetector-verify/{row['token']}"
    assert row["http_url"] == (
        f"https://api.example.com/.well-known/aidetector-verify/{row['token']}"
    )

    assert client.post("/workspace/domains", json={"host": "api.example.com"}).status_code == 409
    assert client.post("/workspace/domains", json={"host": "https://x.io"}).status_code == 422
    verify = f"/workspace/domains/{row['id']}/verify"
    assert client.post(verify, json={"url": "https://other.example.com"}).status_code == 422

    def http_failed(url, token, *, address, transports=None):
        return [
            domains.ProofResult("dns", True),
            domains.ProofResult("http", False, f"{url} did not return the verification token"),
        ]

    monkeypatch.setattr(domains, "prove_each", http_failed)
    monkeypatch.setattr(domains, "resolve_host", lambda host: [ip_address(PUBLIC)])
    checked = client.post(verify, json={})
    assert checked.status_code == 200
    body = checked.json()
    assert body["last_checks"] == [
        {"proof": "dns", "ok": True, "detail": None},
        {
            "proof": "http",
            "ok": False,
            "detail": "https://api.example.com did not return the verification token",
        },
    ]
    assert body["verified_at"] is None
    assert body["last_error"] == body["last_checks"][1]["detail"]

    monkeypatch.setattr(
        domains,
        "prove_each",
        lambda url, token, *, address, transports=None: [
            domains.ProofResult("dns", True),
            domains.ProofResult("http", True),
        ],
    )
    checked = client.post(verify, json={"url": "http://api.example.com:8080"}).json()
    assert checked["verified_at"] and checked["last_error"] is None
    assert checked["last_checks"] == [
        {"proof": "dns", "ok": True, "detail": None},
        {"proof": "http", "ok": True, "detail": None},
    ]

    assert [d["host"] for d in client.get("/workspace/domains").json()] == ["api.example.com"]
    assert client.delete(f"/workspace/domains/{row['id']}").status_code == 200
    assert client.get("/workspace/domains").json() == []


# ---- the local runner ----------------------------------------------------------


def test_runner_refuses_a_private_cleared_target_that_resolves_public(monkeypatch):
    """The server saw ``localhost``; this machine's /etc/hosts says otherwise."""
    import app.core.pinning as pinning
    from app.runner import main

    _resolver(monkeypatch, pinning, {"localhost": [PUBLIC]})
    _resolver(monkeypatch, main, {"localhost": [PUBLIC]})
    run = {"target_policy": {"private_only": True, "verification_token": None}}
    with pytest.raises(TargetNotAllowed, match="public address"):
        main._target_pins(run, "http://localhost:9000")


def test_runner_repeats_the_http_proof_from_its_own_address(monkeypatch):
    import app.core.pinning as pinning
    from app.runner import main

    _resolver(monkeypatch, pinning, {"api.example.com": ["203.0.113.9"]})
    _resolver(monkeypatch, main, {"api.example.com": ["203.0.113.9"]})
    fetched: list[tuple[str, str | None]] = []
    monkeypatch.setattr(
        main,
        "check_http_token",
        lambda url, token, *, address, timeout: fetched.append((token, address)),
    )
    run = {"target_policy": {"private_only": False, "verification_token": TOKEN}}
    pins = main._target_pins(run, "https://api.example.com")
    assert fetched == [(TOKEN, "203.0.113.9")]
    assert pins.address_for("api.example.com") == "203.0.113.9"


# ---- review fixes: one host spelling, raw sockets, unpinned tools --------------


def test_a_unicode_and_a_punycode_spelling_share_one_pin(monkeypatch):
    """httpx connects to the IDNA form; a pin keyed on the other spelling must still hold."""
    import app.core.pinning as pinning

    calls = _resolver(monkeypatch, pinning, {})
    policy = PinPolicy(pins={"bücher.example": "10.0.0.5"}, private_only=["bücher.example"])
    request = httpx.Request("GET", "https://bücher.example/x")
    assert policy.address_for(request.url.raw_host.decode()) == "10.0.0.5"
    assert pinned_request(request, "10.0.0.5").extensions["sni_hostname"] == (
        "xn--bcher-kva.example"
    )
    assert calls == []
    assert domains._host("https://bücher.example/") == "xn--bcher-kva.example"
    assert ownership.normalize_host("Bücher.Example.") == "xn--bcher-kva.example"


def test_proof_never_resolves_on_its_own():
    with pytest.raises(OwnershipNotProven, match="does not resolve"):
        ownership.check_http_token("https://api.example.com", TOKEN, address=None)


def test_raw_socket_checks_connect_to_the_pinned_address(monkeypatch):
    import socket

    from app.engine.checks.request_smuggling import RequestSmugglingCheck
    from app.engine.checks.tls import TlsConfigCheck
    from tests import factories

    dialled: list[tuple[str, int]] = []

    def dial(address, timeout=None):
        dialled.append(address)
        raise OSError("no network in tests")

    monkeypatch.setattr(socket, "create_connection", dial)
    ctx = factories.scan_context([], premium=True)
    ctx.base_url = "https://api.example.com"
    ctx.pins = PinPolicy(pins={"api.example.com": PUBLIC})
    RequestSmugglingCheck().run(ctx)
    monkeypatch.setattr(TlsConfigCheck, "_cleartext", lambda *a, **k: [])
    TlsConfigCheck().run(ctx)
    assert dialled and all(host == PUBLIC for host, _ in dialled)


def test_adjuncts_stop_when_the_target_moves(monkeypatch):
    import app.core.pinning as pinning
    from app.engine.adjuncts import AdjunctPhase

    answers = {"lab.internal": ["10.0.0.5"]}
    _resolver(monkeypatch, pinning, answers)
    policy = PinPolicy(pins={"lab.internal": "10.0.0.5"}, private_only=["lab.internal"])
    events: list[str] = []
    ran: list[str] = []
    phase = AdjunctPhase(
        type("S", (), {"progress": 50})(),
        lambda stage, pct, msg: events.append(stage),
        budget_seconds=60,
        cancelled=lambda: False,
        drift=lambda: policy.drift("lab.internal"),
    )
    phase.add("zap", lambda: (ran.append("zap"), answers.update({"lab.internal": [PUBLIC]})))
    phase.add("kali", lambda: ran.append("kali"))
    phase.run()
    assert ran == ["zap"]
    assert events == ["adjuncts_skipped", "kali_skipped"]
