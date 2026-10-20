"""Seeded resource ids must reach the checks that render a path template.

``ScanContext.resource_ids`` maps a normalized resource name to a real object id
provisioned by the resource-setup pass. A check that hardcodes a synthetic ``1``
instead of reading it probes an object the target does not have, so a real
finding is lost behind a 404. These are the two checks a seeded id reaches
first: the header sweep and the broken-auth control request.
"""
from __future__ import annotations

from types import SimpleNamespace

from app.domain.enums import AuthType
from app.engine.base import HttpProbe, ResolvedCredential, ScanContext, TargetOperation
from app.engine.checks.auth import BrokenAuthCheck
from app.engine.checks.misconfig import sweep_headers

_PATH = "/accounts/{account_id}"


class RecordingClient:
    """A transport that records the rendered path of every request it serves.

    Anonymous requests are rejected (401) and anything carrying an Authorization
    header is accepted, which is the shape ``BrokenAuthCheck`` needs: an
    enforced endpoint whose forged token still gets in.
    """

    def __init__(self) -> None:
        self.urls: list[str] = []

    def request(self, method: str, url: str, **kwargs):
        self.urls.append(url)
        sent = {name.lower() for name in (kwargs.get("headers") or {})}
        if "authorization" not in sent:
            return SimpleNamespace(
                status_code=401, headers={}, text='{"detail":"missing token"}', content=b""
            )
        return SimpleNamespace(
            status_code=200,
            headers={"content-type": "application/json"},
            text='{"id":42,"owner":"alice"}',
            content=b'{"id":42,"owner":"alice"}',
        )


def _context(account_id: str | None) -> tuple[ScanContext, RecordingClient]:
    """One GET /accounts/{account_id} operation, seeded or not."""
    operation = TargetOperation(
        id="op-account",
        method="GET",
        path=_PATH,
        params=[{"name": "account_id", "in": "path", "required": True}],
    )
    client = RecordingClient()
    credential = ResolvedCredential(
        "alice", "user", AuthType.header, "Authorization", "alice-token"
    )
    probe = HttpProbe(client, operations=[operation], credentials=[credential], max_requests=50)
    ctx = ScanContext(
        base_url="http://target",
        operations=[operation],
        credentials=[credential],
        probe=probe,
        resource_ids={} if account_id is None else {"account": account_id},
    )
    return ctx, client


def test_the_header_sweep_probes_the_seeded_object():
    ctx, client = _context("42")

    snapshots = sweep_headers(ctx)

    assert [s.path for s in snapshots] == ["/accounts/42"]
    assert client.urls == ["/accounts/42"]


def test_broken_auth_probes_the_seeded_object():
    ctx, client = _context("42")

    findings = BrokenAuthCheck().run(ctx)

    assert findings, "forged token accepted on a protected endpoint — should report"
    assert set(client.urls) == {"/accounts/42"}
    # Evidence still names the template as the route and the rendered path it hit.
    assert findings[0].evidence["route"] == _PATH
    assert findings[0].evidence["path"] == "/accounts/42"


def test_without_seeded_ids_the_baseline_placeholder_is_used():
    sweep_ctx, sweep_client = _context(None)
    assert [s.path for s in sweep_headers(sweep_ctx)] == ["/accounts/1"]
    assert sweep_client.urls == ["/accounts/1"]

    auth_ctx, auth_client = _context(None)
    BrokenAuthCheck().run(auth_ctx)
    assert set(auth_client.urls) == {"/accounts/1"}
