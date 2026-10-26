"""``python -m app.runner --auth-check``: check identities against the target.

Runs in the same hardened container, on the same network, with the same egress
rules, pins and grant minting as a scan — so "the key works" here means it
works for the scan. Sends at most a few GET requests per identity (and the same
ones anonymously), never a payload, never a write, and follows no redirect, so
a credential cannot be carried to another origin. Prints one JSON document on
stdout: per-identity verdicts and per-route statuses — never a secret, a
response body or a header value. Nothing is uploaded; the server opened no run.
"""
from __future__ import annotations

import json
import sys
from typing import Any, TextIO

import httpx

from app.core.redact import Redactor
from app.core.target_guard import TargetNotAllowed
from app.domain.enums import AuthType
from app.engine.auth_probe import (
    GRANT_FAILED,
    MAX_REQUESTS,
    MISSING_SECRET,
    NO_CREDENTIAL,
    NOT_CHECKED,
    verdict,
)
from app.engine.credentials import ResolvedCredential, wire_kwargs
from app.engine.execution import prepare_credentials
from app.engine.operations import render_path
from app.engine.resource_map import path_values
from app.engine.transport import AsyncHttpClientBridge
from app.runner import main as runner
from app.scans.run_options import supplied_resource_ids

EXIT_OK = 0
EXIT_BAD_INPUT = 2
EXIT_UNREACHABLE = 1


def _status(bridge: AsyncHttpClientBridge, path: str, headers: dict[str, str]) -> int | None:
    try:
        response = bridge.request("GET", path, **wire_kwargs({"headers": headers}))
    except (httpx.HTTPError, TargetNotAllowed, TimeoutError, OSError):
        return None
    return response.status_code


def run_check(cfg: dict[str, Any]) -> dict[str, Any]:
    """The check itself; returns the report (also used by tests)."""
    check = cfg["check"]
    target = check["target_base_url"]
    runner._allowed(target)
    pins = runner._target_pins(check, target)
    ops = runner._operations(check)
    ids = supplied_resource_ids(cfg.get("predefined_resource_ids"))
    routes = [render_path(op.path, path_values(op, ids)) for op in ops]
    bound, events, sensitive = runner._bind_credentials(check, cfg.get("secrets") or {})
    redactor = Redactor(sensitive)

    shapes = {
        (s.get("name") or s.get("role") or ""): s for s in check.get("credentials") or []
    }
    budget = min(int(check.get("max_requests") or MAX_REQUESTS), MAX_REQUESTS)
    bridge = AsyncHttpClientBridge(
        target,
        timeout=10.0,
        requests_per_second=float(check.get("requests_per_second") or 5),
        transport=runner.PinnedAsyncTransport(pins),
        url_validator=runner._allowed,
    )
    sent = 0

    def probe(headers: dict[str, str]) -> list[int | None]:
        nonlocal sent
        out: list[int | None] = []
        for path in routes:
            if sent >= budget:
                out.append(None)
                continue
            sent += 1
            out.append(_status(bridge, path, headers))
        return out

    try:
        ready, mint_events = prepare_credentials(
            bound, allowed=runner._allowed, transport=bridge, on_secret=redactor.add_secret
        )
        events.extend(mint_events)
        ready_names = {c.name for c in ready}
        anonymous = probe({})
        identities: list[dict[str, Any]] = []
        bound_names = {c.name for c in bound}
        for name, shape in shapes.items():
            row: dict[str, Any] = {
                "name": name,
                "role": shape.get("role"),
                "tenant": shape.get("tenant"),
                "auth": shape.get("auth_type"),
                "statuses": [],
            }
            if shape.get("auth_type") == AuthType.none.value:
                row.update(state=NO_CREDENTIAL, detail="auth: none sends no credential")
            elif name not in bound_names:
                row.update(state=MISSING_SECRET, detail="no secret was supplied on this machine")
            elif name not in ready_names:
                row.update(state=GRANT_FAILED, detail="the token grant did not mint a token")
            elif sent + len(routes) > budget:
                row.update(
                    state=NOT_CHECKED, detail=f"the check's cap of {budget} requests was reached"
                )
            else:
                cred: ResolvedCredential = next(c for c in ready if c.name == name)
                statuses = probe(cred.headers())
                v = verdict(statuses, anonymous)
                row.update(state=v.state, detail=v.detail, statuses=statuses)
            identities.append(row)
    finally:
        bridge.close()

    reachable = any(s is not None for s in anonymous) or any(
        s is not None for row in identities for s in row["statuses"]
    )
    return {
        "target": target,
        "reachable": reachable,
        "requests": sent,
        "routes": [{"method": "GET", "path": op.path} for op in ops],
        "anonymous": anonymous,
        "identities": identities,
        # Event messages name identities and roles, never secrets; redacted anyway.
        "events": [{"stage": s, "message": redactor.text(m)} for s, m in events],
    }


def main(stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
    out = stdout if stdout is not None else sys.stdout
    try:
        cfg = json.load(stdin if stdin is not None else sys.stdin)
        if not isinstance(cfg, dict) or not isinstance(cfg.get("check"), dict):
            raise ValueError("config needs `check`")
        if not cfg["check"].get("target_base_url"):
            raise ValueError("check is missing target_base_url")
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"error: bad auth-check config on stdin: {exc}", file=sys.stderr)
        return EXIT_BAD_INPUT
    try:
        report = run_check(cfg)
    except TargetNotAllowed as exc:
        print(f"error: target refused: {exc}", file=sys.stderr)
        return EXIT_BAD_INPUT
    except Exception as exc:  # noqa: BLE001 — a clean line, never a traceback with state in it
        print(f"error: the auth check could not run: {type(exc).__name__}", file=sys.stderr)
        return EXIT_UNREACHABLE
    json.dump(report, out)
    out.write("\n")
    return EXIT_OK if report["reachable"] else EXIT_UNREACHABLE
