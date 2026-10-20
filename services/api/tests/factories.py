"""Builders for the objects tests keep hand-rolling.

``ScanContext``, ``HttpProbe``, ``TargetOperation`` and ``ResolvedCredential``
were each constructed a couple of dozen times across the suite, every time with
the same boilerplate and slightly different omissions. The helpers here take the
one or two fields a given test actually cares about and default the rest, so a
test reads as its own intent rather than as setup.

Everything is bound to the in-process vulnerable app (``tests/vulnapp.py``) by
default, so nothing here touches the network.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from fastapi.testclient import TestClient

from app.domain.enums import AuthType
from app.engine.base import (
    DEFAULT_MAX_REQUESTS,
    HttpClient,
    HttpProbe,
    ResolvedCredential,
    ScanContext,
    TargetOperation,
)
from app.engine.checks import ALL_CHECKS
from app.engine.oob import OobClient
from app.models.credential import CredentialProfile
from app.models.scan import Operation, Scan, ScanStatus
from tests.vulnapp import vulnapp

BASE_URL = "http://testserver"


def operation(
    method: str,
    path: str,
    *,
    id: str | None = None,
    params: list[dict[str, Any]] | None = None,
    auth_scope: str | None = None,
) -> TargetOperation:
    """A target operation; path params are inferred from ``{...}`` in the path."""
    if params is None:
        params = [
            {"name": name, "in": "path", "required": True}
            for name in _path_vars(path)
        ]
    return TargetOperation(
        id=id or f"op-{method.lower()}-{path.strip('/').replace('/', '-') or 'root'}",
        method=method,
        path=path,
        params=params,
        auth_scope=auth_scope,
    )


def _path_vars(path: str) -> list[str]:
    import re

    return re.findall(r"\{([^}]+)\}", path)


def credential(name: str, role: str, secret: str | None = None) -> ResolvedCredential:
    """A header-auth identity — vulnapp matches the raw Authorization header."""
    return ResolvedCredential(
        name=name,
        role=role,
        auth_type=AuthType.header,
        header_name="Authorization",
        secret=secret or f"{name}-token",
    )


#: The two identities the vulnerable app knows about.
def two_identities() -> list[ResolvedCredential]:
    return [credential("alice", "user"), credential("admin", "admin")]


def scan_context(
    operations: list[TargetOperation],
    *,
    credentials: list[ResolvedCredential] | None = None,
    client: HttpClient | None = None,
    probe: HttpProbe | None = None,
    allow_mutation: bool = False,
    premium: bool = False,
    max_requests: int = DEFAULT_MAX_REQUESTS,
    oob: OobClient | None = None,
    spec: dict[str, Any] | None = None,
    spec_text: str | None = None,
    fuzz_cases: int = 0,
    seed: int = 0,
) -> ScanContext:
    """A ScanContext wired to the in-process vulnerable app.

    ``credentials`` defaults to the standard user/admin pair, which is what the
    authorization checks need; pass ``[]`` for the unauthenticated case. Pass
    ``probe`` when the test needs to assert on the probe it built (request
    counts, coverage attribution); otherwise read ``ctx.probe``.
    """
    if probe is None:
        probe = HttpProbe(
            client if client is not None else TestClient(vulnapp),
            max_requests=max_requests,
            operations=operations,
            credentials=credentials if credentials is not None else two_identities(),
        )
    ctx = ScanContext(
        base_url=BASE_URL,
        operations=operations,
        credentials=two_identities() if credentials is None else credentials,
        probe=probe,
        allow_mutation=allow_mutation,
        premium=premium,
        spec=spec,
        spec_text=spec_text,
        fuzz_cases=fuzz_cases,
        seed=seed,
    )
    if oob is not None:
        ctx.oob = oob
    return ctx


#: The five vulnapp endpoints the engine tests exercise. Shared because the
#: engine test modules all assert against the same target surface.
def engine_operations() -> list[TargetOperation]:
    return [
        operation("GET", "/accounts/{account_id}", id="op-acct"),
        operation("POST", "/admin/users/{user_id}/promote", id="op-promote"),
        operation("GET", "/admin/audit", id="op-admin-audit", auth_scope="admin"),
        operation("GET", "/search", id="op-search",
                  params=[{"name": "q", "in": "query", "required": False}]),
        operation("GET", "/lookup", id="op-lookup",
                  params=[{"name": "name", "in": "query", "required": False}]),
        operation("GET", "/health", id="op-health", params=[]),
    ]


def run_check(check: Any, ctx: ScanContext) -> list[Any]:
    """Run one check, setting the probe attribution context as the runner does."""
    ctx.probe.check_context = getattr(check, "key", "?")
    return list(check.run(ctx))


def run_one(check: Any, operations: list[TargetOperation], **ctx_kwargs: Any) -> list[Any]:
    """Run a single check over ``operations`` against the vulnerable app."""
    return run_check(check, scan_context(operations, **ctx_kwargs))


def run_registry(operations: list[TargetOperation] | None = None, **ctx_kwargs: Any) -> list[Any]:
    """Every registered check, over the standard operation set. The smoke path."""
    ctx = scan_context(operations or engine_operations(), **ctx_kwargs)
    findings: list[Any] = []
    for check in ALL_CHECKS:
        findings.extend(run_check(check, ctx))
    return findings


# ---- ORM rows ----------------------------------------------------------------


def scan_row(
    *,
    target_base_url: str = BASE_URL,
    operations: list[Operation] | None = None,
    identities: list[tuple[str, str]] | None = None,
    cancel: bool = False,
) -> Scan:
    """A persistable Scan with operations and encrypted credential profiles."""
    from app.core.vault import encrypt

    scan = Scan(
        target_base_url=target_base_url,
        status=ScanStatus.draft,
        cancel_requested=cancel,
    )
    scan.operations = operations if operations is not None else default_operations()
    pairs = identities if identities is not None else [("alice", "user"), ("admin", "admin")]
    for name, role in pairs:
        scan.credential_profiles.append(
            CredentialProfile(
                name=name,
                role=role,
                auth_type=AuthType.header,
                header_name="Authorization",
                secret_ref=encrypt(f"{name}-token"),
            )
        )
    return scan


def default_operations() -> list[Operation]:
    """The three endpoints most scan-level tests exercise."""
    return [
        Operation(
            method="GET",
            path="/accounts/{account_id}",
            params=[{"name": "account_id", "in": "path", "required": True}],
        ),
        Operation(
            method="POST",
            path="/admin/users/{user_id}/promote",
            params=[{"name": "user_id", "in": "path", "required": True}],
        ),
        Operation(
            method="GET",
            path="/search",
            params=[{"name": "q", "in": "query", "required": False}],
        ),
    ]


def injection_lead(
    family: str, path: str, param: str, *, check: str = "reflected_injection"
) -> SimpleNamespace:
    """A reflection lead as the confirm tools read it: family, path and param."""
    return SimpleNamespace(
        check=check,
        evidence={"family": family, "path": path, "param": param},
        operation_id="op-1",
    )
