"""The ownership gate every scan start answers for a public target.

``clear_target`` decides, from addresses resolved *once*, whether a target needs
ownership proof and, if so, re-runs that proof live against the address the
scan will connect to. The answer is a :class:`Clearance` that carries the
pinned address forward, so the run connects to what was cleared rather than to
a later lookup — that is what stops an edited ``/etc/hosts`` or a rebinding
resolver from turning an exempt "private" target into a public one.

Exempt, in order:

- ``disabled`` — the operator turned ``target_require_verification`` off;
- ``allowlist`` — the operator's ``target_allowlist`` names the host, which is
  already an authoritative statement about where scans may go;
- ``private`` — no resolved address is public (or the name does not resolve on
  this side, as a docker service name does not). The run is then pinned
  private-only: if the host later resolves publicly, the transport refuses it.

The gate is read-only: it never writes the verification row, so it can run
inside a request that will be refused. ``verify_domain`` is the explicit check
that records a result for the UI.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import ownership
from app.core.config import settings
from app.core.ownership import OwnershipNotProven
from app.core.pinning import PinPolicy, url_host
from app.core.target_guard import (
    TargetNotAllowed,
    check_resolved,
    host_in_allowlist,
    is_public_ip,
    resolve_host,
)
from app.models.domain import DomainVerification


@dataclass(frozen=True)
class Clearance:
    """What the gate decided about one target, carried into the run."""

    host: str
    #: The address the run connects to; None when the host did not resolve here.
    address: str | None
    #: Why no proof was needed (``disabled``/``allowlist``/``private``), or None
    #: when ownership was proven.
    exempt: str | None
    #: The workspace's token, when ownership was proven.
    token: str | None = None

    @property
    def private_only(self) -> bool:
        return self.exempt == "private"

    def pin_policy(self) -> PinPolicy:
        return PinPolicy(
            allow_private=settings.target_allow_private,
            allowlist=settings.allowlist_set(),
            pins={self.host: self.address} if self.address else None,
            private_only=[self.host] if self.private_only else [],
        )

    def runner_policy(self) -> dict[str, Any]:
        """What the local runner must re-establish from its own vantage point."""
        return {"private_only": self.private_only, "verification_token": self.token}


@dataclass(frozen=True)
class ProofTransports:
    """Injectable network for the two proofs (tests bind in-process doubles)."""

    dns: httpx.BaseTransport | None = None
    http: httpx.BaseTransport | None = None


def _host(url: str) -> str:
    host = url_host(url)
    if not host:
        raise TargetNotAllowed("target has no host")
    return host


def record_for(db: Session, tenant: str, host: str) -> DomainVerification | None:
    return db.scalars(
        select(DomainVerification).where(
            DomainVerification.tenant_slug == tenant,
            DomainVerification.host == host,
        )
    ).first()


@dataclass(frozen=True)
class ProofResult:
    """One proof's outcome from an explicit check, kept for the UI."""

    proof: str  # "dns" | "http"
    ok: bool
    detail: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"proof": self.proof, "ok": self.ok, "detail": self.detail}


def prove_each(
    target_url: str,
    token: str,
    *,
    address: str | None,
    transports: ProofTransports | None = None,
) -> list[ProofResult]:
    """Run every proof even when an earlier one fails, so a person sees which half
    is missing. An IP literal has no name to prove and gets no DNS result."""
    transports = transports or ProofTransports()
    timeout = settings.domain_verification_timeout_seconds
    host = _host(target_url)
    results: list[ProofResult] = []
    if not ownership.is_ip_literal(host):
        try:
            ownership.check_dns_txt(
                host,
                token,
                doh_url=settings.domain_verification_doh_url,
                timeout=timeout,
                transport=transports.dns,
            )
            results.append(ProofResult("dns", True))
        except TargetNotAllowed as exc:
            results.append(ProofResult("dns", False, str(exc)[:500]))
    try:
        ownership.check_http_token(
            target_url,
            token,
            address=address,
            timeout=timeout,
            inner=transports.http,
            allow_private=settings.target_allow_private,
        )
        results.append(ProofResult("http", True))
    except TargetNotAllowed as exc:
        results.append(ProofResult("http", False, str(exc)[:500]))
    return results


def prove(
    target_url: str,
    token: str,
    *,
    address: str | None,
    transports: ProofTransports | None = None,
) -> None:
    """Both proofs for ``target_url``; raises :class:`OwnershipNotProven`."""
    transports = transports or ProofTransports()
    timeout = settings.domain_verification_timeout_seconds
    ownership.check_dns_txt(
        _host(target_url),
        token,
        doh_url=settings.domain_verification_doh_url,
        timeout=timeout,
        transport=transports.dns,
    )
    ownership.check_http_token(
        target_url,
        token,
        address=address,
        timeout=timeout,
        inner=transports.http,
        allow_private=settings.target_allow_private,
    )


def _exemption(host: str, resolved: Sequence[IPv4Address | IPv6Address]) -> str | None:
    """Why ``host`` needs no ownership proof, or None when it does."""
    if not settings.target_require_verification:
        return "disabled"
    allowlist = sorted(settings.allowlist_set())
    if allowlist and host_in_allowlist(host, allowlist):
        return "allowlist"
    if not any(is_public_ip(ip) for ip in resolved):
        return "private"
    return None


@dataclass(frozen=True)
class OwnershipStatus:
    """What a run of ``target_url`` will ask of this workspace, before it is asked."""

    host: str
    #: Why no proof is needed (``disabled``/``allowlist``/``private``), or None.
    exempt: str | None
    #: The workspace's entry for the host, if it has added one.
    record: DomainVerification | None


def ownership_status(db: Session, tenant: str, target_url: str) -> OwnershipStatus:
    """The ownership half of :func:`clear_target`, minus the live proof.

    For the run panel, so a person learns the target needs proving before the
    run is refused. Advisory only: it fetches nothing from the target, and the
    run gate still proves ownership live. Raises :class:`TargetNotAllowed` when
    the egress policy refuses the target outright.
    """
    host = _host(target_url)
    resolved = resolve_host(host)
    check_resolved(
        host,
        resolved,
        allow_private=settings.target_allow_private,
        allowlist=settings.allowlist_set(),
    )
    exempt = _exemption(host, resolved)
    return OwnershipStatus(host, exempt, None if exempt else record_for(db, tenant, host))


def clear_target(
    db: Session,
    tenant: str,
    target_url: str,
    *,
    transports: ProofTransports | None = None,
    allow_private: bool | None = None,
) -> Clearance:
    """Resolve once, decide whether proof is needed, and prove it live if so.

    Raises :class:`TargetNotAllowed` (egress policy) or
    :class:`OwnershipNotProven` (a public target this workspace has not proven).
    ``allow_private`` overrides the server's egress flag for a lane that does
    not egress from the server (the local-runner claim), matching the guard in
    ``app/scans/policy``; a public target still needs its ownership proof.
    """
    host = _host(target_url)
    resolved = resolve_host(host)
    check_resolved(
        host,
        resolved,
        allow_private=(
            settings.target_allow_private if allow_private is None else allow_private
        ),
        allowlist=settings.allowlist_set(),
    )
    address = str(resolved[0]) if resolved else None
    exempt = _exemption(host, resolved)
    if exempt:
        return Clearance(host, address, exempt)

    record = record_for(db, tenant, host)
    if record is None:
        raise OwnershipNotProven(
            f"'{host}' resolves to a public address, so this workspace must prove it "
            "controls it before scanning: add it under Workspace → Domains and publish "
            "the DNS TXT record and HTTP token shown there"
        )
    if not settings.target_allow_private:
        # The proof is fetched by this server whatever lane the run is on, so it
        # answers the server's own egress flag, not the caller's override: a name
        # resolving to a private and a public address is proven against the
        # public one, never by dialling into the network the flag protects.
        address = next(str(ip) for ip in resolved if is_public_ip(ip))
    prove(target_url, record.token, address=address, transports=transports)
    return Clearance(host, address, None, record.token)


def verify_domain(
    db: Session,
    record: DomainVerification,
    target_url: str,
    *,
    transports: ProofTransports | None = None,
) -> None:
    """The explicit check: run both proofs now and record the result on ``record``."""
    now = datetime.now(UTC)
    record.last_checked_at = now
    try:
        resolved = resolve_host(record.host)
        check_resolved(
            record.host,
            resolved,
            allow_private=settings.target_allow_private,
            allowlist=settings.allowlist_set(),
        )
    except TargetNotAllowed as exc:
        # The egress policy refused the host outright; neither proof was tried.
        record.verified_at = None
        record.last_error = str(exc)[:1000]
        record.last_checks = None
        return
    results = prove_each(
        target_url,
        record.token,
        address=str(resolved[0]) if resolved else None,
        transports=transports,
    )
    record.last_checks = [result.as_dict() for result in results]
    failures = [result.detail or result.proof for result in results if not result.ok]
    record.verified_at = None if failures else now
    record.last_error = "; ".join(failures)[:1000] if failures else None


__all__ = [
    "Clearance",
    "OwnershipNotProven",
    "ProofResult",
    "ProofTransports",
    "clear_target",
    "prove",
    "prove_each",
    "record_for",
    "verify_domain",
]
