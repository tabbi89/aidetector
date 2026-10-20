"""The per-run context checks read from, and the identity pair they compare."""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from app.core.pinning import PinPolicy
from app.core.redact import Redactor
from app.domain.privilege import privilege_rank
from app.engine.credentials import ResolvedCredential
from app.engine.oob import NullOobClient, OobClient
from app.engine.operations import TargetOperation
from app.engine.probe import HttpProbe

if TYPE_CHECKING:
    from app.engine.http_types import HeaderSnapshot
    from app.engine.payloads import Payload, PayloadProvider


@dataclass(frozen=True)
class IdentityPair:
    """A distinct (owner, attacker) pair for a cross-identity oracle.

    ``owner`` is the legitimate high-privilege reader; ``attacker`` is the
    low-privilege identity whose access should be refused. Built only by
    :meth:`ScanContext.identity_pair`, so every cross-identity check agrees on
    what "distinct" means — they used to decide separately, and disagreed.
    """

    owner: ResolvedCredential
    attacker: ResolvedCredential


@dataclass
class ScanContext:
    base_url: str
    operations: list[TargetOperation]
    credentials: list[ResolvedCredential]
    probe: HttpProbe
    # Per-scan seed → rotating payload selection (different each run).
    seed: int = 0
    confirm: bool = False
    confirmation_targets: list[dict[str, Any]] = field(default_factory=list)
    # Out-of-band interaction client; Null (inactive) unless an OAST server is set.
    oob: OobClient = field(default_factory=NullOobClient)
    # Opt-in, off by default: allow checks that WRITE to the target (create/update
    # to confirm a mutation persisted). Gated so a normal scan never mutates state.
    allow_mutation: bool = False
    # Opt-in, off by default: run checks reserved for the premium tier. Gated so
    # a free scan never runs the paid detections (host-header probing, etc.).
    premium: bool = False
    # Raw parsed spec (dict) for schema-driven fuzzing; None when unavailable.
    spec: dict[str, Any] | None = None
    # Verbatim OpenAPI text stored for the scan. Kept separately from ``spec``
    # so offline artifact checks can inspect syntax/examples without serialising
    # the parsed document or reading persistence from inside a check.
    spec_text: str | None = None
    # How many schemathesis-generated cases to try per scan. 0 disables the
    # schema_fuzz check (the default — it is opt-in via the `fuzz:true` run flag).
    fuzz_cases: int = 0
    # Per-endpoint response headers, filled lazily by the header sweep and shared
    # by every header-based check so an endpoint is probed once even though checks
    # run concurrently. ``header_lock`` guards the fill.
    header_sweep: list[HeaderSnapshot] | None = None
    # Engine checks this run skipped as inapplicable (main pass only). The run
    # records them as a gap so the diff calls their older findings not
    # re-tested: a check that did not look cannot say a finding is fixed.
    skipped_checks: list[str] = field(default_factory=list)
    # Engine checks that raised mid-run (main pass only) — a transport timeout
    # on a slow host, or a bug. Recorded as a gap for the same reason: a check
    # that stopped part-way cannot say a finding is fixed.
    failed_checks: list[str] = field(default_factory=list)
    header_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # IDs provisioned by the mutation-authorized resource setup pass. Keys are
    # normalized resource names (``merchant`` for ``merchantId``). They let
    # dependent read checks use a real object instead of synthetic ``1`` values.
    resource_ids: dict[str, str] = field(default_factory=dict)
    # Keys whose ids came from the read-only seed (``engine/id_seed.py``), not
    # from resource setup or the user. They were read as the primary identity,
    # not the owner, so the authorization checks' own harvest ignores them.
    seeded_resource_keys: set[str] = field(default_factory=set)
    # (DELETE operation, rendered path, credential, report row) for resources
    # setup created. Keeping the row with its cleanup prevents positional drift
    # from updating the wrong resource record.
    resource_cleanups: list[tuple[TargetOperation, str, ResolvedCredential, dict[str, Any]]] = (
        field(default_factory=list)
    )
    # Sanitized records of resources setup created, for the run report: resource
    # name, create/read routes, status, and whether the AI proposed the body.
    # Never the created id or any target value — see resource_bootstrap.provision.
    created_resources: list[dict[str, Any]] = field(default_factory=list)
    # User-approved fixture controls carried by the run options.
    predefined_resource_ids: dict[str, str] = field(default_factory=dict)
    resource_refine: bool = False
    resource_attempts: int = 3
    # Database structure ({"tables", "warnings"}: names, types, nullability,
    # lengths, keys — never values) read once per run and shared by every
    # consumer. A local run reads it on the CLI machine; a server run uses the
    # newest snapshot a local run uploaded. None when the scan has none.
    schema_context: dict[str, Any] | None = None
    # Engine check keys this run is scoped to; empty runs every check.
    check_scope: frozenset[str] = frozenset()
    cleanup_failures: list[str] = field(default_factory=list)
    #: check key → {"ms", "requests"} for the operator's slow-check view.
    check_timings: dict[str, dict[str, int]] = field(default_factory=dict)
    # The run's secret-aware body redactor. Held here so a secondary pass that
    # builds its own probe (the discovery probe) reuses the redactor that knows
    # this scan's credentials, instead of silently falling back to the
    # pattern-only default. See ``runner._run_discovery_probe``.
    redact: Redactor | None = None
    # Optional AI-augmented reflection-payload provider (the ``genai_payloads``
    # phase installs one). When None, the reflection checks use the module-level
    # curated + vendored-corpus rotation. It only ever *adds* payloads, so the AI
    # cannot narrow coverage, and reflection identity excludes the family so the
    # extra variants never churn a finding's fingerprint.
    payload_provider: PayloadProvider | None = None
    # Which address each host connects to (``core/pinning``), shared with the
    # HTTP transport. None for an injected in-process client.
    pins: PinPolicy | None = None

    def connect_address(self, host: str) -> str:
        """The address a raw socket to ``host`` must use.

        Checks that open their own socket (TLS inspection, request smuggling)
        bypass the HTTP transport, so they ask here and connect to the run's
        pinned address — never to a lookup of their own. Raises
        ``TargetNotAllowed`` when ``host`` is out of policy.
        """
        return host if self.pins is None else self.pins.address_for(host)

    def reflection_payloads(self, per_family: int = 1) -> list[Payload]:
        """Rotating reflection payloads for this scan.

        Uses the AI-augmented provider when one was installed
        (``genai_payloads``); otherwise the default curated + corpus rotation.
        Either way the selection is deterministic in :attr:`seed` and draws
        ``per_family`` payloads per family, so per-scan request volume is fixed.
        """
        if self.payload_provider is not None:
            return self.payload_provider.rotating_set(self.seed, per_family)
        from app.engine.payloads import rotating_set

        return rotating_set(self.seed, per_family)

    def primary_credential(self) -> ResolvedCredential | None:
        """The scan's first credential — the default identity for probes.

        Checks that fuzz a single identity (injection, enumeration, the header
        sweep) use this rather than a privilege extreme: they are asking "what
        does an authenticated caller see", not comparing two identities.
        """
        return self.credentials[0] if self.credentials else None

    def primary_headers(self) -> dict[str, str]:
        """Auth headers for :meth:`primary_credential`; empty when unauthenticated."""
        cred = self.primary_credential()
        return cred.headers() if cred else {}

    def lowest_priv(self) -> ResolvedCredential | None:
        """The least-privileged credential, by simple role heuristics."""
        if not self.credentials:
            return None
        return min(self.credentials, key=self.privilege_rank)

    @staticmethod
    def privilege_rank(credential: ResolvedCredential) -> int:
        """Comparable privilege rank for checks that require a real role boundary.

        The identity's explicit ``privilege`` when it set one, else inferred from
        the role name (``app/domain/privilege.py``).
        """
        return privilege_rank(credential.role, credential.privilege)

    def lower_privileged(self, than: ResolvedCredential) -> list[ResolvedCredential]:
        """Identities strictly less privileged than ``than``, least privileged first.

        Lets a function-level check try every tier below the top one, not only
        the bottom: with viewer < editor < admin, an admin function an editor can
        call is invisible to a viewer-vs-admin comparison.
        """
        top = self.privilege_rank(than)
        lower = [
            c for c in self.credentials
            if self.privilege_rank(c) < top
            # Function-level authorization is a boundary inside one tenant: a
            # key from another workspace failing an editor call says nothing
            # about this workspace's viewer.
            and (not self.tenants_declared() or c.tenant == than.tenant)
        ]
        # Stable: identities sharing a rank keep the order they were given in.
        return sorted(lower, key=self.privilege_rank)

    def lowest_writer(self) -> ResolvedCredential | None:
        """The least privileged identity whose role does not say read-only.

        For checks that must create an object to test anything (mass
        assignment, race): the lowest identity is the right caller only if it
        may write at all. Falls back to :meth:`lowest_priv` when every role is
        read-only.
        """
        from app.domain.privilege import is_read_only_role

        writers = [c for c in self.credentials if not is_read_only_role(c.role)]
        if not writers:
            return self.lowest_priv()
        return min(writers, key=self.privilege_rank)

    def highest_priv(self) -> ResolvedCredential | None:
        """The most-privileged credential — the legitimate owner/reader identity."""
        if not self.credentials:
            return None
        return max(self.credentials, key=self.privilege_rank)

    def identity_pair(self) -> IdentityPair | None:
        """A distinct (owner, attacker) pair, or None with fewer than two identities.

        Distinctness is by ``name`` — the identifier the user actually gave each
        credential — not by ``role``. ``highest_priv``/``lowest_priv`` rank by a
        coarse role heuristic that scores unknown roles alike, so two credentials
        sharing a role collapse to the *same* object; falling back to the first
        two credentials keeps them usable.

        That matters because requiring distinct *roles* silently disabled every
        cross-identity write oracle on APIs with no role hierarchy — where two
        accounts are two tenants, which is precisely where cross-tenant BOLA
        lives. Two credentials with different names are two identities whatever
        they are labelled.
        """
        if len(self.credentials) < 2:
            return None
        if self.tenants_declared():
            return self._cross_tenant_pair()
        hi, lo = self.highest_priv(), self.lowest_priv()
        assert hi is not None and lo is not None  # len >= 2 checked above
        if hi.name == lo.name:
            hi, lo = self.credentials[0], self.credentials[1]
        return IdentityPair(owner=hi, attacker=lo)

    def tenants_declared(self) -> bool:
        """Whether any identity says which tenant it belongs to."""
        return any(c.tenant for c in self.credentials)

    def _cross_tenant_pair(self) -> IdentityPair | None:
        """Owner and attacker from two different declared tenants.

        Two keys of one workspace reading the same monitor is the API working;
        pairing them by privilege alone reported it as BOLA. With tenants
        declared, the owner is the most privileged identity that has a partner
        in another tenant, and the attacker is that tenant's most privileged
        identity — so the pair differs by tenant, not by role, and a write
        oracle's attacker can actually write in its own tenant. Identities with
        no tenant take no part: which side of the boundary they are on is unknown.
        """
        tenanted = [c for c in self.credentials if c.tenant]
        for owner in sorted(tenanted, key=self.privilege_rank, reverse=True):
            others = [c for c in tenanted if c.tenant != owner.tenant]
            if others:
                return IdentityPair(owner=owner, attacker=max(others, key=self.privilege_rank))
        return None

    def privilege_pair(self) -> IdentityPair | None:
        """A (privileged, lower) pair inside one tenant, for function-level checks.

        Without declared tenants this is :meth:`identity_pair`. With them, the
        pair is the most and least privileged identities of the tenant whose
        top identity ranks highest among tenants holding two or more.
        """
        if not self.tenants_declared():
            return self.identity_pair()
        groups: dict[str, list[ResolvedCredential]] = {}
        for c in self.credentials:
            if c.tenant:
                groups.setdefault(c.tenant, []).append(c)
        best: IdentityPair | None = None
        for members in groups.values():
            if len(members) < 2:
                continue
            hi = max(members, key=self.privilege_rank)
            lo = min(members, key=self.privilege_rank)
            if hi.name == lo.name:
                hi, lo = members[0], members[1]
            if best is None or self.privilege_rank(hi) > self.privilege_rank(best.owner):
                best = IdentityPair(owner=hi, attacker=lo)
        return best

    def pair_gap(self) -> str:
        """Why :meth:`identity_pair` is None, phrased as what to add."""
        if self.tenants_declared():
            tenants = sorted({c.tenant for c in self.credentials if c.tenant})
            return (
                f"every identity with a tenant is in '{tenants[0]}' — add one from another "
                "tenant to test cross-tenant access"
            )
        return "a cross-identity oracle needs two credentials"
