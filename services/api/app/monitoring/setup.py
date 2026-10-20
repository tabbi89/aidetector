"""One-step monitor setup, and the dev-only examples on the bundled target."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.api.schemas import (
    MonitoringRapidIngest,
    MonitoringSetup,
    MonitoringSetupOut,
    MonitoringSetupUpdate,
)
from app.core.config import settings
from app.core.target_guard import TargetNotAllowed
from app.domain.enums import AuthType
from app.models.monitoring import (
    EvidenceSource,
    InfrastructureMonitor,
    MonitoringAlert,
    MonitoringRapidRun,
    MonitoringRun,
)
from app.models.scan import Scan
from app.monitoring import demo, rapid_service, remote, service, sources
from app.monitoring.context import contract_context
from app.monitoring.contracts import (
    ORIGIN_SOURCE_KEY,
    SourceConfig,
    SourceCredentials,
    SourceInput,
    SourceUnavailable,
    parse_load_balancer_arn,
    parse_log_group_arn,
)
from app.scans import credentials, operations
from app.scans import service as scans
from app.scans.policy import require_target_allowed
from app.scans.views import CredentialInput
from app.specs.importers import load_source
from app.specs.parser import SpecError, parse_operations

EXAMPLE_TARGET = demo.TARGET
EXAMPLE_MONITOR = demo.MONITOR_NAME
# services/target's seed identities; it reads the token from a raw Authorization header.
EXAMPLE_CREDENTIALS = (("alice", "user", "alice-token"), ("admin", "admin", "admin-token"))
MAX_EXAMPLE_SPEC_BYTES = 2_000_000


def examples_enabled() -> bool:
    return settings.env == "dev"


def _require_examples() -> None:
    if not examples_enabled():
        raise HTTPException(404, "not found")


def _allowed_target(target: str) -> None:
    try:
        require_target_allowed(target)
    except TargetNotAllowed:
        raise HTTPException(422, "target binding is not allowed") from None


def _message(exc: ValueError) -> str:
    if isinstance(exc, ValidationError):
        return str(exc.errors()[0]["msg"])
    return str(exc)


#: ``context`` keys each owned by one part of setup, so an edit replaces one part only.
CONTRACT_KEYS = ("routes", "openapi_revision", "openapi_explicit", "advisories")
REPOSITORY_KEYS = ("repository", "repository_source_id", "repository_revision")


def _alb_input(
    name: str, target: str, arn: str, *, region: str, account: str | None
) -> SourceInput:
    """The origin source for ``arn``, which must sit beside the WAF it adds status to.

    A regional WebACL only protects resources in its own region and account, so an
    ALB anywhere else cannot be carrying the traffic these WAF logs describe -- its
    status codes would be attached to a different stream's requests.
    """
    alb_region, alb_account, resource = parse_load_balancer_arn(arn)
    # A log group configured as region:group carries no account; compare what is known.
    if alb_region != region or (account is not None and alb_account != account):
        raise ValueError(
            f"the load balancer is in {alb_region}/{alb_account} but the WAF log group is in "
            f"{region}/{account}; a regional WebACL only covers its own region and account"
        )
    return SourceInput(
        name=f"{name} · ALB metrics"[:160],
        target_binding=target,
        connector="aws_alb",
        config=SourceConfig(region=alb_region, account_id=alb_account, load_balancer=resource),
    )


def _require_allowlisted(source: SourceInput) -> None:
    try:
        remote.check_allowlist(source.connector, source.config)
    except SourceUnavailable:
        raise HTTPException(422, sources.not_allowlisted_message(source.connector)) from None


def _alb_arn(source: EvidenceSource | None) -> str | None:
    if source is None or source.connector != "aws_alb":
        return None
    c = source.config
    return (
        f"arn:aws:elasticloadbalancing:{c.get('region')}:{c.get('account_id')}:"
        f"loadbalancer/{c.get('load_balancer')}"
    )


def _source(
    db: Session, monitor: InfrastructureMonitor, source_id: object
) -> EvidenceSource | None:
    source = db.get(EvidenceSource, str(source_id)) if source_id else None
    if source is None or source.tenant_id != monitor.tenant_id or source.status == "revoked":
        return None
    return source


def setup_view(db: Session, monitor: InfrastructureMonitor) -> MonitoringSetupOut:
    waf = _source(db, monitor, monitor.source_ids[0] if monitor.source_ids else None)
    repo = _source(db, monitor, monitor.context.get("repository_source_id"))
    origin = _source(db, monitor, monitor.context.get(ORIGIN_SOURCE_KEY))
    waf_arn = None
    if waf is not None and waf.connector == "aws_cloudwatch":
        c = waf.config
        waf_arn = (
            f"arn:aws:logs:{c.get('region')}:{c.get('account_id')}:log-group:{c.get('log_group')}"
        )
    return MonitoringSetupOut(
        name=monitor.name,
        target_binding=monitor.target_binding,
        waf_log_group_arn=waf_arn,
        alb_arn=_alb_arn(origin),
        github_repository=repo.config.get("repository") if repo else None,
        github_ref=repo.config.get("ref") if repo else None,
        github_token_set=bool(repo and repo.secret_ref),
        scan_id=monitor.scan_id,
        schedule_enabled=monitor.schedule_enabled,
        rapid_enabled=monitor.rapid_enabled,
    )


def _retire(db: Session, source: EvidenceSource | None) -> None:
    """Revoke a source an edit replaced: its audit trail stays, its secret does not.

    Bumping the revision is what stops a collection already reading it, because every
    collection guard re-checks the revision it started with.
    """
    if source is None or source.status == "revoked":
        return
    source.status, source.secret_ref = "revoked", None
    source.revision += 1
    sources.audit(db, source, "revoke", "replaced")


def update_monitor_setup(
    db: Session, monitor: InfrastructureMonitor, body: MonitoringSetupUpdate
) -> InfrastructureMonitor:
    """Apply an edit. As in setup, everything refusable is checked before the first write."""
    fields = body.model_fields_set
    tenant_id, target = monitor.tenant_id, monitor.target_binding
    name = body.name if body.name is not None else monitor.name
    waf = _source(db, monitor, monitor.source_ids[0] if monitor.source_ids else None)
    old_origin = _source(db, monitor, monitor.context.get(ORIGIN_SOURCE_KEY))
    old_repo = _source(db, monitor, monitor.context.get("repository_source_id"))

    if body.rapid_enabled and (waf is None or waf.connector != "aws_cloudwatch"):
        raise HTTPException(
            409,
            "short-window checks read AWS WAF logs from CloudWatch, and this monitor reads none",
        )

    alb: SourceInput | None = None
    if body.alb_arn:
        if waf is None or waf.connector != "aws_cloudwatch":
            raise HTTPException(
                409, "an ALB adds response metrics to AWS WAF logs, and this monitor reads none"
            )
        try:
            alb = _alb_input(
                name, target, body.alb_arn,
                region=str(waf.config.get("region")), account=waf.config.get("account_id"),
            )
        except ValueError as exc:
            raise HTTPException(422, _message(exc)) from None
        _require_allowlisted(alb)

    # Repository. The same repository is edited in place and keeps its token unless a new
    # one is sent. A different repository never inherits the old token: a fine-grained
    # token is scoped to one repository, and that scope is the only boundary on the read.
    repo: SourceInput | None = None
    repo_in_place = False
    repo_fields = {"github_repository", "github_ref", "github_token"} & fields
    repository = (
        body.github_repository if "github_repository" in fields
        else old_repo.config.get("repository") if old_repo else None
    )
    if repo_fields and repository:
        repo_in_place = old_repo is not None and old_repo.config.get("repository") == repository
        ref = body.github_ref or (
            old_repo.config.get("ref") if repo_in_place and old_repo else None
        ) or "main"
        try:
            repo = SourceInput(
                name=f"{name} · {repository}"[:160],
                target_binding=target,
                connector="github",
                config=SourceConfig(repository=repository, ref=ref),
                credentials=(
                    SourceCredentials(github_token=body.github_token)
                    if body.github_token else None
                ),
            )
        except ValueError as exc:
            raise HTTPException(422, _message(exc)) from None

    scan: Scan | None = None
    clear_contract = "scan_id" in fields and body.scan_id is None and body.openapi is None
    if body.scan_id is not None:
        scan = scans.get_scan(db, body.scan_id, tenant_id)
        if scan is None:
            raise HTTPException(404, "scan not found")
        if scan.target_base_url.rstrip("/") != target:
            raise HTTPException(409, "scan belongs to another target")
    elif body.openapi is not None:
        try:
            data, _ = load_source(body.openapi)
            parse_operations(data, target_base_url=target)
        except SpecError as exc:
            raise HTTPException(422, str(exc)) from None

    created: Scan | None = None
    try:
        context = dict(monitor.context)
        if body.openapi is not None:
            scan = created = scans.create_scan(db, target, tenant_id)
            operations.ingest_spec(db, scan, body.openapi)
        if scan is not None or clear_contract:
            context = {k: v for k, v in context.items() if k not in CONTRACT_KEYS}
            if scan is not None:
                context |= contract_context(db, scan)
            monitor.scan_id = scan.id if scan is not None else None

        if "alb_arn" in fields and not (
            alb is not None and old_origin is not None and _alb_arn(old_origin) == body.alb_arn
        ):
            _retire(db, old_origin)
            context.pop(ORIGIN_SOURCE_KEY, None)
            if alb is not None:
                context[ORIGIN_SOURCE_KEY] = str(
                    sources.save_source(db, tenant_id, alb, commit=False).id
                )

        if "github_repository" in fields and not repository:
            _retire(db, old_repo)
            context = {k: v for k, v in context.items() if k not in REPOSITORY_KEYS}
        elif repo is not None:
            if repo_in_place and old_repo is not None:
                saved = sources.save_source(
                    db, tenant_id, repo, old_repo.id, commit=False, keep_credentials=True
                )
            else:
                _retire(db, old_repo)
                saved = sources.save_source(db, tenant_id, repo, commit=False)
            context |= {
                "repository": {"repository": repo.config.repository, "ref": repo.config.ref},
                "repository_source_id": str(saved.id),
                "repository_revision": saved.revision,
            }

        monitor.name = name
        if body.schedule_enabled is not None:
            monitor.schedule_enabled = body.schedule_enabled
        if body.rapid_enabled is not None:
            monitor.rapid_enabled = body.rapid_enabled
        monitor.context = context
        if scan is not None or clear_contract:
            # Which leads apply depends on the contract (shadow routes, bots on routes
            # that require auth), so stored observations are stale until re-derived.
            from app.monitoring import service

            service.recompute(db, monitor)
        db.commit()
    except Exception:
        db.rollback()
        if created is not None:
            scans.delete_scan(db, created)
        raise
    db.refresh(monitor)
    return monitor


def setup_monitor(db: Session, tenant_id: str, body: MonitoringSetup) -> InfrastructureMonitor:
    """Create the optional contract scan, the sources and the monitor together.

    Everything that can be refused is checked before the first write, and a
    failure after a new scan exists removes it again, so a refused setup leaves
    nothing behind.
    """
    try:
        region, account, group = parse_log_group_arn(body.waf_log_group_arn)
        waf = SourceInput(
            name=f"{body.name} · AWS WAF logs"[:160],
            target_binding=body.target_binding,
            connector="aws_cloudwatch",
            config=SourceConfig(region=region, account_id=account, log_group=group),
        )
        repo = (
            SourceInput(
                name=f"{body.name} · {body.github_repository}"[:160],
                target_binding=body.target_binding,
                connector="github",
                config=SourceConfig(repository=body.github_repository, ref=body.github_ref),
                # The repository is this monitor's choice, so its own token is
                # what bounds the read; there is no deployment allowlist.
                credentials=(
                    SourceCredentials(github_token=body.github_token)
                    if body.github_token
                    else None
                ),
            )
            if body.github_repository
            else None
        )
        alb = (
            _alb_input(body.name, body.target_binding, body.alb_arn, region=region, account=account)
            if body.alb_arn
            else None
        )
    except ValueError as exc:
        raise HTTPException(422, _message(exc)) from None
    target = waf.target_binding
    _allowed_target(target)
    if alb is not None:
        _require_allowlisted(alb)
    try:
        remote.check_allowlist(waf.connector, waf.config)
    except SourceUnavailable:
        raise HTTPException(
            422,
            "This log group is not allowlisted on the server. Add its ARN to "
            "MONITORING_AWS_LOG_GROUPS in .env and restart the api and worker.",
        ) from None

    created: Scan | None = None
    scan: Scan | None = None
    if body.scan_id is not None:
        existing = scans.get_scan(db, body.scan_id, tenant_id)
        if existing is None:
            raise HTTPException(404, "scan not found")
        if existing.target_base_url.rstrip("/") != target:
            raise HTTPException(409, "scan belongs to another target")
        scan = existing
    elif body.openapi is not None:
        try:
            data, _ = load_source(body.openapi)
            parse_operations(data, target_base_url=target)
        except SpecError as exc:
            raise HTTPException(422, str(exc)) from None
        scan = created = scans.create_scan(db, target, tenant_id)
        operations.ingest_spec(db, scan, body.openapi)

    try:
        # Without a contract, routes are grouped by URL shape and the
        # contract-based leads (shadow routes, bots on authenticated routes)
        # are not evaluated.
        context = contract_context(db, scan) if scan is not None else {}
        waf_source = sources.save_source(db, tenant_id, waf, commit=False)
        if alb is not None:
            context[ORIGIN_SOURCE_KEY] = str(
                sources.save_source(db, tenant_id, alb, commit=False).id
            )
        if repo is not None:
            repo_source = sources.save_source(db, tenant_id, repo, commit=False)
            context |= {
                "repository": {"repository": repo.config.repository, "ref": repo.config.ref},
                "repository_source_id": str(repo_source.id),
                "repository_revision": repo_source.revision,
            }
        monitor = InfrastructureMonitor(
            tenant_id=tenant_id,
            name=body.name,
            target_binding=target,
            source_ids=[str(waf_source.id)],
            scan_id=scan.id if scan is not None else None,
            schedule_enabled=body.schedule_enabled,
            context=context,
        )
        db.add(monitor)
        db.commit()
    except Exception:
        db.rollback()
        if created is not None:
            scans.delete_scan(db, created)
        raise
    db.refresh(monitor)
    return monitor


def fetch_example_spec() -> str:
    """The bundled target's live OpenAPI document, so the example never drifts from it."""
    _allowed_target(EXAMPLE_TARGET)
    try:
        with httpx.Client(timeout=5, follow_redirects=False, trust_env=False) as client:
            response = client.get(f"{EXAMPLE_TARGET}/openapi.json")
    except httpx.HTTPError:
        response = None
    if (
        response is None
        or response.status_code != 200
        or len(response.content) > MAX_EXAMPLE_SPEC_BYTES
    ):
        raise HTTPException(503, "example target unavailable; start the stack with make up")
    return response.text


def create_example_scan(db: Session, tenant_id: str) -> Scan:
    """A scan of the bundled target with its spec and both seed identities, not yet run."""
    _require_examples()
    spec = fetch_example_spec()
    scan = scans.create_scan(db, EXAMPLE_TARGET, tenant_id)
    try:
        operations.ingest_spec(db, scan, spec)
        for name, role, token in EXAMPLE_CREDENTIALS:
            credentials.add_credential(
                db,
                scan,
                CredentialInput(
                    name=name,
                    role=role,
                    auth_type=AuthType.header,
                    header_name="Authorization",
                    secret=token,
                ),
            )
    except Exception:
        db.rollback()
        scans.delete_scan(db, scan)
        raise
    db.refresh(scan)
    return scan


def create_example_monitor(db: Session, tenant_id: str) -> InfrastructureMonitor:
    """A monitor on the bundled target with seven ordinary days and one attack day."""
    _require_examples()
    existing = db.scalar(
        select(InfrastructureMonitor).where(
            InfrastructureMonitor.tenant_id == tenant_id,
            InfrastructureMonitor.name == EXAMPLE_MONITOR,
            InfrastructureMonitor.target_binding == EXAMPLE_TARGET,
            InfrastructureMonitor.status == "active",
        )
    )
    if existing is not None:
        _refresh_example_contract(db, existing)
        _seed_example_rapid(db, existing)
        return existing
    scan = db.scalar(
        select(Scan)
        .where(
            Scan.tenant_id == tenant_id,
            Scan.target_base_url == EXAMPLE_TARGET,
            Scan.spec_text.is_not(None),
        )
        .order_by(Scan.created_at.desc())
        .limit(1)
    ) or create_example_scan(db, tenant_id)
    source = sources.save_source(
        db,
        tenant_id,
        SourceInput(name=f"{EXAMPLE_MONITOR} · WAF snapshots", target_binding=EXAMPLE_TARGET),
        commit=False,
    )
    monitor = InfrastructureMonitor(
        tenant_id=tenant_id,
        name=EXAMPLE_MONITOR,
        target_binding=EXAMPLE_TARGET,
        source_ids=[str(source.id)],
        scan_id=scan.id,
        rapid_enabled=True,
        context=contract_context(db, scan),
    )
    db.add(monitor)
    db.commit()
    today = datetime.now(UTC).date()
    days = demo.history(today)
    for day, records in days:
        sources.ingest_snapshot(
            db,
            monitor.id,
            tenant_id,
            source.id,
            source.revision,
            day,
            json.dumps(records).encode(),
        )
    # There is no load balancer behind the example, so its metrics are attached the way
    # collection stores them, then every day is re-judged with them in place.
    runs = {
        run.observation_date: run
        for run in db.scalars(select(MonitoringRun).where(MonitoringRun.monitor_id == monitor.id))
    }
    for day, _ in days:
        run = runs[day]
        run.metrics = {
            **run.metrics,
            "origin": demo.day_load_balancer(day, attack=day == today - timedelta(days=1)),
        }
    service.recompute(db, monitor)
    db.commit()
    _seed_example_rapid(db, monitor)
    db.refresh(monitor)
    return monitor


def _seed_example_rapid(db: Session, monitor: InfrastructureMonitor) -> None:
    """Keep the bundled dev example's latest pulse populated without weakening AWS setup."""
    monitor.rapid_enabled = True
    db.commit()
    now = datetime.now(UTC)
    timestamp = int(now.timestamp())
    newest_end = datetime.fromtimestamp(timestamp - timestamp % 300, UTC)
    for offset in (2, 1, 0):
        end = newest_end - timedelta(minutes=offset * 5)
        rapid_service.ingest(
            db,
            monitor,
            MonitoringRapidIngest(
                window_start=end - timedelta(hours=1),
                window_end=end,
                waf_records=demo.rapid_records(end, attack=offset <= 1),
            ),
        )


def _refresh_example_contract(db: Session, monitor: InfrastructureMonitor) -> None:
    """Upgrade legacy bundled examples to the explicit contract they were seeded from."""
    scan = db.get(Scan, monitor.scan_id) if monitor.scan_id else None
    if scan is None:
        return
    if scan.spec_origin == "unknown":
        scan.spec_origin = "openapi"
    fresh = contract_context(db, scan)
    context = {key: value for key, value in monitor.context.items() if key not in CONTRACT_KEYS}
    context.update(fresh)
    if context != monitor.context:
        monitor.context = context
        # Rapid evidence was judged under the old contract state; rebuild this dev fixture.
        db.execute(delete(MonitoringRapidRun).where(MonitoringRapidRun.monitor_id == monitor.id))
        db.execute(delete(MonitoringAlert).where(
            MonitoringAlert.monitor_id == monitor.id,
            MonitoringAlert.state == "rapid_anomaly",
        ))
    db.commit()
