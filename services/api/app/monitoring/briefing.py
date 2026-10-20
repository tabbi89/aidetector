"""On-demand AI briefing of a monitor's bot, AI and client traffic.

Where an explanation answers "what is this one observation", a briefing answers
the question a person opening the page actually has: is anything here worth
caring about, when should I react, and how would this raise an alert.

The provider receives the same value-free aggregates the page shows plus the
detectors' own rules, built from their constants, so the model explains the
thresholds that run rather than ones it imagines. A briefing is commentary
stored on the monitor: it never changes an observation, a state or an alert,
and a disabled or failing provider records a fixed reason instead.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai.provider import ProviderUnavailable, build_monitoring_provider
from app.core.db import SessionLocal
from app.domain.enums import SEVERITY_RANK, Severity
from app.models.monitoring import InfrastructureMonitor, MonitoringAlert, MonitoringRun
from app.monitoring import analysis, bots, clients, lb
from app.monitoring.explain import MAX_TEXT, AgentLog, day_sampling, shared_observation
from app.monitoring.service import open_observations

MAX_STRUCTURED_BYTES = 48_000
MAX_EVIDENCE_BYTES = 120_000
MAX_OBSERVATIONS = 40
MAX_CRAWLERS = 25
MAX_CLIENTS = 15
MAX_ALERTS = 20
MAX_LEAD_HISTORY = 60
MAX_CRAWLER_ROUTES = 5
LB_ANSWERS = ("target_2xx", "target_3xx", "target_4xx", "target_5xx")
LB_DAY_FIELDS = (
    "requests",
    "target_responses",
    "success_rate",
    "client_error_rate",
    "server_error_rate",
    "stopped_at_load_balancer_rate",
    "response_p99_max",
)


def _rule(kind: str, detector: str, severity: str, trigger: str, remediation: str) -> dict:
    return {
        "type": kind,
        "detector": detector,
        "severity": severity,
        "trigger": trigger,
        "remediation": remediation,
    }


def _pct(value: float) -> str:
    return f"{value * 100:g}%"


def rules() -> list[dict]:
    """What each lead means and when it fires, from the detectors' own constants.

    "Before the baseline" is a day with fewer than minimum_baseline_days complete prior
    days; single-day rules are absolute and stricter, baseline rules compare with the
    median of those days.
    """
    a, b, c = analysis, bots, clients
    return [
        _rule(
            "bot_identity_spoof", "bots", "medium",
            "A crawler name AWS Bot Control verified (the same day before the baseline, on "
            "earlier baseline days after) also arrived unverified at least "
            f"{b.SPOOF_REQUESTS} times.",
            b.REMEDIATION["bot_identity_spoof"],
        ),
        _rule(
            "unverified_ai_surge", "bots", "medium",
            "Baseline only. Unverified AI-category requests in the day are at least "
            f"{b.AI_SURGE_REQUESTS} and at least {b.AI_SURGE_RATIO}x the median of the "
            "baseline days.",
            b.REMEDIATION["unverified_ai_surge"],
        ),
        _rule(
            "bot_on_protected_route", "bots", "low",
            f"An unverified bot was allowed by the WAF at least {b.PROTECTED_ALLOWED} times on "
            "an operation the API contract declares as authenticated. WAF logs carry no origin "
            "status, so the app may still have refused it. Needs an API contract.",
            b.REMEDIATION["bot_on_protected_route"],
        ),
        _rule(
            "ja4_request_manipulation", "clients",
            "medium when any matching request was allowed, low when all were blocked",
            f"Any day. At least {c.ATTACK_MATCHES} requests from one TLS (JA4) fingerprint "
            "matched AWS managed rules for injection, traversal or exploit payloads.",
            c.REMEDIATION["ja4_request_manipulation"],
        ),
        _rule(
            "ja4_identifier_enumeration", "clients", "medium",
            f"Any day. One JA4 fingerprint asked for at least {c.ENUM_IDS} distinct identifiers "
            f"on one route, at least {_pct(c.ENUM_SEQUENTIAL)} consecutive, and at least "
            f"{c.PER_ADDRESS} per source address. Verified bots and allow-listed traffic never "
            "count.",
            c.REMEDIATION["ja4_identifier_enumeration"],
        ),
        _rule(
            "ja4_endpoint_probing", "clients", "medium",
            f"Any day. One JA4 fingerprint asked for at least {c.PROBE_PATHS} distinct paths, "
            f"at least {_pct(c.PROBE_RATIO)} of its requests, and at least {c.PER_ADDRESS} per "
            "source address. Verified bots and allow-listed traffic never count.",
            c.REMEDIATION["ja4_endpoint_probing"],
        ),
        _rule(
            "enumeration_anomaly", "requests", "medium",
            "Per method, route, client and hour. Before the baseline: at least "
            f"{a.DAY_ENUM_IDENTIFIERS} distinct identifiers, and either {_pct(a.ENUM_SEQUENTIAL)} "
            f"consecutive or at least {a.DAY_ENUM_NOT_FOUND} 404s. With the baseline: requests "
            f"at least {a.SURGE_REQUESTS} and {a.SURGE_RATIO}x usual, identifiers at least "
            f"{a.ENUM_IDENTIFIERS} and {a.ENUM_IDENTIFIER_RATIO}x usual, and either "
            f"{_pct(a.ENUM_SEQUENTIAL)} consecutive or at least {a.ENUM_NOT_FOUND} 404s.",
            a.REMEDIATION["enumeration_anomaly"],
        ),
        _rule(
            "account_enumeration_lead", "requests", "medium",
            "On a route whose path contains " + ", ".join(a.ACCOUNT_ROUTE_WORDS) + ", answered "
            "with more than one response shape. Before the baseline: at least "
            f"{a.DAY_ACCOUNT_REQUESTS} requests in an hour from one client. With the baseline: "
            f"at least {a.SURGE_REQUESTS} and {a.SURGE_RATIO}x usual.",
            a.REMEDIATION["account_enumeration_lead"],
        ),
        _rule(
            "high_volume_client", "requests", "medium",
            f"Before the baseline only. One identified client made at least "
            f"{a.HIGH_VOLUME_REQUESTS} requests and {_pct(a.HIGH_VOLUME_SHARE)} of an hour's "
            "traffic. After the baseline this lead is not raised. Both are counted in the "
            "day's evidence: on a sampled day that is the newest events of the hour, so the "
            "count and share describe the end of the hour, not the client's full volume.",
            a.REMEDIATION["high_volume_client"],
        ),
        _rule(
            "response_size_drift", "requests", "medium",
            f"Baseline only. A route's median response is over {a.SIZE_RATIO}x its usual median "
            f"and over {a.SIZE_FLOOR_BYTES} bytes.",
            a.REMEDIATION["response_size_drift"],
        ),
        _rule(
            "sensitive_request_metadata", "requests", "medium",
            "Any day. Credentials or personal data were seen in URLs or Referer headers "
            "(names of the locations only, never values).",
            a.REMEDIATION["sensitive_request_metadata"],
        ),
        _rule(
            "shadow_route", "requests", "medium",
            "Any day, with an API contract. Traffic reached a route the contract does not "
            "declare, matched only by a path heuristic.",
            a.REMEDIATION["shadow_route"],
        ),
        _rule(
            "lb_server_error_surge", "load_balancer",
            f"high when an hour reaches {_pct(lb.HIGH_SERVER_RATE)} 5XX, otherwise medium",
            f"Per hour with at least {lb.MIN_ANSWERED} app answers. Before the baseline: at "
            f"least {lb.SINGLE_DAY_SERVER_COUNT} 5XX and {_pct(lb.SINGLE_DAY_SERVER_RATE)} of "
            f"answers. With the baseline: at least {lb.SERVER_ERROR_RATIO:g}x the same hour's "
            f"usual share, {_pct(lb.SERVER_ERROR_FLOOR)} points above it, and "
            f"{lb.SPREAD_UNITS:g} spread units above it.",
            lb.REMEDIATION["lb_server_error_surge"],
        ),
        _rule(
            "lb_client_error_surge", "load_balancer", "medium",
            f"Baseline only, per hour with at least {lb.MIN_ANSWERED} app answers. 4XX share at "
            f"least {lb.CLIENT_ERROR_RATIO:g}x the same hour's usual, "
            f"{_pct(lb.CLIENT_ERROR_FLOOR)} points above it, and {lb.SPREAD_UNITS:g} spread "
            "units above it.",
            lb.REMEDIATION["lb_client_error_surge"],
        ),
        _rule(
            "lb_latency_surge", "load_balancer", "low",
            f"Baseline only, per hour with at least {lb.MIN_ANSWERED} app answers. p99 latency "
            f"at least {lb.LATENCY_RATIO:g}x the same hour's usual and "
            f"{lb.LATENCY_FLOOR_SECONDS:g}s slower.",
            lb.REMEDIATION["lb_latency_surge"],
        ),
    ]


#: How the monitor turns leads into alerts, as ``service.recompute`` implements it.
ALERTING = [
    "Collection runs once a day for the previous UTC days, so a lead appears about a day "
    "after the traffic.",
    "Every lead is heuristic: it shows intent or exposure risk, not a confirmed breach.",
    "Before the monitor has minimum_baseline_days of prior complete days the state is "
    "warming_up: single-day leads (spoofing, JA4, 5XX) are shown but no alert is created.",
    "After that, a day with any lead that is not suppressed is in the anomaly state; with "
    "none it is baseline_ready; with no events it is no_data.",
    "An alert is created only when the latest day's state changes to anomaly, "
    "baseline_ready or no_data. A day that stays in anomaly creates no new alert, even "
    "when a new or more severe lead appears.",
    "A failed collection creates one degraded alert per day, closed automatically when "
    "that day later collects.",
    "Suppressing a lead removes it from the anomaly decision.",
    "Alerts are listed on the monitor page and its API only; no email, chat or webhook "
    "notification is sent.",
]


def _fits(evidence: dict) -> bool:
    return len(json.dumps(evidence, default=str)) <= MAX_EVIDENCE_BYTES


def _brief_lead(observation: dict) -> dict:
    """A lead named without its evidence: what, where and how bad."""
    return {
        key: observation[key]
        for key in ("type", "method", "route_family", "severity", "hours")
        if key in observation
    }


def lead_history(runs: list[MonitoringRun], triage: dict, latest: MonitoringRun | None) -> list:
    """Every distinct lead in the window, with the days it appeared, worst and newest first.

    A lead still open on the latest day carries its evidence there, so it is named here
    without it; an earlier one keeps the evidence of the last day it was seen, which is
    the only place that evidence survives.
    """
    leads: dict[str, dict] = {}
    for run in runs:
        if run.status != "complete":
            continue
        for observation in run.observations or []:
            fingerprint = observation.get("fingerprint")
            if not fingerprint:
                continue
            entry = leads.setdefault(fingerprint, {"days": [], "_last": observation})
            entry["days"].append(run.observation_date.isoformat())
            entry["_last"] = observation
    latest_date = latest.observation_date.isoformat() if latest else None
    rows = []
    for fingerprint, entry in leads.items():
        last = entry.pop("_last")
        on_latest = entry["days"][-1] == latest_date
        row = {
            **(_brief_lead(last) if on_latest else shared_observation(last)),
            "days": entry["days"],
            "first_seen": entry["days"][0],
            "last_seen": entry["days"][-1],
            "on_latest_day": on_latest,
            "disposition": triage.get(fingerprint, "candidate"),
        }
        rows.append(row)
    rows.sort(key=lambda row: (
        -_severity_rank(row.get("severity")),
        _neg_date(row["last_seen"]),
        str(row.get("type")),
    ))
    return rows[:MAX_LEAD_HISTORY]


def _severity_rank(value: object) -> int:
    try:
        return SEVERITY_RANK[Severity(str(value))]
    except ValueError:
        return SEVERITY_RANK[Severity.info]


def _neg_date(value: str) -> int:
    return -date.fromisoformat(value).toordinal()


def load_balancer_day(run: MonitoringRun) -> dict | None:
    """One day's app answers from the load balancer, and its worst hours."""
    origin = run.metrics.get("origin")
    if not isinstance(origin, dict):
        return None
    day: dict = {"date": run.observation_date.isoformat()}
    if origin.get("error"):
        return {**day, "error": origin["error"]}
    stored_total = origin.get("total")
    total: dict = stored_total if isinstance(stored_total, dict) else {}
    day |= {key: total.get(key) for key in LB_DAY_FIELDS if key in total}
    hours = [
        h for h in origin.get("hours") or []
        if isinstance(h, dict) and sum(int(h.get(k) or 0) for k in LB_ANSWERS) >= lb.MIN_ANSWERED
    ]

    def rate(hour: dict, key: str) -> float:
        return int(hour.get(key) or 0) / max(1, sum(int(hour.get(k) or 0) for k in LB_ANSWERS))

    day["worst_5xx_hours"] = [
        {"hour": h.get("hour"), "rate": round(rate(h, "target_5xx"), 4)}
        for h in sorted(hours, key=lambda h: -rate(h, "target_5xx"))[:3]
        if h.get("target_5xx")
    ]
    day["worst_4xx_hours"] = [
        {"hour": h.get("hour"), "rate": round(rate(h, "target_4xx"), 4)}
        for h in sorted(hours, key=lambda h: -rate(h, "target_4xx"))[:3]
        if h.get("target_4xx")
    ]
    day["slowest_hours"] = [
        {"hour": h.get("hour"), "p99": h.get("response_p99")}
        for h in sorted(
            (h for h in hours if isinstance(h.get("response_p99"), int | float)),
            key=lambda h: -float(h["response_p99"]),
        )[:3]
    ]
    return day


def evidence(db: Session, monitor: InfrastructureMonitor, days: int) -> dict:
    """The value-free facts a briefing may use. Cohorts are HMACs of people and stay out."""
    since = datetime.now(UTC).date() - timedelta(days=days)
    runs = list(db.scalars(
        select(MonitoringRun)
        .where(MonitoringRun.monitor_id == monitor.id, MonitoringRun.observation_date >= since)
        .order_by(MonitoringRun.observation_date.asc())
    ))
    complete = [run for run in runs if run.status == "complete"]
    latest = complete[-1] if complete else None
    observations = list((latest.observations if latest else None) or [])
    unanswered = open_observations(observations)
    suppressed = [o for o in observations if o not in unanswered]
    stored_clients = (latest.metrics.get("clients") if latest else None) or {}
    client_rows = clients.with_flags(stored_clients, limit=clients.MAX_CLIENTS)
    alerts = db.scalars(
        select(MonitoringAlert)
        .where(MonitoringAlert.monitor_id == monitor.id)
        .order_by(MonitoringAlert.created_at.desc())
        .limit(MAX_ALERTS)
    )
    result: dict = {
        "window_days": days,
        "monitor": {
            "minimum_baseline_days": monitor.minimum_baseline_days,
            "schedule_enabled": monitor.schedule_enabled,
            "status": monitor.status,
            "has_api_contract": bool(monitor.context.get("routes")),
        },
        "latest_day": None if latest is None else {
            "date": latest.observation_date.isoformat(),
            "state": latest.state,
            "data_quality": latest.data_quality,
            "baseline_days_available": latest.baseline_days_available,
            "sampled": bool(latest.metrics.get("sample")),
            "sampling": day_sampling(latest),
            "open_leads": [shared_observation(o) for o in unanswered[:MAX_OBSERVATIONS]],
            "open_leads_total": len(unanswered),
            "suppressed_leads": [_brief_lead(o) for o in suppressed[:MAX_OBSERVATIONS]],
            "suppressed_leads_total": len(suppressed),
        },
        "lead_history": lead_history(runs, monitor.triage or {}, latest),
        "days": [
            {
                "date": run.observation_date.isoformat(),
                "status": run.status,
                "state": run.state,
                "error_code": run.error_code,
                "open_leads": len(open_observations(run.observations)),
            } | ({"sampling": day_sampling(run)} if run.status == "complete" else {})
            for run in runs
        ],
        "load_balancer_days": [day for run in complete if (day := load_balancer_day(run))],
        "bots": bots.summarize(
            [(run.observation_date, run.metrics.get("bots") or {}) for run in complete],
            limit=MAX_CRAWLERS,
            routes=MAX_CRAWLER_ROUTES,
        ),
        "tls_clients": {
            "day": latest.observation_date.isoformat() if latest else None,
            "clients_total": int(stored_clients.get("clients_total") or len(client_rows)),
            "flagged": [
                {k: v for k, v in row.items() if k != "cohort"}
                for row in client_rows
                if row["flags"]
            ][:MAX_CLIENTS],
        },
        "alerts": [
            {
                "state": alert.state,
                "observation_date": alert.observation_date.isoformat(),
                "acknowledged": alert.acknowledged,
            }
            for alert in alerts
        ],
        "rules": rules(),
        "alerting": ALERTING,
        "evidence_trimmed": [],
    }
    history = result["lead_history"]
    latest_day = result["latest_day"] or {}
    crawlers = result["bots"]["crawlers"]
    trims: list[tuple[str, Callable[[], object]]] = [
        ("daily bot category series", lambda: result["bots"].pop("series", None)),
        ("earlier leads' evidence", lambda: history.__setitem__(
            slice(None), [{k: v for k, v in r.items() if k != "current"} for r in history]
        )),
        ("crawler routes beyond the top 3", lambda: [
            row.update(routes=row.get("routes", [])[:3]) for row in crawlers
        ]),
        ("load balancer worst hours", lambda: [
            day.pop(key, None)
            for day in result["load_balancer_days"]
            for key in ("worst_4xx_hours", "slowest_hours")
        ]),
        ("flagged TLS clients beyond 5", lambda: result["tls_clients"].update(
            flagged=result["tls_clients"]["flagged"][:5]
        )),
        ("crawlers beyond the top 10", lambda: crawlers.__delitem__(slice(10, None))),
        ("lead history beyond 20", lambda: history.__delitem__(slice(20, None))),
        ("latest-day leads beyond 10", lambda: latest_day and latest_day.update(
            open_leads=latest_day["open_leads"][:10]
        )),
    ]
    # Cut the least decisive parts first, and say what was cut so the reader knows.
    for name, trim in trims:
        if _fits(result):
            break
        trim()
        result["evidence_trimmed"].append(name)
    if not _fits(result):
        result["evidence_trimmed"].append("still over the size budget")
    return result


def _now() -> str:
    return datetime.now(UTC).isoformat()


def request(db: Session, monitor: InfrastructureMonitor, days: int) -> InfrastructureMonitor:
    locked = db.scalar(
        select(InfrastructureMonitor)
        .where(InfrastructureMonitor.id == monitor.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if locked is None:
        raise HTTPException(404, "monitor not found")
    locked.ai_briefing = {"status": "pending", "requested_at": _now(), "days": days}
    db.commit()
    return locked


def mark_unavailable(db: Session, monitor: InfrastructureMonitor, reason: str) -> None:
    monitor.ai_briefing = {
        **(monitor.ai_briefing or {}),
        "status": "unavailable",
        "reason": reason,
        "finished_at": _now(),
    }
    db.commit()


def _store_if_current(monitor_id: uuid.UUID, requested_at: object, value: dict) -> bool:
    """Write onto the monitor only while this request is still the pending one."""
    with SessionLocal() as db:
        monitor = db.scalar(
            select(InfrastructureMonitor)
            .where(InfrastructureMonitor.id == monitor_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        current = (monitor.ai_briefing if monitor else None) or {}
        if (
            monitor is None
            or current.get("status") != "pending"
            or current.get("requested_at") != requested_at
        ):
            db.rollback()
            return False
        monitor.ai_briefing = value
        db.commit()
        return True


class BriefingLog(AgentLog):
    """Value-free agent progress, saved on the pending briefing as it arrives."""

    def __init__(self, monitor_id: uuid.UUID, requested_at: object, base: dict) -> None:
        super().__init__(monitor_id, "", requested_at)
        self.base = base

    def _persist(self) -> None:
        _store_if_current(self.run_id, self.requested_at, {**self.base, "log": list(self.lines)})


def run_briefing(monitor_id: str) -> dict:
    with SessionLocal() as db:
        monitor = db.get(InfrastructureMonitor, uuid.UUID(monitor_id))
        pending = dict((monitor.ai_briefing if monitor else None) or {})
        if monitor is None or pending.get("status") != "pending":
            return {"status": "missing"}
        requested_at = pending.get("requested_at")
        days = int(pending.get("days") or 28)
        facts = evidence(db, monitor, days)
        db.commit()  # hold no lock across a slow provider call
    latest = facts.get("latest_day") or {}
    log = BriefingLog(uuid.UUID(monitor_id), requested_at, pending)
    log.add("Preparing value-free traffic aggregates, leads, alerts and detector rules")
    value: dict = {"requested_at": requested_at, "days": days}
    try:
        response = build_monitoring_provider().brief(facts, on_event=log.event)
        structured = response.structured
        if structured is not None and len(json.dumps(structured)) > MAX_STRUCTURED_BYTES:
            structured = None
        value |= {
            "status": "complete",
            "provider": response.provider,
            "model": response.model,
            "text": response.text[:MAX_TEXT],
            "structured": structured,
            "evidence_through": latest.get("date"),
            "evidence_trimmed": facts.get("evidence_trimmed") or [],
            "tokens_in": sum(u.tokens_in for u in response.usages),
            "tokens_out": sum(u.tokens_out for u in response.usages),
        }
    except ProviderUnavailable as exc:
        value |= {"status": "unavailable", "reason": exc.code}
    except Exception:  # noqa: BLE001 — an AI failure never fails monitoring
        value |= {"status": "unavailable", "reason": "provider_error"}
    value |= {"finished_at": _now(), "log": log.lines}
    if not _store_if_current(uuid.UUID(monitor_id), requested_at, value):
        return {"status": "superseded"}
    return {"status": value["status"]}

