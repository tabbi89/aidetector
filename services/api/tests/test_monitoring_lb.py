"""Load balancer leads: each hour against the same hour on earlier days.

Both directions matter. A detector that flags an hour which is always busy with refusals
teaches people to suppress it, and then the real surge in that hour is suppressed too.
"""

from datetime import UTC, date, datetime, timedelta

from sqlalchemy import select

from app.models.monitoring import InfrastructureMonitor, MonitoringRun
from app.monitoring import lb, service
from app.monitoring.waf import normalize_waf_event

LB = "app/pd-app-prod-lb/50dc6c495c0c9188"


def day(**overrides: dict) -> dict:
    """A day of hourly points: 1000 answers an hour, 2% 4XX, no 5XX, 460 ms p99.

    ``overrides`` maps ``"h<hour>"`` to fields replacing that hour's defaults.
    """
    hours = []
    for hour in range(24):
        row = {
            "hour": hour,
            "requests": 1000,
            "target_2xx": 980,
            "target_3xx": 0,
            "target_4xx": 20,
            "target_5xx": 0,
            "elb_4xx": 5,
            "elb_5xx": 0,
            "rejected_connections": 0,
            "target_connection_errors": 0,
            "response_avg": 0.08,
            "response_p99": 0.46,
        }
        row.update(overrides.get(f"h{hour}", {}))
        hours.append(row)
    return {"version": 1, "load_balancer": LB, "hours": hours}


def history(n: int = 7, **overrides: dict) -> list[dict]:
    return [day(**overrides) for _ in range(n)]


def kinds(observations: list[dict]) -> dict[str, list[int]]:
    return {o["type"]: o["hours"] for o in observations}


# --- with a baseline ----------------------------------------------------------------


def test_an_ordinary_day_raises_nothing():
    assert lb.assess(day(), history(), 7) == []


def test_a_4xx_surge_in_one_hour_is_a_lead_naming_that_hour():
    observations = lb.assess(day(h14={"target_2xx": 700, "target_4xx": 300}), history(), 7)
    assert kinds(observations) == {"lb_client_error_surge": [14]}
    (lead,) = observations
    assert (lead["severity"], lead["confidence"], lead["basis"]) == (
        "medium",
        "heuristic",
        "baseline",
    )
    (hour,) = lead["current"]["hours"]
    assert (hour["rate"], hour["usual"], hour["answered"]) == (0.3, 0.02, 1000)


def test_an_hour_that_is_always_refused_is_compared_with_itself():
    """A nightly job refused 40% of the time every night is normal at 03:00."""
    nightly = {"target_2xx": 600, "target_4xx": 400}
    assert lb.assess(day(h3={"target_2xx": 560, "target_4xx": 440}), history(h3=nightly), 7) == []


def test_a_small_rise_on_a_flat_history_is_not_a_surge():
    """Zero spread would make one extra 4XX an anomaly; the floors stop that."""
    assert lb.assess(day(h10={"target_2xx": 950, "target_4xx": 50}), history(), 7) == []


def test_a_noisy_history_needs_a_bigger_jump():
    noisy = [
        day(h9={"target_2xx": 1000 - r, "target_4xx": r}) for r in (20, 60, 150, 30, 120, 40, 90)
    ]
    assert lb.assess(day(h9={"target_2xx": 850, "target_4xx": 150}), noisy, 7) == []
    assert kinds(lb.assess(day(h9={"target_2xx": 500, "target_4xx": 500}), noisy, 7)) == {
        "lb_client_error_surge": [9],
    }


def test_quiet_hours_are_not_judged():
    """Three 5XX out of twenty answers is 15%, and means nothing."""
    quiet = {"requests": 20, "target_2xx": 17, "target_4xx": 0, "target_5xx": 3}
    assert (
        lb.assess(day(h4=quiet), history(h4={"requests": 20, "target_2xx": 20, "target_4xx": 0}), 7)
        == []
    )


def test_server_errors_escalate_to_high_at_a_tenth_of_answers():
    medium = lb.assess(day(h12={"target_2xx": 940, "target_5xx": 40}), history(), 7)
    high = lb.assess(day(h12={"target_2xx": 830, "target_5xx": 150}), history(), 7)
    assert [(o["type"], o["severity"]) for o in medium] == [("lb_server_error_surge", "medium")]
    assert [(o["type"], o["severity"]) for o in high] == [("lb_server_error_surge", "high")]


def test_affected_hours_group_into_one_lead_per_kind():
    surge = {"target_2xx": 700, "target_4xx": 300}
    (lead,) = lb.assess(day(h14=surge, h15=surge, h2=surge), history(), 7)
    assert lead["hours"] == [2, 14, 15]


def test_latency_must_double_and_grow_by_half_a_second():
    assert lb.assess(day(h8={"response_p99": 0.9}), history(), 7) == []  # doubled, +0.44s
    assert kinds(lb.assess(day(h8={"response_p99": 1.4}), history(), 7)) == {
        "lb_latency_surge": [8],
    }
    (lead,) = lb.assess(day(h8={"response_p99": 1.4}), history(), 7)
    assert lead["severity"] == "low"


def test_an_hour_missing_from_a_baseline_day_is_not_judged():
    """A median over fewer days than the baseline claims would overstate it."""
    gappy = history(6) + [
        {"version": 1, "load_balancer": LB, "hours": [h for h in day()["hours"] if h["hour"] != 14]}
    ]
    assert lb.assess(day(h14={"target_2xx": 700, "target_4xx": 300}), gappy, 7) == []


def test_the_fingerprint_is_stable_across_days_and_hours():
    """So suppressing a kind on this load balancer keeps it suppressed tomorrow."""
    a = lb.assess(day(h14={"target_2xx": 700, "target_4xx": 300}), history(), 7)
    b = lb.assess(day(h3={"target_2xx": 700, "target_4xx": 300}), history(), 7)
    assert a[0]["fingerprint"] == b[0]["fingerprint"]
    other = dict(
        day(h14={"target_2xx": 700, "target_4xx": 300}), load_balancer="app/x/1111222233334444"
    )
    assert lb.assess(other, history(), 7)[0]["fingerprint"] != a[0]["fingerprint"]


# --- before a baseline, and without metrics -----------------------------------------


def test_before_a_baseline_only_server_errors_are_judged():
    refusals = {"target_2xx": 500, "target_4xx": 500}
    slow = {"response_p99": 9.0}
    assert lb.assess(day(h14=refusals, h15=slow), history(2), 7) == []
    (lead,) = lb.assess(day(h14={"target_2xx": 900, "target_5xx": 80}), history(2), 7)
    assert (lead["type"], lead["basis"], lead["current"]["hours"][0]["usual"]) == (
        "lb_server_error_surge",
        "single_day",
        None,
    )


def test_single_day_server_errors_need_both_a_share_and_a_count():
    few = {"requests": 200, "target_2xx": 170, "target_4xx": 0, "target_5xx": 30}  # 15%, 30
    assert lb.assess(day(h1=few), [], 7) == []


def test_a_day_whose_metrics_read_failed_raises_nothing_and_is_not_a_baseline_day():
    assert lb.assess({"error": "access_denied"}, history(), 7) == []
    assert lb.assess(None, history(), 7) == []
    failed = history(6) + [{"error": "access_denied"}]
    surge = day(h14={"target_2xx": 700, "target_4xx": 300})
    # Six real baseline days are not seven: only server errors are judged.
    assert lb.assess(surge, failed, 7) == []


# --- through recompute ----------------------------------------------------------------


def waf_day(db_session, monitor, when: date):
    start = datetime(when.year, when.month, when.day, 12, tzinfo=UTC)
    events = [
        normalize_waf_event(
            {
                "timestamp": (start + timedelta(seconds=i)).isoformat(),
                "httpMethod": "GET",
                "uri": "/search",
                "clientIp": f"198.51.100.{i}",
                "requestId": f"{when}-{i}",
            },
            salt=b"s",
        )
        for i in range(1, 30)
    ]
    return service.ingest_normalized_events(
        db_session, monitor, events, observation_date=when, source_revisions={}
    )


def test_recompute_raises_triages_and_ranks_load_balancer_leads(db_session):
    monitor = InfrastructureMonitor(
        tenant_id="default", name="m", target_binding="https://t.test", source_ids=[]
    )
    monitor.minimum_baseline_days = 3
    db_session.add(monitor)
    db_session.commit()
    last = date(2026, 9, 15)
    for offset in (3, 2, 1, 0):
        waf_day(db_session, monitor, last - timedelta(days=offset))
    runs = list(
        db_session.scalars(
            select(MonitoringRun)
            .where(MonitoringRun.monitor_id == monitor.id)
            .order_by(MonitoringRun.observation_date)
        )
    )
    for run in runs[:-1]:
        run.metrics = {**run.metrics, "origin": day()}
    runs[-1].metrics = {
        **runs[-1].metrics,
        "origin": day(h14={"target_2xx": 780, "target_5xx": 200}),
    }
    service.recompute(db_session, monitor)
    db_session.commit()
    db_session.refresh(runs[-1])

    (lead,) = [o for o in runs[-1].observations if o["type"].startswith("lb_")]
    assert (lead["type"], lead["severity"], lead["hours"]) == (
        "lb_server_error_surge",
        "high",
        [14],
    )
    assert runs[-1].state == "anomaly"
    # A high lead sorts ahead of the medium ones the WAF detectors raise.
    assert runs[-1].observations[0]["fingerprint"] == lead["fingerprint"]

    monitor.triage = {lead["fingerprint"]: "suppressed"}
    service.recompute(db_session, monitor)
    db_session.commit()
    db_session.refresh(runs[-1])
    (again,) = [o for o in runs[-1].observations if o["type"].startswith("lb_")]
    assert again["disposition"] == "suppressed"
