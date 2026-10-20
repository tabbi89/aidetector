"""Load balancer CloudWatch metrics: the hourly read, and how it joins a WAF day.

The read signs with the worker's production identity, and a failure in it must never
cost the WAF day it is added to -- while a cancel raised during it still must.
"""

import json
import threading
from datetime import UTC, date, datetime, timedelta

import httpx
import pytest

from app.core.config import settings
from app.monitoring import remote
from app.monitoring.contracts import SourceConfig, SourceUnavailable

DAY = date(2026, 9, 14)
ACCOUNT, REGION = "257498453293", "us-west-2"
LB = "app/pd-app-prod-lb/50dc6c495c0c9188"
LB_ARN = f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/{LB}"
CONFIG = SourceConfig(region=REGION, account_id=ACCOUNT, load_balancer=LB)
WAF_ARN = f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:aws-waf-logs-pd_prod"


class ChainCredentials:
    def get_frozen_credentials(self):
        return type("Frozen", (), {"access_key": "AKIDCHAIN", "secret_key": "s", "token": None})()


def epoch(day: date, hour: int) -> float:
    return datetime(day.year, day.month, day.day, hour, tzinfo=UTC).timestamp()


class FakeMetrics:
    """GetMetricData over ``{id: {hour: value}}``, optionally split into pages."""

    def __init__(self, day: date, series: dict[str, dict[int, float]], *, pages: int = 1,
                 error: str | None = None, extra_points: bool = False, endless: bool = False):
        self.day, self.series, self.pages, self.error = day, series, pages, error
        self.extra_points, self.endless = extra_points, endless
        self.calls: list[httpx.Request] = []
        self.lock = threading.Lock()

    def __call__(self, request: httpx.Request) -> httpx.Response:
        with self.lock:
            self.calls.append(request)
        if self.error:
            return httpx.Response(400, json={"__type": self.error})
        body = json.loads(request.content)
        page = int(body.get("NextToken") or 0)
        results = []
        for query in body["MetricDataQueries"]:
            points = sorted(self.series.get(query["Id"], {}).items())
            if self.extra_points:  # outside the requested day; must be ignored
                points.append((-1, 999.0))
            mine = [p for i, p in enumerate(points) if i % self.pages == page]
            results.append({
                "Id": query["Id"],
                "Timestamps": [
                    epoch(self.day, h) if h >= 0 else epoch(self.day - timedelta(days=1), 23)
                    for h, _ in mine
                ],
                "Values": [v for _, v in mine],
                "StatusCode": "Complete",
            })
        out: dict = {"MetricDataResults": results}
        if self.endless or page + 1 < self.pages:
            out["NextToken"] = str(page + 1)
        return httpx.Response(200, json=out)


@pytest.fixture
def aws(monkeypatch):
    monkeypatch.setattr(settings, "monitoring_aws_load_balancers", LB_ARN)
    monkeypatch.setattr(remote, "ambient_credentials", lambda: ChainCredentials())
    monkeypatch.setattr(remote, "sleep", lambda seconds: None)


def serve(monkeypatch, fake):
    monkeypatch.setattr(
        remote, "client_factory", lambda: httpx.Client(transport=httpx.MockTransport(fake))
    )
    return fake


def read(day=DAY, check=lambda: None):
    return remote.alb_metrics(CONFIG, {}, day, check, seconds=30)


SERIES = {
    "requests": {12: 1000.0, 14: 400.0},
    "target_2xx": {12: 900.0, 14: 100.0},
    "target_4xx": {12: 40.0, 14: 280.0},
    "target_5xx": {12: 10.0},
    "elb_4xx": {12: 50.0, 14: 20.0},
    "response_p99": {12: 0.4578, 14: 1.2},
    "response_avg": {12: 0.08},
}


# --- the read -----------------------------------------------------------------------


def test_one_signed_request_asks_for_every_metric_by_hour_for_this_load_balancer(
    aws, monkeypatch
):
    fake = serve(monkeypatch, FakeMetrics(DAY, SERIES))
    read()
    (call,) = fake.calls
    assert call.url.host == f"monitoring.{REGION}.amazonaws.com"
    assert call.headers["x-amz-target"] == "GraniteServiceVersion20100801.GetMetricData"
    assert call.headers["content-type"] == "application/x-amz-json-1.0"
    auth = call.headers["authorization"]
    assert "AKIDCHAIN" in auth and f"/{REGION}/monitoring/aws4_request" in auth
    body = json.loads(call.content)
    assert body["EndTime"] - body["StartTime"] == 86_400
    assert body["StartTime"] == epoch(DAY, 0)
    stats = {q["Id"]: q["MetricStat"] for q in body["MetricDataQueries"]}
    assert set(stats) == set(remote.ALB_METRICS)
    for stat in stats.values():
        assert stat["Period"] == 3600
        assert stat["Metric"]["Namespace"] == "AWS/ApplicationELB"
        assert stat["Metric"]["Dimensions"] == [{"Name": "LoadBalancer", "Value": LB}]
    assert stats["response_p99"]["Stat"] == "p99"


def test_points_fold_into_24_hours_with_gaps_as_zero_counts_and_unknown_latency(
    aws, monkeypatch
):
    serve(monkeypatch, FakeMetrics(DAY, SERIES))
    metrics, _ = read()
    hours = metrics["hours"]
    assert [h["hour"] for h in hours] == list(range(24))
    assert hours[14]["target_4xx"] == 280 and hours[14]["response_p99"] == 1.2
    # No datapoint in an hour means no requests, but not a latency of zero.
    assert hours[3]["requests"] == 0 and hours[3]["response_p99"] is None


def test_day_totals_rate_responses_over_what_the_app_answered(aws, monkeypatch):
    serve(monkeypatch, FakeMetrics(DAY, SERIES))
    total = read()[0]["total"]
    assert total["target_responses"] == 1330
    assert total["server_error_rate"] == round(10 / 1330, 4)
    assert total["client_error_rate"] == round(320 / 1330, 4)
    # Stopped at the load balancer (a WAF block is an ELB 403) is a share of all requests.
    assert total["stopped_at_load_balancer_rate"] == round(70 / 1400, 4)
    assert total["response_p99_max"] == 1.2


def test_a_day_with_no_traffic_has_no_rates_rather_than_zero(aws, monkeypatch):
    serve(monkeypatch, FakeMetrics(DAY, {}))
    total = read()[0]["total"]
    assert total["requests"] == 0
    assert total["server_error_rate"] is None and total["response_p99_max"] is None


def test_pages_are_followed_and_merged(aws, monkeypatch):
    fake = serve(monkeypatch, FakeMetrics(DAY, SERIES, pages=2))
    metrics, _ = read()
    assert len(fake.calls) == 2
    assert metrics["hours"][12]["requests"] == 1000 and metrics["hours"][14]["requests"] == 400


def test_a_result_that_never_stops_paging_fails_rather_than_looping(aws, monkeypatch):
    serve(monkeypatch, FakeMetrics(DAY, SERIES, endless=True))
    with pytest.raises(SourceUnavailable) as raised:
        read()
    assert raised.value.code in {"incomplete_pagination", "call_limit"}


def test_points_outside_the_day_are_ignored(aws, monkeypatch):
    serve(monkeypatch, FakeMetrics(DAY, SERIES, extra_points=True))
    assert read()[0]["hours"][23]["requests"] == 0


def test_the_digest_follows_the_data(aws, monkeypatch):
    serve(monkeypatch, FakeMetrics(DAY, SERIES))
    first = read()
    serve(monkeypatch, FakeMetrics(DAY, SERIES, pages=2))
    assert read() == first
    serve(monkeypatch, FakeMetrics(DAY, {**SERIES, "target_5xx": {12: 11.0}}))
    assert read()[1] != first[1]


@pytest.mark.parametrize(
    "error,code",
    [("AccessDenied", "access_denied"), ("AccessDeniedException", "access_denied"),
     ("SomethingNew", "source_unavailable")],
)
def test_errors_map_to_codes(aws, monkeypatch, error, code):
    serve(monkeypatch, FakeMetrics(DAY, SERIES, error=error))
    with pytest.raises(SourceUnavailable) as raised:
        read()
    assert raised.value.code == code


def test_throttling_is_retried(aws, monkeypatch):
    fake = FakeMetrics(DAY, SERIES)
    first = {"done": False}

    def throttled_once(request):
        if not first["done"]:
            first["done"] = True
            return httpx.Response(400, json={"__type": "Throttling"})
        return fake(request)

    serve(monkeypatch, throttled_once)
    assert read()[0]["hours"][12]["requests"] == 1000


def test_a_load_balancer_that_is_not_allowlisted_is_never_called(monkeypatch):
    monkeypatch.setattr(settings, "monitoring_aws_load_balancers", "")
    fake = serve(monkeypatch, FakeMetrics(DAY, SERIES))
    with pytest.raises(SourceUnavailable) as raised:
        read()
    assert raised.value.code == "source_not_allowed"
    assert fake.calls == []


# --- collection: metrics add to a WAF day and can never cost it -----------------------


def cloudwatch_logs(records):
    def respond(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        rows = [r for r in records if body["startTime"] <= r["timestamp"] <= body["endTime"]]
        return httpx.Response(200, json={"events": [
            {"eventId": r["httpRequest"]["requestId"], "message": json.dumps(r)} for r in rows
        ]})

    return respond


def router(logs, metrics):
    def route(request: httpx.Request) -> httpx.Response:
        return logs(request) if request.url.host.startswith("logs.") else metrics(request)

    return route


@pytest.fixture
def linked(aws, monkeypatch):
    monkeypatch.setattr(settings, "monitoring_aws_log_groups", WAF_ARN)


def yesterday() -> date:
    return datetime.now(UTC).date() - timedelta(days=1)


def waf_records(day: date):
    from app.monitoring import demo

    return demo.day_records(day, attack=False)


def setup_monitor(client, *, alb_arn: str | None = LB_ARN) -> dict:
    body = {
        "name": "pd_prod", "target_binding": "https://target.test", "waf_log_group_arn": WAF_ARN,
    }
    if alb_arn:
        body["alb_arn"] = alb_arn
    response = client.post("/monitoring/setup", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def latest_run(client, monitor) -> dict:
    return client.get(f"/monitoring/{monitor['id']}/runs").json()[0]


def test_collection_adds_load_balancer_metrics_to_the_waf_day(client, linked, monkeypatch):
    day = yesterday()
    serve(monkeypatch, router(cloudwatch_logs(waf_records(day)), FakeMetrics(day, SERIES)))
    monitor = setup_monitor(client)
    assert client.post(f"/monitoring/{monitor['id']}/run").status_code == 202
    run = latest_run(client, monitor)
    assert run["status"] == "complete", run
    assert run["metrics"]["origin"]["hours"][14]["target_4xx"] == 280
    assert run["metrics"]["event_count"] > 0  # the WAF day itself is intact
    assert len(run["source_revisions"]) == 2  # the metrics read counts toward the day


def test_denied_metrics_never_cost_the_waf_day(client, linked, monkeypatch):
    day = yesterday()
    serve(monkeypatch, router(
        cloudwatch_logs(waf_records(day)), FakeMetrics(day, SERIES, error="AccessDenied")
    ))
    monitor = setup_monitor(client)
    client.post(f"/monitoring/{monitor['id']}/run")
    run = latest_run(client, monitor)
    assert (run["status"], run["error_code"]) == ("complete", None)
    assert run["metrics"]["origin"] == {"error": "access_denied"}
    assert run["metrics"]["event_count"] > 0


def test_a_bug_in_the_metrics_read_never_costs_the_waf_day(client, linked, monkeypatch):
    day = yesterday()
    serve(monkeypatch, router(cloudwatch_logs(waf_records(day)), FakeMetrics(day, SERIES)))

    def broken(*args, **kwargs):
        raise RuntimeError("bug")

    monkeypatch.setattr(remote, "alb_metrics", broken)
    monitor = setup_monitor(client)
    client.post(f"/monitoring/{monitor['id']}/run")
    run = latest_run(client, monitor)
    assert run["status"] == "complete", run
    assert run["metrics"]["origin"] == {"error": "source_unavailable"}


def test_linking_a_load_balancer_and_recollecting_a_day_adds_its_metrics(
    client, linked, monkeypatch
):
    """A day is re-persisted only when its revisions change, so the metrics must count."""
    day = yesterday()
    serve(monkeypatch, router(cloudwatch_logs(waf_records(day)), FakeMetrics(day, SERIES)))
    monitor = setup_monitor(client, alb_arn=None)
    client.post(f"/monitoring/{monitor['id']}/run")
    assert "origin" not in latest_run(client, monitor)["metrics"]

    assert client.put(
        f"/monitoring/{monitor['id']}/setup", json={"alb_arn": LB_ARN}
    ).status_code == 200
    client.post(f"/monitoring/{monitor['id']}/run")
    assert latest_run(client, monitor)["metrics"]["origin"]["hours"][12]["requests"] == 1000


def test_the_metrics_read_is_skipped_when_the_task_has_no_time_left(client, linked, monkeypatch):
    """A task killed mid-read would lose the WAF day it already read."""
    from app.monitoring import collection

    day = yesterday()
    fake = FakeMetrics(day, SERIES)
    serve(monkeypatch, router(cloudwatch_logs(waf_records(day)), fake))
    monkeypatch.setattr(collection, "MIN_ORIGIN_SECONDS", 10**9)
    monitor = setup_monitor(client)
    client.post(f"/monitoring/{monitor['id']}/run")
    run = latest_run(client, monitor)
    assert run["status"] == "complete"
    assert run["metrics"]["origin"] == {"error": "no_time_left"}
    assert fake.calls == []


def test_a_cancel_during_the_metrics_read_still_cancels_the_day(client, linked, monkeypatch):
    """The metrics read swallows its own failures; a cancel must not be one of them."""
    from sqlalchemy import update

    from app.core.db import SessionLocal
    from app.models.monitoring import MonitoringRun

    day = yesterday()
    metrics = FakeMetrics(day, SERIES)

    def cancel_then_serve(request: httpx.Request) -> httpx.Response:
        with SessionLocal() as db:  # what POST /monitoring/{id}/cancel writes
            db.execute(update(MonitoringRun).values(
                status="cancelled", claim=None, state="degraded", error_code="cancelled",
            ))
            db.commit()
        return metrics(request)

    serve(monkeypatch, router(cloudwatch_logs(waf_records(day)), cancel_then_serve))
    monitor = setup_monitor(client)
    client.post(f"/monitoring/{monitor['id']}/run")
    run = latest_run(client, monitor)
    assert (run["status"], run["error_code"]) == ("cancelled", "cancelled")
    assert "origin" not in run["metrics"]
