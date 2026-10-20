"""AWS WAF collection through CloudWatch Logs: credential chain, allowlist and paging."""

import hashlib
import json
import threading
from datetime import UTC, date, datetime, timedelta

import httpx
import pytest

from app.core.config import settings
from app.monitoring import demo, remote
from app.monitoring.accumulate import day_metrics
from app.monitoring.contracts import SourceConfig, SourceInput, SourceUnavailable
from app.monitoring.waf import normalize_waf_event

DAY = date(2026, 9, 14)
CONFIG = SourceConfig(
    region="us-west-2", account_id="257498453293", log_group="aws-waf-logs-pd_prod"
)


class ChainCredentials:
    def get_frozen_credentials(self):
        return type("Frozen", (), {"access_key": "AKIDCHAIN", "secret_key": "s", "token": None})()


class FakeCloudWatch:
    """FilterLogEvents over a record list: time-window filtering and paging."""

    def __init__(self, records, *, page_size=40, error=None, throttle_once=False,
                 timeouts=0, disconnects=0, repeat_token=False):
        self.records, self.page_size, self.error = records, page_size, error
        self.throttle_once, self.timeouts, self.repeat_token = throttle_once, timeouts, repeat_token
        self.disconnects = disconnects
        self.calls: list[httpx.Request] = []
        self.lock = threading.Lock()

    def __call__(self, request):
        body = json.loads(request.content)
        with self.lock:
            self.calls.append(request)
            if self.timeouts:
                self.timeouts -= 1
                raise httpx.ReadTimeout("slow page", request=request)
            if self.disconnects:
                self.disconnects -= 1
                raise httpx.RemoteProtocolError("server disconnected", request=request)
            if self.error:
                return httpx.Response(400, json={"__type": self.error})
            if self.throttle_once:
                self.throttle_once = False
                return httpx.Response(
                    400, json={"__type": "com.amazon.coral#ThrottlingException"}
                )
        rows = [r for r in self.records if body["startTime"] <= r["timestamp"] <= body["endTime"]]
        token = body.get("nextToken")
        offset = self.page_size if token == "repeat" else int(token or 0)
        chunk = rows[offset: offset + self.page_size]
        out: dict = {
            "events": [
                {"eventId": r["httpRequest"]["requestId"], "message": json.dumps(r)} for r in chunk
            ]
        }
        if offset + self.page_size < len(rows):
            out["nextToken"] = "repeat" if self.repeat_token else str(offset + self.page_size)
        return httpx.Response(200, json=out)


@pytest.fixture
def aws(monkeypatch):
    monkeypatch.setattr(
        settings,
        "monitoring_aws_log_groups",
        "arn:aws:logs:us-west-2:257498453293:log-group:aws-waf-logs-pd_prod:*",
    )
    monkeypatch.setattr(remote, "ambient_credentials", lambda: ChainCredentials())
    monkeypatch.setattr(remote, "sleep", lambda seconds: None)


def serve(monkeypatch, fake):
    monkeypatch.setattr(
        remote, "client_factory", lambda: httpx.Client(transport=httpx.MockTransport(fake))
    )
    return fake


def collect(day=DAY, progress=None):
    return remote.cloudwatch_events(
        CONFIG, {}, day, lambda: None, salt=b"test", routes=[], progress=progress
    )


def test_hourly_windows_are_signed_paged_and_folded(aws, monkeypatch):
    records = demo.day_records(DAY, attack=True)
    fake = serve(monkeypatch, FakeCloudWatch(records))
    metrics, count, digest = collect()
    assert len(fake.calls) > 24  # every hour, plus follow-up pages
    assert all("AKIDCHAIN" in c.headers["authorization"] for c in fake.calls)
    assert fake.calls[0].headers["x-amz-target"] == "Logs_20140328.FilterLogEvents"
    assert any("nextToken" in json.loads(c.content) for c in fake.calls)
    assert count == metrics["event_count"] == len(records)
    assert metrics["bots"]["unverified_ai"] > 300
    assert "203.0.113.66" not in json.dumps(metrics)
    # Folding a day page by page matches aggregating the whole day at once
    # (this day is below the hourly sample size, so the sample keeps everything).
    assert metrics.pop("sample")["kept"] == len(records)
    whole = day_metrics(normalize_waf_event(r, salt=b"test") for r in records)
    assert metrics == whole


def test_paging_and_thread_timing_move_neither_aggregates_nor_digest(aws, monkeypatch):
    records = demo.day_records(DAY, attack=True)
    serve(monkeypatch, FakeCloudWatch(records))
    first = collect()
    serve(monkeypatch, FakeCloudWatch(records, page_size=7))
    assert collect() == first


def test_duplicates_across_pages_count_once(aws, monkeypatch):
    records = demo.day_records(DAY, attack=False)
    serve(monkeypatch, FakeCloudWatch(records + records[:5]))
    assert collect()[1] == len(records)


def test_throttling_timeouts_and_dropped_connections_are_retried(aws, monkeypatch):
    records = demo.day_records(DAY, attack=False)
    for fake in (
        FakeCloudWatch(records, throttle_once=True),
        FakeCloudWatch(records, timeouts=2),
        FakeCloudWatch(records, disconnects=2),
    ):
        serve(monkeypatch, fake)
        assert collect()[1] == len(records)


def test_persistent_transport_and_aws_errors_have_fixed_codes(aws, monkeypatch):
    for fake, code in [
        (FakeCloudWatch([], timeouts=10_000), "source_timeout"),
        (FakeCloudWatch([], disconnects=10_000), "source_connection"),
        (FakeCloudWatch([], error="AccessDeniedException"), "access_denied"),
        (FakeCloudWatch([], error="ResourceNotFoundException"), "log_group_not_found"),
        (FakeCloudWatch([], error="SomethingElse"), "source_unavailable"),
    ]:
        serve(monkeypatch, fake)
        with pytest.raises(SourceUnavailable) as exc:
            collect()
        assert exc.value.code == code


def test_missing_chain_credentials_fail_before_any_request(aws, monkeypatch):
    monkeypatch.setattr(remote, "ambient_credentials", lambda: None)
    fake = serve(monkeypatch, FakeCloudWatch([]))
    with pytest.raises(SourceUnavailable) as exc:
        collect()
    assert exc.value.code == "credential_unavailable" and fake.calls == []


@pytest.mark.parametrize(
    "allowlist, allowed",
    [
        ("", False),
        ("arn:aws:logs:us-west-2:111111111111:log-group:aws-waf-logs-pd_prod", False),
        ("us-west-2:aws-waf-logs-pd_prod", True),
        ("not-an-arn, arn:aws:logs:us-west-2:257498453293:log-group:aws-waf-logs-pd_prod", True),
    ],
)
def test_log_group_allowlist_is_authoritative(aws, monkeypatch, allowlist, allowed):
    monkeypatch.setattr(settings, "monitoring_aws_log_groups", allowlist)
    serve(monkeypatch, FakeCloudWatch([]))
    if allowed:
        assert collect()[1] == 0
    else:
        with pytest.raises(SourceUnavailable) as exc:
            collect()
        assert exc.value.code == "source_not_allowed"


def test_event_cap_repeated_token_and_other_days(aws, monkeypatch):
    records = demo.day_records(DAY, attack=False)
    monkeypatch.setattr(settings, "monitoring_aws_max_events", 5)
    serve(monkeypatch, FakeCloudWatch(records))
    with pytest.raises(SourceUnavailable, match="row_limit"):
        collect()
    monkeypatch.setattr(settings, "monitoring_aws_max_events", 100_000)
    serve(monkeypatch, FakeCloudWatch(records, page_size=2, repeat_token=True))
    with pytest.raises(SourceUnavailable, match="pagination_incomplete"):
        collect()
    serve(monkeypatch, FakeCloudWatch(records))
    assert collect(DAY + timedelta(days=1))[1] == 0


def test_progress_reports_counts_only(aws, monkeypatch):
    records = demo.day_records(DAY, attack=False)
    fake = serve(monkeypatch, FakeCloudWatch(records))
    seen: list[dict] = []
    collect(progress=seen.append)
    assert max(s["pages"] for s in seen) == len(fake.calls)
    assert max(s["events"] for s in seen) == len(records)
    assert all(set(s) == {"pages", "events", "seconds"} for s in seen)


def test_aws_source_keys_are_optional_but_never_half_set():
    base = {
        "name": "waf",
        "target_binding": "https://target.test",
        "connector": "aws_cloudwatch",
        "config": CONFIG.model_dump(exclude_none=True),
    }
    assert SourceInput.model_validate(base).credentials is None
    with pytest.raises(ValueError):
        SourceInput.model_validate({**base, "credentials": {"access_key_id": "AKID"}})


def test_scheduled_collection_persists_bot_analysis(client, aws, monkeypatch):
    source = client.post(
        "/monitoring/sources",
        json={
            "name": "waf",
            "target_binding": "https://target.test",
            "connector": "aws_cloudwatch",
            "config": CONFIG.model_dump(exclude_none=True),
        },
    )
    assert source.status_code == 201, source.text
    assert source.json()["has_credentials"] is False
    monitor = client.post(
        "/monitoring",
        json={
            "name": "m",
            "target_binding": "https://target.test",
            "source_ids": [source.json()["id"]],
        },
    ).json()
    yesterday = datetime.now(UTC).date() - timedelta(days=1)
    serve(monkeypatch, FakeCloudWatch(demo.day_records(yesterday, attack=True)))
    assert client.post(f"/monitoring/{monitor['id']}/run").status_code == 202
    run = client.get(f"/monitoring/{monitor['id']}/runs").json()[0]
    assert run["status"] == "complete", run
    assert run["metrics"]["bots"]["unverified_ai"] > 300
    assert "progress" not in run["metrics"]  # the finished day replaces progress
    view = client.get(f"/monitoring/{monitor['id']}/bots").json()
    assert view["days"] == 1 and view["crawlers"][0]["name"] == "gptbot"


def test_recollecting_an_identical_day_keeps_its_metrics(client, aws, monkeypatch):
    """Progress overwrites a run's metrics while it reads; the finished day must replace
    them even when it folds to exactly what the run already held in memory."""
    source = client.post(
        "/monitoring/sources",
        json={
            "name": "waf",
            "target_binding": "https://target.test",
            "connector": "aws_cloudwatch",
            "config": CONFIG.model_dump(exclude_none=True),
        },
    ).json()
    monitor = client.post(
        "/monitoring",
        json={"name": "m", "target_binding": "https://target.test", "source_ids": [source["id"]]},
    ).json()
    yesterday = datetime.now(UTC).date() - timedelta(days=1)
    serve(monkeypatch, FakeCloudWatch(demo.day_records(yesterday, attack=True)))
    for _ in range(2):
        assert client.post(f"/monitoring/{monitor['id']}/run").status_code == 202
        run = client.get(f"/monitoring/{monitor['id']}/runs").json()[0]
        assert run["status"] == "complete", run
        assert "progress" not in run["metrics"]
        assert run["metrics"]["event_count"] > 0
        assert run["metrics"]["clients"]["clients"]


def test_retried_failures_keep_one_open_alert_and_a_clean_retry(client, aws, monkeypatch):
    source = client.post(
        "/monitoring/sources",
        json={
            "name": "waf",
            "target_binding": "https://target.test",
            "connector": "aws_cloudwatch",
            "config": CONFIG.model_dump(exclude_none=True),
        },
    ).json()
    monitor = client.post(
        "/monitoring",
        json={"name": "m", "target_binding": "https://target.test", "source_ids": [source["id"]]},
    ).json()
    runs = f"/monitoring/{monitor['id']}/runs"
    for _ in range(3):
        serve(monkeypatch, FakeCloudWatch([], error="AccessDeniedException"))
        assert client.post(f"/monitoring/{monitor['id']}/run").status_code == 202
        assert client.get(runs).json()[0]["error_code"] == "access_denied"
    alerts = client.get(f"/monitoring/{monitor['id']}/alerts").json()
    assert [a["state"] for a in alerts] == ["degraded"]
    # The source recovers: the retried day completes without the old error.
    yesterday = datetime.now(UTC).date() - timedelta(days=1)
    serve(monkeypatch, FakeCloudWatch(demo.day_records(yesterday, attack=False)))
    assert client.post(f"/monitoring/{monitor['id']}/run").status_code == 202
    run = client.get(runs).json()[0]
    assert (run["status"], run["error_code"]) == ("complete", None)


def dense_hour(count, *, hour=10, spacing_ms=1800):
    start = int(datetime(2026, 9, 14, hour, tzinfo=UTC).timestamp() * 1000)
    return [
        {
            "timestamp": start + i * spacing_ms,
            "action": "ALLOW",
            "httpRequest": {
                "clientIp": "192.0.2.9",
                "uri": "/search",
                "args": "",
                "httpMethod": "GET",
                "requestId": f"dense-{i}",
            },
            "labels": [],
        }
        for i in range(count)
    ]


def test_each_hour_keeps_only_its_newest_events(aws, monkeypatch):
    monkeypatch.setattr(settings, "monitoring_aws_sample_events", 48)  # two per hour
    records = demo.day_records(DAY, attack=True)
    serve(monkeypatch, FakeCloudWatch(records))
    metrics, count, _ = collect()

    def newest_first(record):
        digest = hashlib.sha256(json.dumps(record).encode()).digest()
        return record["timestamp"], int.from_bytes(digest, "big")

    expected = []
    for hour in range(24):
        in_hour = [
            r for r in records
            if datetime.fromtimestamp(r["timestamp"] / 1000, UTC).hour == hour
        ]
        expected += sorted(in_hour, key=newest_first, reverse=True)[:2]
    sample = metrics.pop("sample")
    assert (sample["per_hour"], sample["kept"], count) == (2, len(expected), len(expected))
    assert metrics == day_metrics(normalize_waf_event(r, salt=b"test") for r in expected)


def test_sampling_reads_a_slice_of_a_busy_hour_not_all_of_it(aws, monkeypatch):
    records = dense_hour(2000)  # one event every 1.8 s across 10:00-11:00
    serve(monkeypatch, FakeCloudWatch(records, page_size=200))
    metrics, count, _ = collect()
    assert count == metrics["sample"]["per_hour"] == 834
    assert metrics["sample"]["read"] < len(records)


def test_full_day_mode_reads_every_event(aws, monkeypatch):
    monkeypatch.setattr(settings, "monitoring_aws_sample_events", 0)
    serve(monkeypatch, FakeCloudWatch(dense_hour(2000), page_size=200))
    metrics, count, _ = collect()
    assert count == 2000 and "sample" not in metrics


def test_cancel_during_collection_stays_cancelled(client, aws, monkeypatch):
    from sqlalchemy import update

    from app.core.db import SessionLocal
    from app.models.monitoring import MonitoringRun

    source = client.post(
        "/monitoring/sources",
        json={
            "name": "waf",
            "target_binding": "https://target.test",
            "connector": "aws_cloudwatch",
            "config": CONFIG.model_dump(exclude_none=True),
        },
    ).json()
    monitor = client.post(
        "/monitoring",
        json={"name": "m", "target_binding": "https://target.test", "source_ids": [source["id"]]},
    ).json()
    yesterday = datetime.now(UTC).date() - timedelta(days=1)
    fake = FakeCloudWatch(demo.day_records(yesterday, attack=False))
    cancelled = threading.Event()

    def cancel_on_first_call(request):
        if not cancelled.is_set():
            cancelled.set()
            with SessionLocal() as db:  # what POST /monitoring/{id}/cancel writes
                db.execute(
                    update(MonitoringRun).values(
                        status="cancelled", claim=None, state="degraded", error_code="cancelled"
                    )
                )
                db.commit()
        return fake(request)

    serve(monkeypatch, cancel_on_first_call)
    assert client.post(f"/monitoring/{monitor['id']}/run").status_code == 202
    run = client.get(f"/monitoring/{monitor['id']}/runs").json()[0]
    assert (run["status"], run["error_code"]) == ("cancelled", "cancelled")
