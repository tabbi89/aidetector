from datetime import UTC, date, datetime, timedelta

from app.ai.provider import (
    NullMonitoringAIProvider,
    ProviderUnavailable,
    build_monitoring_provider,
)
from app.monitoring.detectors import detect_enumeration
from app.monitoring.waf import normalize_waf_event

SALT = b"test-only-tenant-salt"


def event(day: date, identifier: int, *, action: str = "ALLOW"):
    timestamp = datetime(day.year, day.month, day.day, 12, tzinfo=UTC).isoformat()
    return normalize_waf_event(
        {
            "timestamp": timestamp,
            "httpMethod": "GET",
            "uri": f"/users/{identifier}?email=user-{identifier}@example.test",
            "statusCode": 200,
            "action": action,
            "clientIp": "198.51.100.5",
            "requestId": f"req-{identifier}",
        },
        salt=SALT,
    )


def test_waf_normalization_drops_values_and_hashes_join_keys():
    normalized = event(date(2026, 9, 15), 42)

    assert normalized.route_family == "/users/{id}"
    assert normalized.query_keys == ("email",)
    assert normalized.identifier_hashes
    assert "/users/42" not in normalized.route_family
    assert "user-42" not in repr(normalized)


def test_enumeration_requires_seven_nonempty_baseline_days():
    today = date(2026, 9, 15)
    baseline = {
        today - timedelta(days=offset): [event(today - timedelta(days=offset), 1)]
        for offset in range(1, 7)
    }
    assert (
        detect_enumeration([event(today, identifier) for identifier in range(50)], baseline)
        == []
    )

    baseline[today - timedelta(days=7)] = [event(today - timedelta(days=7), 1)]
    findings = detect_enumeration(
        [event(today, identifier) for identifier in range(50)], baseline
    )

    assert len(findings) == 1
    assert findings[0].route_family == "/users/{id}"
    assert findings[0].confidence == "heuristic"
    assert findings[0].baseline_days == 7


def test_normal_volume_does_not_trigger_enumeration():
    today = date(2026, 9, 15)
    baseline = {
        today - timedelta(days=offset): [event(today - timedelta(days=offset), 1)]
        for offset in range(1, 8)
    }

    assert (
        detect_enumeration([event(today, identifier) for identifier in range(19)], baseline)
        == []
    )


def test_monitoring_ai_defaults_to_disabled():
    provider = build_monitoring_provider()
    assert isinstance(provider, NullMonitoringAIProvider)
    try:
        provider.explain({"type": "enumeration_anomaly"})
    except ProviderUnavailable as exc:
        assert "disabled" in str(exc)
    else:  # pragma: no cover - defensive assertion for the provider contract
        raise AssertionError("the default monitoring provider must be disabled")


def test_buckets_keep_the_busiest_and_count_the_rest_instead_of_failing():
    from app.monitoring import analysis

    when = datetime(2026, 9, 15, 12, tzinfo=UTC).isoformat()

    def request(client):
        record = {"timestamp": when, "httpMethod": "GET", "uri": "/users/1", "clientIp": client}
        return normalize_waf_event(record, salt=SALT)

    events = [request(f"client-{i}") for i in range(analysis.MAX_BUCKETS)] + [request("heavy")] * 5
    result = analysis.aggregate(events)
    assert len(result["buckets"]) == analysis.MAX_BUCKETS
    assert result["buckets_truncated"] == 1
    assert result["event_count"] == len(events)
    assert max(b["requests"] for b in result["buckets"].values()) == 5


def test_single_day_leads_without_a_baseline():
    from app.monitoring import analysis

    start = datetime(2026, 9, 15, 12, tzinfo=UTC)

    def hit(client, uri, second):
        return normalize_waf_event(
            {
                "timestamp": (start + timedelta(seconds=second)).isoformat(),
                "httpMethod": "GET",
                "uri": uri,
                "clientIp": client,
                "requestId": f"{client}-{second}",
            },
            salt=SALT,
        )

    walker = [hit("walker", f"/users/{i}", i) for i in range(1, 80)]
    heavy = [hit("heavy", "/search", 100 + i) for i in range(300)]
    quiet = [hit(f"client-{i}", "/search", 500 + i) for i in range(100)]
    leads = analysis.assess_day(analysis.aggregate(walker + heavy + quiet), has_contract=False)
    kinds = {(lead["type"], lead["route_family"]) for lead in leads}
    assert kinds == {("enumeration_anomaly", "/users/{id}"), ("high_volume_client", "/search")}
    assert all(
        lead["basis"] == "single_day" and lead["confidence"] == "heuristic" for lead in leads
    )
    assert analysis.assess_day(analysis.aggregate(quiet), has_contract=False) == []


def test_paths_outside_the_api_vocabulary_keep_a_value_free_shape():
    def route(uri):
        record = {"timestamp": "2026-09-15T12:00:00Z", "httpMethod": "GET", "uri": uri}
        return normalize_waf_event(record, salt=SALT).route_family

    assert route("/dashboard") == "/dashboard"
    assert route("/app/john.smith/settings") == "/app/{value}/{value}"
    assert route("/assets/index-3f9a2c11.js") == "/assets/{value}"
    assert route("/app/login") == "/app/login"
    assert route("/a/b/c/d/e") == "/a/{value}/{value}/{more}"
    assert route("/Jane.Doe@example.com") == "/{value}"
    assert route("/orders/42") == "/orders/{id}"
