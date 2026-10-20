"""ZAP adapter tests — alert mapping is pure; the scan flow uses a fake transport."""
from __future__ import annotations

from app.domain.enums import Severity
from app.engine.fingerprint import fingerprint
from app.engine.zap import ZapScanner, map_alerts


def test_map_alerts_maps_risk_and_fields():
    alerts = [
        {"alert": "SQL Injection", "risk": "High", "url": "http://t/x?id=1",
         "param": "id", "cweid": "89", "description": "d", "solution": "s"},
        {"name": "X-Frame-Options Missing", "risk": "Medium (Low)", "cweid": "-1"},
        {"alert": "Info leak", "risk": "Informational"},
    ]
    findings = map_alerts(alerts)
    assert [f.severity for f in findings] == [Severity.high, Severity.medium, Severity.info]
    assert findings[0].check == "zap"
    assert findings[0].owasp_id == "CWE-89"
    assert findings[1].owasp_id is None  # cweid -1 → no id
    assert findings[0].evidence["param"] == "id"


def test_map_alerts_collapses_passive_duplicates_to_one_per_location():
    """The passive scanner reports the same alert once per payload it tried.

    A dozen "User Agent Fuzzer" records across the same URL must become one
    finding, not a dozen rows a reviewer dismisses individually.
    """
    alerts = [
        {"alert": "User Agent Fuzzer", "risk": "Informational", "url": "http://t/v1",
         "param": "Header User-Agent", "attack": f"bot-{i}", "pluginId": "10104"}
        for i in range(12)
    ]
    alerts.append(
        {"alert": "User Agent Fuzzer", "risk": "Informational", "url": "http://t/v2",
         "param": "Header User-Agent", "attack": "bot-0", "pluginId": "10104"}
    )
    findings = map_alerts(alerts)
    assert len(findings) == 2
    assert all(f.title == "ZAP: User Agent Fuzzer" for f in findings)


def test_zap_alerts_get_distinct_identity_beyond_the_title():
    """ZAP alerts carry no spec route, so name/param/url are their identity —
    two alerts of the same type on different URLs must not share a fingerprint.
    """
    first = map_alerts([
        {"alert": "User Agent Fuzzer", "risk": "Informational", "url": "http://t/v1",
         "param": "Header User-Agent", "pluginId": "10104"},
    ])[0]
    second = map_alerts([
        {"alert": "User Agent Fuzzer", "risk": "Informational", "url": "http://t/v2",
         "param": "Header User-Agent", "pluginId": "10104"},
    ])[0]
    assert fingerprint(first.check, first.owasp_id, first.title, first.evidence) != fingerprint(
        second.check, second.owasp_id, second.title, second.evidence
    )


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload
        self.status_code = 200

    def json(self):
        return self._payload


class _FakeZapHttp:
    """Scripts spider/ascan as instantly complete and returns one alert."""

    def get(self, url, **kwargs):
        if "/spider/action/scan/" in url:
            return _FakeResp({"scan": "0"})
        if "/spider/view/status/" in url:
            return _FakeResp({"status": "100"})
        if "/ascan/action/scan/" in url:
            return _FakeResp({"scan": "0"})
        if "/ascan/view/status/" in url:
            return _FakeResp({"status": "100"})
        if "/core/view/alerts/" in url:
            return _FakeResp({"alerts": [{"alert": "XSS", "risk": "High", "cweid": "79"}]})
        return _FakeResp({})


def test_zap_scanner_runs_full_flow():
    scanner = ZapScanner("http://zap:8090", api_key="k", http=_FakeZapHttp(), poll_seconds=0)
    findings = scanner.run("http://target:9000")
    assert len(findings) == 1
    assert findings[0].title == "ZAP: XSS"
    assert findings[0].severity == Severity.high


def test_zap_scanner_degrades_on_error():
    class _Boom:
        def get(self, url, **kwargs):
            raise RuntimeError("daemon down")

    scanner = ZapScanner("http://zap:8090", http=_Boom(), poll_seconds=0)
    assert scanner.run("http://target:9000") == []  # never raises


def test_zap_scanner_seeds_spec_urls():
    """The spider gets one seed per rendered operation URL so the active scan
    reaches the spec's API paths — an API base URL links to nothing."""

    class _Recorder(_FakeZapHttp):
        def __init__(self):
            self.spider_urls = []

        def get(self, url, **kwargs):
            if "/spider/action/scan/" in url:
                params = kwargs.get("params") or {}
                self.spider_urls.append(params.get("url"))
            return super().get(url, **kwargs)

    http = _Recorder()
    scanner = ZapScanner("http://zap:8090", http=http, poll_seconds=0)
    scanner.run(
        "http://target:9000",
        # duplicates and empties are ignored
        spec_urls=["http://target:9000/v1/a", "http://target:9000/v1/a", ""],
    )
    assert http.spider_urls == ["http://target:9000", "http://target:9000/v1/a"]


def test_active_scan_duplicates_collapse_despite_rotating_payloads():
    """The active scanner reports one alert per injected value, each URL differing.

    Collapsing on the raw URL would leave a dozen rows for one bug; collapsing on
    the location leaves one, and keeps the two genuinely different locations apart.
    """
    alerts = [
        {"alert": "SQL Injection", "risk": "High", "param": "id", "pluginId": "40018",
         "url": f"http://t/v1/items?id=1%27+OR+{i}%3D{i}"}
        for i in range(12)
    ]
    alerts.append(
        {"alert": "SQL Injection", "risk": "High", "param": "id", "pluginId": "40018",
         "url": "http://t/v1/orders?id=1%27+OR+1%3D1"}
    )

    findings = map_alerts(alerts)

    assert len(findings) == 2
    assert [f.evidence["location"] for f in findings] == [
        "http://t/v1/items",
        "http://t/v1/orders",
    ]


def test_zap_identity_survives_a_rerun_that_changed_only_the_payload():
    """A rotating payload must not report the same alert as fixed-and-new."""
    def alert(payload: str) -> dict:
        return {"alert": "SQL Injection", "risk": "High", "param": "id",
                "pluginId": "40018", "attack": payload, "evidence": payload,
                "url": f"http://t/v1/items?id={payload}"}

    first = map_alerts([alert("1%27+OR+1%3D1")])[0]
    second = map_alerts([alert("9%27+UNION+SELECT")])[0]

    assert fingerprint("zap", first.owasp_id, first.title, first.evidence) == fingerprint(
        "zap", second.owasp_id, second.title, second.evidence
    )


def test_zap_identity_separates_two_locations():
    """...while two genuinely different endpoints stay two findings."""
    def alert(path: str) -> dict:
        return {"alert": "SQL Injection", "risk": "High", "param": "id",
                "pluginId": "40018", "url": f"http://t{path}?id=1"}

    a, b = map_alerts([alert("/v1/items"), alert("/v1/orders")])

    assert fingerprint("zap", a.owasp_id, a.title, a.evidence) != fingerprint(
        "zap", b.owasp_id, b.title, b.evidence
    )


def test_alert_location_keeps_where_and_drops_what_was_sent():
    """The payload lives in the query string; identity must not."""
    from app.engine.zap import alert_location

    assert alert_location("http://t/v1/items?id=1%27+OR+1%3D1") == "http://t/v1/items"
    assert alert_location("https://t:8443/a/b?x=1#frag") == "https://t:8443/a/b"
    # A path with no scheme still loses its query.
    assert alert_location("/v1/items?id=1") == "/v1/items"
    # Nothing to strip.
    assert alert_location("http://t/v1/items") == "http://t/v1/items"


def test_alert_location_survives_a_url_it_cannot_parse():
    """ZAP's output is target-influenced; a bad URL must not fail the mapping."""
    from app.engine.zap import alert_location

    assert alert_location("") == ""
    assert alert_location("http://[malformed") != ""  # returns something, does not raise
    assert len(alert_location("http://t/" + "a" * 900)) <= 500


def test_an_alert_with_no_url_still_maps():
    findings = map_alerts([{"alert": "X", "risk": "Low"}])
    assert len(findings) == 1
    assert findings[0].evidence["location"] == ""
