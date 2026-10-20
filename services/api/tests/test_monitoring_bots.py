"""AWS WAF Bot Control labels and the AI/bot traffic analysis built on them."""

from dataclasses import replace
from datetime import UTC, date, datetime, timedelta

from app.monitoring import bots, demo
from app.monitoring.waf import normalize_waf_event

SALT = b"test-only-tenant-salt"
LABEL = "awswaf:managed:aws:bot-control:"
TODAY = date(2026, 9, 15)


def waf(labels, *, uri="/search", action="ALLOW", client="192.0.2.5"):
    return normalize_waf_event(
        {
            "timestamp": int(datetime(2026, 9, 14, 12, tzinfo=UTC).timestamp() * 1000),
            "action": action,
            "httpRequest": {"uri": uri, "httpMethod": "GET", "clientIp": client},
            "labels": [{"name": name} for name in labels],
        },
        salt=SALT,
    )


def day_events(day, *, attack):
    return [normalize_waf_event(r, salt=SALT) for r in demo.day_records(day, attack=attack)]


def baseline():
    return [
        bots.aggregate(day_events(TODAY - timedelta(days=offset), attack=False))
        for offset in range(2, 9)
    ]


def test_bot_control_labels_are_read_and_everything_else_ignored():
    event = waf(
        [
            f"{LABEL}bot:name:GPTBot",
            f"{LABEL}bot:organization:openai",
            f"{LABEL}bot:category:ai",
            f"{LABEL}bot:unverified",
            f"{LABEL}signal:cloud_service_provider:aws",
            f"{LABEL}bot:name:second-name-is-ignored",
            f"{LABEL}bot:category:<script>",
            "awswaf:123456789012:custom:bot:name:not-bot-control",
        ]
    )
    assert event.bot_name == "gptbot"
    assert event.bot_organization == "openai"
    assert event.bot_category == "ai"
    assert event.bot_verification == "unverified"
    assert event.bot_signals == ("cloud_service_provider:aws",)
    assert "192.0.2.5" not in repr(event)


def test_verified_outranks_unverified_and_unlabelled_traffic_is_not_a_bot():
    assert waf([f"{LABEL}bot:unverified", f"{LABEL}bot:verified"]).bot_verification == "verified"
    plain = waf([])
    assert not bots.is_bot(plain)
    assert plain.bot_signals == ()


def test_aggregate_counts_ai_share_and_crawler_outcomes():
    events = [
        waf([f"{LABEL}bot:name:gptbot", f"{LABEL}bot:category:ai", f"{LABEL}bot:unverified"]),
        waf(
            [f"{LABEL}bot:name:gptbot", f"{LABEL}bot:category:ai", f"{LABEL}bot:unverified"],
            action="BLOCK",
        ),
        waf([f"{LABEL}bot:name:googlebot", f"{LABEL}bot:category:ai", f"{LABEL}bot:verified"]),
        waf([]),
    ]
    day = bots.aggregate(events)
    assert (day["requests"], day["bot_requests"], day["ai_requests"]) == (4, 3, 3)
    assert (day["verified_ai"], day["unverified_ai"]) == (1, 2)
    gptbot = day["crawlers"][0]
    assert (gptbot["name"], gptbot["requests"], gptbot["allowed"], gptbot["blocked"]) == (
        "gptbot",
        2,
        1,
        1,
    )
    assert gptbot["routes"] == [{"route": "GET /search", "requests": 2, "allowed": 1}]


def test_crawler_table_is_bounded():
    events = [
        waf([f"{LABEL}bot:name:bot{i}", f"{LABEL}bot:category:ai"])
        for i in range(bots.MAX_CRAWLERS + 5)
    ]
    day = bots.aggregate(events)
    assert len(day["crawlers"]) == bots.MAX_CRAWLERS
    assert day["crawlers_truncated"] == 5


def test_ordinary_days_are_quiet():
    history = baseline()
    quiet = bots.aggregate(day_events(TODAY - timedelta(days=1), attack=False))
    assert bots.assess(quiet, history, 7, protected=set()) == []


def test_attack_day_raises_surge_and_spoof_leads():
    attack = bots.aggregate(day_events(TODAY - timedelta(days=1), attack=True))
    found = bots.assess(attack, baseline(), 7, protected=set())
    assert {o["type"] for o in found} == {"unverified_ai_surge", "bot_identity_spoof"}
    assert all(o["confidence"] == "heuristic" and o["remediation"] for o in found)
    spoof = next(o for o in found if o["type"] == "bot_identity_spoof")
    assert spoof["cohort"] == "bot:googlebot"


def test_single_day_impersonation_lead_needs_no_history():
    verified = [f"{LABEL}bot:name:googlebot", f"{LABEL}bot:category:search_engine"]
    today = bots.aggregate(
        [waf([*verified, f"{LABEL}bot:verified"])] * 3
        + [waf([*verified, f"{LABEL}bot:unverified"], client="198.51.100.7")] * 6
    )
    leads = bots.assess_day(today, protected=set())
    assert [(o["type"], o["cohort"], o["basis"]) for o in leads] == [
        ("bot_identity_spoof", "bot:googlebot", "single_day")
    ]
    ordinary = bots.aggregate(day_events(TODAY - timedelta(days=1), attack=False))
    assert bots.assess_day(ordinary, protected=set()) == []


def test_leads_need_a_full_baseline():
    attack = bots.aggregate(day_events(TODAY - timedelta(days=1), attack=True))
    assert bots.assess(attack, baseline()[:6], 7, protected=set()) == []


def test_fingerprints_ignore_volume():
    attack = bots.aggregate(day_events(TODAY - timedelta(days=1), attack=True))
    louder = {**attack, "unverified_ai": attack["unverified_ai"] * 3}
    first = {o["fingerprint"] for o in bots.assess(attack, baseline(), 7, protected=set())}
    second = {o["fingerprint"] for o in bots.assess(louder, baseline(), 7, protected=set())}
    assert first == second


def test_unverified_bot_allowed_on_protected_route():
    context = {
        "routes": [
            {"method": "GET", "path": "/accounts/{id}"},
            {"method": "GET", "path": "/search"},
        ],
        "advisories": [
            {"type": "declared_public_operation", "method": "GET", "path": "/search"}
        ],
    }
    protected = bots.protected_routes(context)
    assert protected == {"GET /accounts/{id}"}
    crawler = [f"{LABEL}bot:name:scraper", f"{LABEL}bot:category:scraping_framework"]
    today = bots.aggregate(
        [waf(crawler, uri=f"/accounts/{i}") for i in range(6)]
        + [waf(crawler, uri="/search") for _ in range(6)]
    )
    found = bots.assess(today, baseline(), 7, protected=protected)
    assert [(o["type"], o["route_family"]) for o in found] == [
        ("bot_on_protected_route", "/accounts/{id}")
    ]
    verified = [replace(e, bot_verification="verified") for e in day_events(TODAY, attack=False)]
    assert bots.assess(bots.aggregate(verified), baseline(), 7, protected=protected) == []


def test_summarize_merges_days_into_percentages_and_series():
    older, newer = TODAY - timedelta(days=2), TODAY - timedelta(days=1)
    days = [
        (older, bots.aggregate(day_events(older, attack=False))),
        (newer, bots.aggregate(day_events(newer, attack=True))),
    ]
    view = bots.summarize(days, limit=3)
    assert view["days"] == 2
    assert view["ai_requests"] == view["verified_ai"] + view["unverified_ai"]
    assert view["unverified_ai_pct"] == 100.0
    assert [row["day"] for row in view["series"]] == [str(older), str(newer)]
    assert len(view["crawlers"]) == 3
    assert view["crawlers"][0]["name"] == "gptbot"
