"""Main-route traffic series and their baseline anomaly states."""

from datetime import date, timedelta

from app.monitoring.routes import summarize_routes

DAY = date(2026, 9, 14)


def day(offset, counts, *, total=1000, sample=False):
    metrics = {
        "event_count": total,
        "routes": {
            route: {"requests": n, "blocked_requests": 0, "not_found_requests": 0}
            for route, n in counts.items()
        },
    }
    if sample:
        metrics["sample"] = {"per_hour": 834}
    return DAY - timedelta(days=offset), metrics


def test_top_routes_are_ranked_and_warm_up_without_a_baseline():
    view = summarize_routes(
        [day(1, {"/a": 600, "/b": 300, "/c": 100}), day(0, {"/a": 500, "/b": 400})],
        limit=2,
        minimum_days=7,
    )
    assert [route["route"] for route in view["routes"]] == ["/a", "/b"]
    first = view["routes"][0]
    assert (first["state"], first["score"], first["baseline_share"]) == ("warming_up", None, 0.6)
    assert [point["share"] for point in first["series"]] == [0.6, 0.5]


def test_a_share_shift_is_an_anomaly_and_ordinary_noise_is_not():
    history = [day(o, {"/login": 50 + o % 3, "/ajax.php": 800}) for o in range(8, 0, -1)]
    quiet = summarize_routes(history + [day(0, {"/login": 52, "/ajax.php": 790})])
    assert {r["route"]: r["state"] for r in quiet["routes"]} == {
        "/ajax.php": "normal",
        "/login": "normal",
    }
    spike = summarize_routes(history + [day(0, {"/login": 400, "/ajax.php": 500})])
    states = {r["route"]: (r["state"], r["change"]) for r in spike["routes"]}
    assert states["/login"][0] == "anomaly" and states["/login"][1] > 5
    assert states["/ajax.php"][0] == "anomaly" and states["/ajax.php"][1] < -0.3


def test_sampled_days_compare_shares_not_raw_counts():
    history = [day(o, {"/a": 100}) for o in range(8, 0, -1)]
    view = summarize_routes(history + [day(0, {"/a": 2000}, total=20000, sample=True)])
    route = view["routes"][0]
    assert view["sampled"]
    assert (route["state"], route["latest_share"], route["latest_requests"]) == (
        "normal",
        0.1,
        2000,
    )


def test_days_without_events_are_left_out_of_series_and_baseline():
    view = summarize_routes([day(1, {}, total=0), day(0, {"/a": 10}, total=100)], minimum_days=1)
    assert view["days"] == 1
    assert view["routes"][0]["state"] == "warming_up"
