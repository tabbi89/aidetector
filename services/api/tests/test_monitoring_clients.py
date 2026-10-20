from datetime import UTC, datetime

from app.monitoring import clients, waf
from app.monitoring.clients import ClientAccumulator, assess_day, flags
from app.monitoring.waf import normalize_waf_event

SALT = b"test-only-tenant-salt"
TOOL = "t12d190800_0a1b2c3d4e5f_6a7b8c9d0e1f"
BROWSER = "t13d1516h2_8daaf6152771_02713d6af862"
START = int(datetime(2026, 9, 14, 12, tzinfo=UTC).timestamp() * 1000)


def record(
    uri: str,
    *,
    ja4: str | None = TOOL,
    ip: str = "198.51.100.7",
    args: str = "",
    action: str = "ALLOW",
    labels: tuple[str, ...] = (),
    rule: str = "Default_Action",
    offset: int = 0,
) -> dict:
    return {
        "timestamp": START + offset,
        "action": action,
        "terminatingRuleId": rule,
        "terminatingRuleType": "REGULAR",
        "ja4Fingerprint": ja4,
        "httpRequest": {
            "clientIp": ip,
            "uri": uri,
            "args": args,
            "httpMethod": "GET",
            "requestId": f"r-{offset}",
        },
        "labels": [{"name": name} for name in labels],
    }


def day(records: list[dict]) -> dict:
    accumulator = ClientAccumulator()
    for item in records:
        accumulator.add(normalize_waf_event(item, salt=SALT))
    return accumulator.result()


def kinds(current: dict) -> set[str]:
    return {observation["type"] for observation in assess_day(current)}


def test_normalizer_reads_ja4_payload_rules_and_query_identifiers_without_values():
    event = normalize_waf_event(
        record(
            "/ajax.php",
            args="action=getjob&jid=48213&tech_id=77&limit=100",
            labels=(
                "awswaf:managed:aws:sql-database:SQLi_QueryArguments",
                "awswaf:managed:aws:core-rule-set:SizeRestrictions_Body",
                "awswaf:managed:aws:anonymous-ip-list:HostingProviderIPList",
                "awswaf:managed:aws:bot-control:signal:automated_browser",
            ),
        ),
        salt=SALT,
    )

    assert event.ja4 == TOOL
    assert event.attack_labels == ("sql-database:SQLi_QueryArguments",)
    assert event.identifier_keys == ("jid", "tech_id")
    assert len(event.identifier_hashes) == 2 and len(event.successor_hashes) == 2
    assert "48213" not in repr(event) and "/ajax.php?" not in repr(event)
    assert event.allow_rule is False


def test_malformed_ja4_is_dropped_and_allow_rules_are_recognised():
    event = normalize_waf_event(
        record("/hook", ja4="<script>", rule="AllowTwilioWebhook"), salt=SALT
    )

    assert event.ja4 is None
    assert event.allow_rule is True


def test_one_fingerprint_asking_for_many_new_paths_is_probing():
    current = day([record(f"/x{i}", offset=i) for i in range(150)])

    row = current["clients"][0]
    assert (row["paths"], row["addresses"]) == (150, 1)
    assert kinds(current) == {"ja4_endpoint_probing"}


def test_revisiting_a_few_pages_or_ids_is_not_probing():
    repeat = [record(f"/page{i % 20}", offset=i) for i in range(400)]
    # Distinct ids on one route template to one path shape.
    browsing = [record(f"/jobs/{1000 + i * 7}", offset=1000 + i) for i in range(300)]

    assert kinds(day(repeat)) == set()
    assert kinds(day(browsing)) == set()


def test_a_browser_build_shared_by_many_users_does_not_add_up_to_one_client():
    records = [
        record(f"/u{user}/p{page}", ja4=BROWSER, ip=f"203.0.113.{user}", offset=user * 10 + page)
        for user in range(100)
        for page in range(3)
    ]

    current = day(records)
    assert current["clients"][0]["paths"] == 300
    assert kinds(current) == set()


def test_walking_consecutive_query_identifiers_across_addresses_is_enumeration():
    records = [
        record("/ajax.php", args=f"action=getjob&jid={5000 + i}", ip=f"192.0.2.{i % 3}", offset=i)
        for i in range(120)
    ]

    (observation,) = assess_day(day(records))
    assert observation["type"] == "ja4_identifier_enumeration"
    assert (observation["method"], observation["route_family"]) == ("GET", "/ajax.php")
    assert observation["current"]["identifiers"]["parameters"] == ["jid"]
    assert observation["cohort"] == f"ja4:{TOOL}"
    assert observation["confidence"] == "heuristic"


def test_scattered_identifiers_are_not_a_walk():
    records = [
        record("/ajax.php", args=f"jid={1000 + i * 37}", offset=i) for i in range(120)
    ]

    assert kinds(day(records)) == set()


def test_payload_rule_matches_are_manipulation_and_severity_reflects_reaching_the_origin():
    sqli = ("awswaf:managed:aws:sql-database:SQLi_Body",)
    blocked = day([record("/login", action="BLOCK", labels=sqli, offset=i) for i in range(3)])
    counted = day([record("/login", labels=sqli, offset=i) for i in range(3)])

    (at_edge,) = assess_day(blocked)
    (reached,) = assess_day(counted)
    assert at_edge["type"] == "ja4_request_manipulation"
    assert (at_edge["severity"], reached["severity"]) == ("low", "medium")
    assert at_edge["route_family"] == "/login"
    assert at_edge["current"]["attack_labels"] == {"sql-database:SQLi_Body": 3}


def test_only_payload_matched_requests_keep_their_path_verbatim():
    """The one carve-out from value-free normalization, and its edges."""
    lfi = ("awswaf:managed:aws:core-rule-set:GenericLFI_URIPATH",)
    payload = "/..%2f..%2fetc%2fpasswd"

    attack = normalize_waf_event(record(payload, labels=lfi), salt=SALT)
    # Same path shape, no managed-rule match: the profile of an ordinary client.
    ordinary = normalize_waf_event(record("/dana-na/auth/url_default/welcome.cgi"), salt=SALT)

    # Kept exactly as sent -- decoding it would erase what makes it a traversal.
    assert attack.attack_path == payload
    # ...which is the whole point: the templated route still shows nothing useful.
    assert attack.route_family == "/{value}/{value}/{value}/{more}"
    assert ordinary.attack_path is None

    # The query string is where a real client's values live, so it never comes along.
    with_query = normalize_waf_event(
        record(payload + "?token=abc123&email=a@b.test", labels=lfi), salt=SALT
    )
    assert with_query.attack_path == payload


def test_a_long_attack_path_is_truncated_rather_than_dropped():
    lfi = ("awswaf:managed:aws:core-rule-set:GenericLFI_URIPATH",)
    long_path = "/" + "../" * 400
    event = normalize_waf_event(record(long_path, labels=lfi), salt=SALT)
    assert event.attack_path is not None
    assert event.attack_path.endswith("...")
    assert len(event.attack_path) == waf.MAX_ATTACK_PATH + 3


def test_manipulation_observation_carries_the_paths_that_matched():
    lfi = ("awswaf:managed:aws:core-rule-set:GenericLFI_URIPATH",)
    paths = ["/.git/config", "/actuator/env", "/..%2f..%2fetc%2fpasswd"]
    records = [record(path, labels=lfi, offset=i) for i, path in enumerate(paths)]
    # The same payload twice, so the sample counts rather than repeats it.
    records.append(record(paths[0], labels=lfi, offset=9))

    (observation,) = assess_day(day(records))
    assert observation["type"] == "ja4_request_manipulation"
    sample = observation["current"]["attack_paths"]
    assert {row["path"] for row in sample} == set(paths)
    assert {row["path"]: row["requests"] for row in sample}[paths[0]] == 2
    assert observation["current"]["attack_paths_total"] == len(paths)


def test_paths_of_requests_that_matched_nothing_are_never_collected():
    """Breadth leads read hashes only; a probing client's wordlist is not stored."""
    current = day([record(f"/wp-admin-{i}", offset=i) for i in range(200)])
    (row,) = current["clients"]
    assert row["attack_paths"] == []
    (observation,) = assess_day(current)
    assert observation["type"] == "ja4_endpoint_probing"
    assert "attack_paths" not in observation["current"]


def test_stored_attack_paths_are_bounded_per_fingerprint(monkeypatch):
    monkeypatch.setattr(clients, "MAX_ATTACK_PATHS", 5)
    lfi = ("awswaf:managed:aws:core-rule-set:GenericLFI_URIPATH",)
    current = day([record(f"/.%2e/{i}", labels=lfi, offset=i) for i in range(50)])
    (row,) = current["clients"]
    assert row["attack_paths_total"] == 5
    assert len(row["attack_paths"]) == clients.SHOWN_ATTACK_PATHS


def test_allowlisted_senders_and_verified_bots_do_not_count_toward_breadth():
    verified = "awswaf:managed:aws:bot-control:bot:verified"
    records = [record(f"/hook{i}", rule="AllowTwilioWebhook", offset=i) for i in range(200)]
    records += [
        record(f"/crawl{i}", ja4=BROWSER, labels=(verified,), offset=500 + i) for i in range(200)
    ]

    current = day(records)
    by_ja4 = {row["ja4"]: row for row in current["clients"]}
    assert (by_ja4[TOOL]["trusted"], by_ja4[TOOL]["paths"]) == (200, 0)
    assert (by_ja4[BROWSER]["verified_bot"], by_ja4[BROWSER]["paths"]) == (200, 0)
    assert kinds(current) == set()


def test_fingerprints_ignore_volume():
    small = assess_day(day([record(f"/x{i}", offset=i) for i in range(150)]))
    large = assess_day(day([record(f"/x{i}", offset=i) for i in range(400)]))

    assert [o["fingerprint"] for o in small] == [o["fingerprint"] for o in large]


def test_bounded_table_keeps_flagged_clients(monkeypatch):
    monkeypatch.setattr(clients, "MAX_CLIENTS", 3)
    quiet = [
        record("/home", ja4=f"t13d1516h2_8daaf6152771_{n:012x}", offset=n)
        for n in range(10)
        for _ in range(5)
    ]
    probing = [record(f"/x{i}", offset=1000 + i) for i in range(120)]

    current = day(quiet + probing)
    assert len(current["clients"]) == 3 and current["clients_truncated"] == 8
    assert any(flags(row) for row in current["clients"])


def test_requests_without_a_fingerprint_are_counted_not_dropped_silently():
    current = day([record("/x", ja4=None)])

    assert current["clients"] == [] and current["without_fingerprint"] == 1
