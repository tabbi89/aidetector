"""Deterministic synthetic WAF days for the bundled vulnbank target (dev only).

Records are shaped like real AWS WAF logs — nested ``httpRequest``, millisecond
timestamps, Bot Control labels — so a demo exercises the same normalization,
baseline and bot analysis a production feed does. Addresses come from the
TEST-NET documentation ranges and request IDs are synthetic.

Seven ordinary days build the baseline. The attack day adds three things a
monitor should surface:

- a known client that starts walking ``GET /accounts/{id}`` sequentially;
- a surge of unverified AI crawlers;
- traffic claiming to be googlebot without Bot Control's verification;
- one TLS client (JA4) probing paths from three addresses and sending payloads
  the SQL injection and LFI managed rules match, some of them carried in the
  path itself so the retained attack path has something to show.

Each day also has the load balancer's hourly CloudWatch metrics, telling the same
story from the app's side: at 14:00 the identifier walk draws a wave of 404s and
slower responses, and at 03:00 the scanner's wordlist is stopped at the load
balancer while the payloads that got through make the app fail with 5XX. Ordinary
days carry one quirk on purpose -- a nightly job at 03:00 that is always refused a
little more -- so the demo shows that an hour is compared with itself.
"""

from __future__ import annotations

import random
from datetime import UTC, date, datetime, timedelta

TARGET = "http://target:9000"
MONITOR_NAME = "vulnbank demo"

LABEL = "awswaf:managed:aws:bot-control:"
BOTS: dict[str, tuple[str, str, str]] = {
    # name: (organization, category, usual verification)
    "googlebot": ("google", "search_engine", "verified"),
    "betteruptime": ("betterstack", "monitoring", "verified"),
    "gptbot": ("openai", "ai", "unverified"),
    "claudebot": ("anthropic", "ai", "unverified"),
    "perplexitybot": ("perplexity", "ai", "unverified"),
}
HUMAN_ROUTES = [
    ("GET", "/users/me"),
    ("GET", "/accounts/{id}"),
    ("GET", "/notes/{id}"),
    ("POST", "/login"),
    ("GET", "/search"),
]
HUMANS = ["203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13"]
ENUMERATOR = "203.0.113.66"
SPOOFER = "198.51.100.99"
SCANNERS = ["198.51.100.20", "198.51.100.21", "198.51.100.22"]
# Made-up but well-formed JA4 fingerprints.
BROWSER_JA4 = "t13d1516h2_8daaf6152771_02713d6af862"
BOT_JA4 = "t13d1011h2_61a7ad8aa9b6_3a8073fd4b1c"
SCRIPT_JA4 = "t13d311100_e8f1e7e78f70_d339722ba4af"
SCANNER_JA4 = "t12d190800_0a1b2c3d4e5f_6a7b8c9d0e1f"
SCANNER_WORDS = ["admin", "backup", "config", "debug", "internal", "old", "staging", "test"]
# Payloads carried in the path itself, so the demo shows the retained attack path.
# Percent-encoding is left as sent: it is half of what makes these traversal attempts.
SCANNER_PAYLOADS = [
    "/..%2f..%2f..%2fetc%2fpasswd",
    "/static/%2e%2e/%2e%2e/config.yml",
    "/users/1%27%20OR%20%271%27%3D%271",
    "/.git/config",
    "/actuator/env",
]


def rapid_records(end: datetime, *, attack: bool, seed: int = 7) -> list[dict]:
    """A recent rolling hour for the dev monitor, including an exact five-minute pulse."""
    rng = random.Random(f"{seed}:rapid:{end.isoformat()}")
    records: list[dict] = []

    def add(
        seconds_ago: int,
        method: str,
        path: str,
        client: str,
        *,
        action: str = "ALLOW",
        ja4: str = BROWSER_JA4,
        labels: tuple[str, ...] = (),
        bot: str | None = None,
    ) -> None:
        when = end - timedelta(seconds=seconds_ago)
        raw_labels = [{"name": label} for label in labels]
        if bot:
            organization, category, verification = BOTS[bot]
            raw_labels += [
                {"name": f"{LABEL}bot:name:{bot}"},
                {"name": f"{LABEL}bot:organization:{organization}"},
                {"name": f"{LABEL}bot:category:{category}"},
                {"name": f"{LABEL}bot:{verification}"},
            ]
        records.append({
            "timestamp": int(when.timestamp() * 1000),
            "action": action,
            "ja4Fingerprint": ja4,
            "httpRequest": {
                "clientIp": client,
                "uri": path,
                "args": "",
                "httpMethod": method,
                "requestId": f"rapid-{int(end.timestamp())}-{len(records)}",
            },
            "labels": raw_labels,
        })

    # Normal application traffic fills the hour and the final five-minute pulse.
    routes = [("GET", "/users/me"), ("GET", "/accounts/1"), ("GET", "/notes/1"),
              ("POST", "/login"), ("GET", "/search")]
    for index in range(90):
        method, path = routes[index % len(routes)]
        add(3300 - index * 34, method, path, HUMANS[index % len(HUMANS)])
    for index in range(36 + rng.randrange(8)):
        method, path = routes[index % len(routes)]
        add(280 - index * 6, method, path, HUMANS[index % len(HUMANS)])
    for index in range(8):
        add(260 - index * 22, "GET", "/search", "192.0.2.40", bot="gptbot", ja4=BOT_JA4)

    if attack:
        # One address walks distinct, off-contract paths across the hour and then bursts.
        for index in range(18):
            seconds_ago = (3200 - index * 170) if index < 14 else (250 - (index - 14) * 55)
            add(seconds_ago, "GET", f"/admin-probe-{index}", SCANNERS[0],
                action="BLOCK", ja4=SCANNER_JA4)
        # Managed-rule matches in the final five minutes, including two count-mode escapes.
        for index in range(6):
            label = (
                "awswaf:managed:aws:sql-database:SQLi_QueryArguments"
                if index < 4 else "awswaf:managed:aws:core-rule-set:GenericLFI_URIPATH"
            )
            add(210 - index * 28, "GET", "/search", SCANNERS[0],
                action="ALLOW" if index < 2 else "BLOCK", ja4=SCANNER_JA4,
                labels=(label,))
    return records


def day_records(day: date, *, attack: bool, seed: int = 7) -> list[dict]:
    rng = random.Random(f"{seed}:{day.isoformat()}")
    start = datetime.combine(day, datetime.min.time(), tzinfo=UTC)
    records: list[dict] = []

    def add(
        hour: int,
        method: str,
        path: str,
        client: str,
        *,
        bot: str | None = None,
        verification: str | None = None,
        action: str = "ALLOW",
        ja4: str | None = None,
        extra_labels: tuple[str, ...] = (),
    ) -> None:
        when = start + timedelta(hours=hour, seconds=rng.randrange(3600))
        labels = [{"name": name} for name in extra_labels]
        if bot:
            organization, category, usual = BOTS[bot]
            labels += [
                {"name": f"{LABEL}bot:name:{bot}"},
                {"name": f"{LABEL}bot:organization:{organization}"},
                {"name": f"{LABEL}bot:category:{category}"},
                {"name": f"{LABEL}bot:{verification or usual}"},
            ]
        records.append(
            {
                "timestamp": int(when.timestamp() * 1000),
                "action": action,
                "ja4Fingerprint": ja4 or (BOT_JA4 if bot else BROWSER_JA4),
                "httpRequest": {
                    "clientIp": client,
                    "uri": path.replace("{id}", str(rng.randint(1, 3))),
                    "args": "",
                    "httpMethod": method,
                    "requestId": f"demo-{day.isoformat()}-{len(records)}",
                },
                "labels": labels,
            }
        )

    for hour in range(8, 21):
        for client in HUMANS:
            method, path = rng.choice(HUMAN_ROUTES)
            add(hour, method, path, client)
    for hour in range(24):
        add(hour, "GET", "/health", "192.0.2.20", bot="betteruptime")
    for _ in range(10):
        add(rng.randrange(24), "GET", "/search", "192.0.2.30", bot="googlebot")
    for bot, count in (("gptbot", 6), ("claudebot", 4), ("perplexitybot", 3)):
        for _ in range(count):
            add(rng.randrange(24), "GET", "/search", "192.0.2.40", bot=bot)
    # The client that later enumerates is an ordinary account holder first.
    for identifier in (1, 2):
        add(14, "GET", f"/accounts/{identifier}", ENUMERATOR, ja4=SCRIPT_JA4)

    if attack:
        for identifier in range(3, 303):
            when = start + timedelta(hours=14, seconds=identifier)
            records.append(
                {
                    "timestamp": int(when.timestamp() * 1000),
                    "action": "ALLOW",
                    "ja4Fingerprint": SCRIPT_JA4,
                    "httpRequest": {
                        "clientIp": ENUMERATOR,
                        "uri": f"/accounts/{identifier}",
                        "args": "",
                        "httpMethod": "GET",
                        "requestId": f"demo-{day.isoformat()}-enum-{identifier}",
                    },
                    "labels": [],
                }
            )
        for bot, count in (("gptbot", 180), ("claudebot", 140), ("perplexitybot", 60)):
            for _ in range(count):
                path = rng.choice(["/search", "/notes/{id}"])
                add(rng.randrange(24), "GET", path, "192.0.2.41", bot=bot)
        for _ in range(40):
            hour = rng.randrange(24)
            add(hour, "GET", "/search", SPOOFER, bot="googlebot", verification="unverified")
        # One tool behind three addresses: a wordlist of paths, then injection attempts.
        for index in range(160):
            word = SCANNER_WORDS[index % len(SCANNER_WORDS)]
            client = SCANNERS[index % len(SCANNERS)]
            add(3, "GET", f"/{word}-{index}", client, ja4=SCANNER_JA4, action="BLOCK")
        for index in range(6):
            add(
                3,
                "GET",
                "/search",
                SCANNERS[index % len(SCANNERS)],
                ja4=SCANNER_JA4,
                # Two slipped past a rule left in count mode.
                action="ALLOW" if index < 2 else "BLOCK",
                extra_labels=("awswaf:managed:aws:sql-database:SQLi_QueryArguments",),
            )
        for index, payload in enumerate(SCANNER_PAYLOADS):
            add(
                3,
                "GET",
                payload,
                SCANNERS[index % len(SCANNERS)],
                ja4=SCANNER_JA4,
                action="BLOCK",
                extra_labels=(
                    "awswaf:managed:aws:core-rule-set:GenericLFI_URIPATH",
                ),
            )
    return records


def history(today: date, *, days: int = 8) -> list[tuple[date, list[dict]]]:
    """The last ``days`` completed UTC days, oldest first; the newest is the attack day."""
    days_back = [today - timedelta(days=offset) for offset in range(days, 0, -1)]
    return [(day, day_records(day, attack=day == today - timedelta(days=1))) for day in days_back]


#: The demo's Application Load Balancer, as the ``LoadBalancer`` metric dimension.
LOAD_BALANCER = "app/vulnbank-demo/0123456789abcdef"


def day_load_balancer(day: date, *, attack: bool, seed: int = 7) -> dict:
    """One day of hourly load balancer metrics, in the shape the metrics reader stores."""
    from app.monitoring.remote import ALB_LATENCY, ALB_METRICS, alb_summary

    rng = random.Random(f"{seed}:lb:{day.isoformat()}")
    hours = []
    for hour in range(24):
        reached = (420 + rng.randrange(40)) if 8 <= hour <= 20 else (150 + rng.randrange(15))
        # The nightly job at 03:00 is refused a little more every night: normal for 03:00.
        client_errors = round(reached * (0.05 if hour == 3 else 0.02))
        server_errors = rng.randrange(2)
        redirects = round(reached * 0.05)
        stopped = 2 + rng.randrange(5)
        p99 = 0.38 + rng.randrange(8) / 100
        if attack and hour == 14:
            # The walk over /accounts/{id}: most guessed identifiers do not exist.
            reached += 300
            client_errors += 260
            p99 = 1.2
        if attack and hour == 3:
            # The scanner: its wordlist is stopped at the load balancer (ELB 403), and
            # the payloads that got through make a handler fail instead of refusing them.
            stopped += 160
            reached += 30
            server_errors += 24
            client_errors += 6
        row: dict[str, float] = {key: 0 for key in ALB_METRICS if key not in ALB_LATENCY}
        row.update(
            hour=hour,
            requests=reached + stopped,
            target_2xx=reached - client_errors - server_errors - redirects,
            target_3xx=redirects,
            target_4xx=client_errors,
            target_5xx=server_errors,
            elb_4xx=stopped,
            response_avg=round(p99 / 5, 4),
            response_p99=round(p99, 4),
        )
        hours.append(row)
    return {
        "version": 1,
        "load_balancer": LOAD_BALANCER,
        "period_seconds": 3600,
        "hours": hours,
        "total": alb_summary(hours),
    }
