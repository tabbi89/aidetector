"""Fixed-destination, bounded read adapters. No redirects or proxy environment.

AWS reads sign with a source's stored keys when it has them and otherwise with
the deployment's standard credential chain (profile, web identity, container or
instance role). Chain credentials belong to the deployment rather than to a
tenant, so a log group is readable only when the operator lists it in
``MONITORING_AWS_LOG_GROUPS``; a tenant cannot aim them anywhere else.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import re
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, date, datetime, timedelta
from typing import Any
from urllib.parse import quote

import httpx

from app.core.config import settings
from app.monitoring.accumulate import DayAccumulator
from app.monitoring.connectors import MAX_SNAPSHOT_BYTES
from app.monitoring.contracts import (
    RouteBinding,
    SourceConfig,
    SourceUnavailable,
    parse_load_balancer_arn,
    parse_log_group_arn,
)
from app.monitoring.waf import NormalizedWafEvent, normalize_waf_event, short_key

MAX_CALLS = 10
MAX_SECONDS = 60
# A FilterLogEvents page is at most 1 MB; this bounds one decoded response.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_RETRIES = 5
# A 1 MB FilterLogEvents page over a large log group routinely takes several
# seconds, so reads get a generous timeout; connecting does not.
TIMEOUT = httpx.Timeout(10.0, read=60.0)
HOUR_MS = 3_600_000
# Sampling reads backwards from each hour's end, starting with this slice.
SAMPLE_FIRST_SLICE_MS = 60_000
#: Concurrent time slices a short-window hour is read in.
RAPID_SLICES = 12
_RETRYABLE = frozenset(
    {"ThrottlingException", "Throttling", "LimitExceededException", "LimitExceeded",
     "ServiceUnavailableException"}
)
#: Transport failures worth another attempt: a slow page or a dropped connection.
_TRANSIENT = frozenset({"source_timeout", "source_connection"})
_AWS_ERRORS = {
    "AccessDeniedException": "access_denied",
    "AccessDenied": "access_denied",
    "ResourceNotFoundException": "log_group_not_found",
    "UnrecognizedClientException": "credential_unavailable",
    "ExpiredTokenException": "credential_unavailable",
    "InvalidSignatureException": "credential_unavailable",
}
_DIGEST_MODULUS = 1 << 256
# Module-level so tests can replace backoff without waiting.
sleep = time.sleep
log = logging.getLogger(__name__)


class ReadBudget:
    def __init__(
        self,
        check: Callable[[], None],
        *,
        max_calls: int = MAX_CALLS,
        seconds: float = MAX_SECONDS,
        max_bytes: int | None = MAX_SNAPSHOT_BYTES,
    ):
        self.check = check
        self.deadline = time.monotonic() + seconds
        self.remaining = max_bytes
        self.max_calls = max_calls
        self.calls = 0
        self._lock = threading.Lock()

    def guard(self) -> None:
        if time.monotonic() >= self.deadline:
            raise SourceUnavailable("deadline_exceeded")
        self.check()

    def pause(self, seconds: float) -> None:
        if time.monotonic() + seconds >= self.deadline:
            raise SourceUnavailable("deadline_exceeded")
        sleep(seconds)
        self.guard()

    def fetch(
        self, client: httpx.Client, method: str, url: str, *, max_response: int, **kwargs
    ) -> tuple[int, Any]:
        """One bounded call; returns the status and decoded JSON (None when absent)."""
        status, body = self.fetch_bytes(client, method, url, max_response=max_response, **kwargs)
        try:
            data = json.loads(body) if body else None
        except (ValueError, RecursionError):
            if status == 200:
                raise SourceUnavailable("invalid_source_data") from None
            data = None
        return status, data

    def fetch_bytes(
        self, client: httpx.Client, method: str, url: str, *, max_response: int, **kwargs
    ) -> tuple[int, bytes]:
        """One bounded call; returns the status and the raw body, capped and guarded."""
        self.guard()
        with self._lock:
            self.calls += 1
            over = self.calls > self.max_calls
            cap = max_response if self.remaining is None else min(max_response, self.remaining)
        if over:
            raise SourceUnavailable("call_limit")
        try:
            with client.stream(method, url, **kwargs) as response:
                if response.headers.get("content-encoding", "identity") != "identity":
                    raise SourceUnavailable("unsupported_encoding")
                body = bytearray()
                for chunk in response.iter_bytes(chunk_size=16384):
                    self.guard()
                    body.extend(chunk)
                    if len(body) > cap:
                        raise SourceUnavailable("byte_limit")
                if self.remaining is not None:
                    with self._lock:
                        self.remaining -= len(body)
                status = response.status_code
            self.guard()
            return status, bytes(body)
        except SourceUnavailable:
            raise
        except httpx.TimeoutException:
            raise SourceUnavailable("source_timeout") from None
        except httpx.TransportError as exc:
            # A connection dropped or reset mid-page is transient; callers may retry.
            log.warning("monitoring source connection failed: %s", type(exc).__name__)
            raise SourceUnavailable("source_connection") from None
        except (httpx.HTTPError, RecursionError) as exc:
            log.warning("monitoring source request failed: %s", type(exc).__name__)
            raise SourceUnavailable("source_unavailable") from None

    def request(self, client: httpx.Client, method: str, url: str, **kwargs) -> dict:
        status, data = self.fetch(client, method, url, max_response=MAX_SNAPSHOT_BYTES, **kwargs)
        if status != 200:
            raise SourceUnavailable("source_unavailable")
        if not isinstance(data, dict):
            raise SourceUnavailable("invalid_source_data")
        return data


def client_factory() -> httpx.Client:
    return httpx.Client(
        timeout=TIMEOUT,
        follow_redirects=False,
        trust_env=False,
        headers={"Accept-Encoding": "identity"},
    )


def _aws_allowlist() -> set[str]:
    """``region:group`` and ``region:account:group`` keys the operator approved."""
    allowed: set[str] = set()
    for raw in settings.monitoring_aws_log_groups.split(","):
        entry = raw.strip()
        if not entry:
            continue
        if entry.startswith("arn:"):
            try:
                region, account, group = parse_log_group_arn(entry, require_waf_prefix=False)
            except ValueError:
                continue  # a malformed entry approves nothing
            allowed.add(f"{region}:{account}:{group}")
        else:
            allowed.add(entry)
    return allowed


def _alb_allowlist() -> set[str]:
    """``region:account:app/name/id`` keys for approved Application Load Balancers."""
    allowed: set[str] = set()
    for raw in settings.monitoring_aws_load_balancers.split(","):
        if not raw.strip():
            continue
        try:
            region, account, resource = parse_load_balancer_arn(raw)
        except ValueError:
            continue  # a malformed entry approves nothing
        allowed.add(f"{region}:{account}:{resource}")
    return allowed


def check_allowlist(connector: str, config: SourceConfig) -> None:
    if connector == "aws_alb":
        key = f"{config.region}:{config.account_id}:{config.load_balancer}"
        if key not in _alb_allowlist():
            raise SourceUnavailable("source_not_allowed")
        return
    if connector == "aws_cloudwatch":
        keys = {f"{config.region}:{config.log_group}"}
        if config.account_id:
            keys.add(f"{config.region}:{config.account_id}:{config.log_group}")
        if not keys & _aws_allowlist():
            raise SourceUnavailable("source_not_allowed")
    # GitHub needs no deployment allowlist: a repository is read only with the
    # token its own source carries, so that token's scope bounds the read.


def ambient_credentials() -> Any:
    """The deployment's AWS credential chain, or None when nothing is configured."""
    from botocore.session import get_session

    return get_session().get_credentials()


def _signing_credentials(stored: dict) -> Callable[[], Any]:
    """Return a callable yielding current credentials, refreshing a role session."""
    from botocore.credentials import Credentials

    key, secret = stored.get("access_key_id"), stored.get("secret_access_key")
    if key and secret:
        static = Credentials(key, secret, stored.get("session_token"))
        return lambda: static
    if key or secret or stored.get("session_token"):
        raise SourceUnavailable("credential_unavailable")
    try:
        resolved = ambient_credentials()
    except Exception:  # noqa: BLE001 — provider errors must not surface chain details
        raise SourceUnavailable("credential_unavailable") from None
    if resolved is None:
        raise SourceUnavailable("credential_unavailable")

    def current() -> Any:
        try:
            frozen = resolved.get_frozen_credentials()
        except Exception:  # noqa: BLE001
            raise SourceUnavailable("credential_unavailable") from None
        return Credentials(frozen.access_key, frozen.secret_key, frozen.token)

    return current


def _aws_call(
    budget: ReadBudget,
    client: httpx.Client,
    region: str,
    target: str,
    payload: bytes,
    credentials: Callable[[], Any],
    *,
    service: str = "logs",
    json_version: str = "1.1",
) -> dict:
    """One signed AWS JSON-protocol call, retried on throttling and transient failures.

    ``service`` is both the endpoint prefix and the SigV4 signing name, which coincide for
    CloudWatch Logs (``logs``) and CloudWatch metrics (``monitoring``).
    """
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    url = f"https://{service}.{region}.amazonaws.com/"
    for attempt in range(MAX_RETRIES + 1):
        # Re-sign every attempt: a SigV4 signature carries its timestamp.
        request = AWSRequest(
            method="POST",
            url=url,
            data=payload,
            headers={
                "Content-Type": f"application/x-amz-json-{json_version}", "X-Amz-Target": target,
            },
        )
        SigV4Auth(credentials(), service, region).add_auth(request)
        try:
            status, data = budget.fetch(
                client,
                "POST",
                url,
                max_response=MAX_RESPONSE_BYTES,
                content=payload,
                headers=dict(request.headers),
            )
        except SourceUnavailable as exc:
            if exc.code not in _TRANSIENT or attempt == MAX_RETRIES:
                raise
            log.warning("AWS %s call failed (%s); retry %d", service, exc.code, attempt + 1)
            budget.pause(min(8.0, 0.5 * 2**attempt))
            continue
        if status == 200:
            if not isinstance(data, dict):
                raise SourceUnavailable("invalid_source_data")
            return data
        kind = str(data.get("__type", "")).rsplit("#", 1)[-1] if isinstance(data, dict) else ""
        if (kind in _RETRYABLE or status >= 500) and attempt < MAX_RETRIES:
            budget.pause(min(8.0, 0.5 * 2**attempt))
            continue
        # AWS error type names are safe to log; the message body is not logged.
        log.warning("AWS %s returned HTTP %s %s", service, status, kind or "(no error type)")
        raise SourceUnavailable(_AWS_ERRORS.get(kind, "source_unavailable"))
    raise SourceUnavailable("source_unavailable")  # pragma: no cover - loop always returns


def _hour_windows(day: date) -> list[tuple[int, int]]:
    """Inclusive millisecond bounds for each UTC hour of ``day``."""
    start = datetime.combine(day, datetime.min.time(), tzinfo=UTC)
    return [
        (
            int((start + timedelta(hours=hour)).timestamp() * 1000),
            int((start + timedelta(hours=hour + 1)).timestamp() * 1000) - 1,
        )
        for hour in range(24)
    ]


def _event_key(event_id: object) -> int | None:
    if not isinstance(event_id, str) or not event_id:
        return None
    return int.from_bytes(hashlib.blake2b(event_id.encode(), digest_size=8).digest(), "big")


def sample_per_hour() -> int:
    """Events kept per UTC hour; 0 reads the whole day."""
    limit = settings.monitoring_aws_sample_events
    return math.ceil(limit / 24) if limit > 0 else 0


#: One page record ready to fold: eventId key, request-id key, message hash, event.
_PageRow = tuple[int | None, int | None, int, NormalizedWafEvent]


def cloudwatch_events(
    config: SourceConfig,
    credentials: dict,
    day: date,
    check: Callable[[], None],
    *,
    salt: bytes,
    routes: list[RouteBinding],
    progress: Callable[[dict], None] | None = None,
) -> tuple[dict, int, str]:
    """Read one UTC day of FilterLogEvents and fold it into the day's aggregates.

    Returns ``(metrics, event_count, digest)``. The day is split into hourly
    windows read concurrently. By default each hour is **sampled**: it is read
    backwards from its end in slices sized from the traffic rate just seen, and
    only its newest ``sample_per_hour()`` events are kept, so a production day
    costs minutes of logs per hour instead of the whole volume and every hour is
    represented. With ``MONITORING_AWS_SAMPLE_EVENTS=0`` every event is read.

    Records are normalized as their page arrives and folded into a
    ``DayAccumulator``, so no raw message outlives its page. Duplicates are
    dropped by eventId and request id, and the digest is an order-independent
    sum of the kept messages' hashes, so thread timing moves neither. Any failed
    window or incomplete pagination fails the whole day.
    """
    check_allowlist("aws_cloudwatch", config)
    if not config.region or not config.log_group:
        raise SourceUnavailable("invalid_configuration")
    return _CloudWatchDay(
        config,
        config.region,
        config.log_group,
        credentials,
        day,
        check,
        salt=salt,
        routes=routes,
        progress=progress,
    ).read()


class _CloudWatchDay:
    """One day's read: the hour workers share its dedupe sets, digest and counts.

    Everything mutable is touched under ``lock``; ``stop`` makes the remaining
    windows give up at their next call once one has failed.
    """

    def __init__(
        self,
        config: SourceConfig,
        region: str,
        log_group: str,
        credentials: dict,
        day: date,
        check: Callable[[], None],
        *,
        salt: bytes,
        routes: list[RouteBinding],
        progress: Callable[[dict], None] | None,
    ) -> None:
        self.config = config
        self.region = region
        self.log_group = log_group
        self.day = day
        self.check = check
        self.salt = salt
        self.routes = routes
        self.progress = progress
        self.signing = _signing_credentials(credentials)
        self.per_hour = sample_per_hour()
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.accumulator = DayAccumulator()
        self.seen_events: set[int] = set()
        self.seen_requests: set[int] = set()
        self.pages = 0
        self.events = 0
        self.digest = 0
        self.started = time.monotonic()
        self.budget = ReadBudget(
            self.guard,
            max_calls=settings.monitoring_aws_max_calls,
            seconds=settings.monitoring_collect_seconds,
            max_bytes=None,
        )

    def read(self) -> tuple[dict, int, str]:
        pool = ThreadPoolExecutor(max_workers=max(1, settings.monitoring_aws_concurrency))
        try:
            futures = [pool.submit(self.read_hour, bounds) for bounds in _hour_windows(self.day)]
            for future in as_completed(futures):
                future.result()
        except BaseException:
            self.stop.set()  # running windows stop at their next call
            pool.shutdown(wait=True, cancel_futures=True)
            raise
        pool.shutdown(wait=True)
        self.budget.guard()
        metrics = self.accumulator.metrics()
        if self.per_hour:
            metrics["sample"] = {
                "strategy": "newest_per_hour",
                "per_hour": self.per_hour,
                "limit": settings.monitoring_aws_sample_events,
                "kept": self.accumulator.event_count,
                "read": self.events,
            }
        return metrics, self.accumulator.event_count, f"{self.digest:064x}"

    def guard(self) -> None:
        if self.stop.is_set():
            raise SourceUnavailable("cancelled")
        self.check()

    def fold(self, rows: list[_PageRow]) -> None:
        """Add rows to the day; the caller holds ``lock``."""
        for event_key, request_key, message_value, event in rows:
            if event_key is not None:
                if event_key in self.seen_events:
                    continue
                self.seen_events.add(event_key)
            if request_key is not None:
                if request_key in self.seen_requests:
                    continue
                self.seen_requests.add(request_key)
            self.digest = (self.digest + message_value) % _DIGEST_MODULUS
            self.accumulator.add(event)

    def read_hour(self, bounds: tuple[int, int]) -> None:
        with client_factory() as client:
            if not self.per_hour:
                self.read_range(client, bounds[0], bounds[1], self.fold)
                return
            candidates: list[_PageRow] = []
            end, span = bounds[1], SAMPLE_FIRST_SLICE_MS
            while end >= bounds[0] and len(candidates) < self.per_hour:
                start = max(bounds[0], end - span + 1)
                before = len(candidates)
                self.read_range(client, start, end, candidates.extend)
                got, missing = len(candidates) - before, self.per_hour - len(candidates)
                end = start - 1
                # Size the next slice from the rate just seen, with headroom.
                span = (
                    span * 8
                    if got == 0
                    else max(span, math.ceil(span * missing / got * 1.25))
                )
                span = min(span, HOUR_MS)
            newest = sorted(
                candidates, key=lambda row: (row[3].observed_at, row[2]), reverse=True
            )[: self.per_hour]
            with self.lock:
                self.fold(newest)

    def read_range(
        self,
        client: httpx.Client,
        start: int,
        end: int,
        on_page: Callable[[list[_PageRow]], None],
    ) -> None:
        """Page through one inclusive millisecond range to exhaustion."""
        tokens: set[str] = set()
        token: str | None = None
        while True:
            self.guard()
            check_allowlist("aws_cloudwatch", self.config)
            args: dict[str, object] = {
                "logGroupName": self.log_group,
                "startTime": start,
                "endTime": end,
                "unmask": False,
            }
            if token:
                args["nextToken"] = token
            result = _aws_call(
                self.budget,
                client,
                self.region,
                "Logs_20140328.FilterLogEvents",
                json.dumps(args).encode(),
                self.signing,
            )
            rows = result.get("events")
            if not isinstance(rows, list):
                raise SourceUnavailable("invalid_source_data")
            page = self.page_rows(rows)
            with self.lock:
                on_page(page)
                snapshot = self._count_page(len(rows))
            log.info(
                "monitoring collect %s %s: page %d, %d events read, %ds",
                self.log_group,
                self.day,
                snapshot["pages"],
                snapshot["events"],
                snapshot["seconds"],
            )
            if self.progress is not None:
                self.progress(snapshot)
            next_token = result.get("nextToken")
            if next_token is None:
                return
            if not isinstance(next_token, str) or not next_token or next_token in tokens:
                raise SourceUnavailable("pagination_incomplete")
            tokens.add(next_token)
            token = next_token

    def _count_page(self, rows: int) -> dict[str, int]:
        """Count a page against the row limit; the caller holds ``lock``."""
        self.pages += 1
        self.events += rows
        if self.events > settings.monitoring_aws_max_events:
            raise SourceUnavailable("row_limit")
        # Counts only: a progress line never carries a log value.
        return {
            "pages": self.pages,
            "events": self.events,
            "seconds": round(time.monotonic() - self.started),
        }

    def page_rows(self, rows: list) -> list[_PageRow]:
        page: list[_PageRow] = []
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("message"), str):
                raise SourceUnavailable("invalid_source_data")
            try:
                record = json.loads(row["message"])
                if not isinstance(record, dict):
                    raise ValueError
                event = normalize_waf_event(record, salt=self.salt, routes=self.routes)
            except (ValueError, TypeError, OverflowError, OSError, RecursionError):
                raise SourceUnavailable("invalid_source_data") from None
            if event.observed_at.date() != self.day:
                continue  # counted on the day it belongs to
            page.append(
                (
                    _event_key(row.get("eventId")),
                    short_key(event.request_id_hash) if event.request_id_hash else None,
                    int.from_bytes(hashlib.sha256(row["message"].encode()).digest(), "big"),
                    event,
                )
            )
        return page


# --- Application Load Balancer metrics ------------------------------------------------

#: ``id -> (metric, statistic)`` read per hour from ``AWS/ApplicationELB``. Ids are what
#: the stored hours are keyed by. Counts are sums; response time is in seconds.
ALB_METRICS: dict[str, tuple[str, str]] = {
    "requests": ("RequestCount", "Sum"),
    "target_2xx": ("HTTPCode_Target_2XX_Count", "Sum"),
    "target_3xx": ("HTTPCode_Target_3XX_Count", "Sum"),
    "target_4xx": ("HTTPCode_Target_4XX_Count", "Sum"),
    "target_5xx": ("HTTPCode_Target_5XX_Count", "Sum"),
    "elb_4xx": ("HTTPCode_ELB_4XX_Count", "Sum"),
    "elb_5xx": ("HTTPCode_ELB_5XX_Count", "Sum"),
    "rejected_connections": ("RejectedConnectionCount", "Sum"),
    "target_connection_errors": ("TargetConnectionErrorCount", "Sum"),
    "response_avg": ("TargetResponseTime", "Average"),
    "response_p99": ("TargetResponseTime", "p99"),
}
ALB_LATENCY = frozenset({"response_avg", "response_p99"})
#: One point per UTC hour: the same grain as the WAF buckets, so a lead's hours line up
#: with the load balancer's, and CloudWatch keeps hourly points for 455 days.
ALB_PERIOD = 3600
#: Pages of GetMetricData per day; one day of hourly points fits in the first.
ALB_MAX_PAGES = 10


def cloudwatch_window(
    config: SourceConfig,
    credentials: dict,
    start: datetime,
    end: datetime,
    check: Callable[[], None],
    *,
    salt: bytes,
    routes: list[RouteBinding],
) -> tuple[list[NormalizedWafEvent], str | None]:
    """Read every WAF event in ``[start, end)`` for the short-window detectors.

    Unlike the daily reader this never samples: a threshold counted over a sample
    is a different threshold. Returns ``(events, incomplete)``. ``incomplete`` names
    why the read stopped early -- ``row_limit`` or ``deadline_exceeded`` -- and the
    events read so far are kept: a partial window can only undercount, and it is
    labelled, where discarding it would record an unreadable hour. A binding change,
    a bad page or an AWS error still raises.
    """
    check_allowlist("aws_cloudwatch", config)
    if not config.region or not config.log_group:
        raise SourceUnavailable("invalid_configuration")
    region, log_group = config.region, config.log_group
    signing = _signing_credentials(credentials)
    stop = threading.Event()
    lock = threading.Lock()
    events: list[NormalizedWafEvent] = []
    seen: set[int] = set()
    state: dict[str, str | None] = {"incomplete": None}

    def guard() -> None:
        if stop.is_set():
            raise SourceUnavailable("cancelled")
        check()

    budget = ReadBudget(
        guard,
        max_calls=settings.monitoring_aws_max_calls,
        seconds=settings.monitoring_rapid_collect_seconds,
        max_bytes=None,
    )
    first, last = int(start.timestamp() * 1000), int(end.timestamp() * 1000) - 1
    step = math.ceil((last - first + 1) / RAPID_SLICES)
    bounds = [(lo, min(last, lo + step - 1)) for lo in range(first, last + 1, step)]

    def read(window: tuple[int, int]) -> None:
        token: str | None = None
        tokens: set[str] = set()
        with client_factory() as client:
            while not stop.is_set():
                check_allowlist("aws_cloudwatch", config)
                args: dict[str, object] = {
                    "logGroupName": log_group, "startTime": window[0],
                    "endTime": window[1], "unmask": False,
                }
                if token:
                    args["nextToken"] = token
                result = _aws_call(
                    budget, client, region, "Logs_20140328.FilterLogEvents",
                    json.dumps(args).encode(), signing,
                )
                rows = result.get("events")
                if not isinstance(rows, list):
                    raise SourceUnavailable("invalid_source_data")
                page = []
                for row in rows:
                    if not isinstance(row, dict) or not isinstance(row.get("message"), str):
                        raise SourceUnavailable("invalid_source_data")
                    try:
                        record = json.loads(row["message"])
                        if not isinstance(record, dict):
                            raise ValueError
                        event = normalize_waf_event(record, salt=salt, routes=routes)
                    except (ValueError, TypeError, OverflowError, OSError, RecursionError):
                        raise SourceUnavailable("invalid_source_data") from None
                    page.append((_event_key(row.get("eventId")), event))
                with lock:
                    for key, event in page:
                        if key is not None:
                            if key in seen:
                                continue
                            seen.add(key)
                        if len(events) >= settings.monitoring_rapid_max_events:
                            state["incomplete"] = "row_limit"
                            stop.set()  # every slice stops at its next call
                            return
                        events.append(event)
                next_token = result.get("nextToken")
                if next_token is None:
                    return
                if not isinstance(next_token, str) or not next_token or next_token in tokens:
                    raise SourceUnavailable("pagination_incomplete")
                tokens.add(next_token)
                token = next_token

    pool = ThreadPoolExecutor(max_workers=max(1, settings.monitoring_aws_concurrency))
    failure: SourceUnavailable | None = None
    try:
        for future in as_completed([pool.submit(read, window) for window in bounds]):
            try:
                future.result()
            except SourceUnavailable as exc:
                if exc.code == "deadline_exceeded" and state["incomplete"] is None:
                    state["incomplete"] = "deadline_exceeded"
                    stop.set()
                elif exc.code != "cancelled" or state["incomplete"] is None:
                    failure = failure or exc
                    stop.set()
    except BaseException:
        stop.set()
        raise
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
    if failure is not None:
        raise failure
    return events, state["incomplete"]


def _rate(part: float, whole: float) -> float | None:
    return round(part / whole, 4) if whole else None


def alb_summary(hours: list[dict]) -> dict:
    """Day totals and the rates the page compares, from hourly points.

    Response-code rates are shares of what the targets answered. A request the load
    balancer answered itself (a WAF block shows as an ELB 403) never reached the app,
    so it is reported as its own share of all requests instead.
    """
    total = {key: sum(h[key] for h in hours) for key in ALB_METRICS if key not in ALB_LATENCY}
    answered = sum(total[k] for k in ("target_2xx", "target_3xx", "target_4xx", "target_5xx"))
    p99 = [h["response_p99"] for h in hours if h["response_p99"] is not None]
    return {
        **total,
        "target_responses": answered,
        "success_rate": _rate(total["target_2xx"], answered),
        "client_error_rate": _rate(total["target_4xx"], answered),
        "server_error_rate": _rate(total["target_5xx"], answered),
        "stopped_at_load_balancer_rate": _rate(total["elb_4xx"], total["requests"]),
        # The worst hour's p99, not an average of percentiles, which means nothing.
        "response_p99_max": round(max(p99), 4) if p99 else None,
    }


def alb_metrics(
    config: SourceConfig,
    credentials: dict,
    day: date,
    check: Callable[[], None],
    *,
    seconds: float,
) -> tuple[dict, str]:
    """Read one UTC day of a load balancer's CloudWatch metrics, one point per hour.

    Returns ``(metrics, digest)``. These cover the whole load balancer: no route and no
    client. They say how the app answered in each hour, which a WAF log cannot, and a
    lead's hours can be read against them -- as timing, never as attribution.
    """
    check_allowlist("aws_alb", config)
    if not config.region or not config.account_id or not config.load_balancer:
        raise SourceUnavailable("invalid_configuration")
    signing = _signing_credentials(credentials)
    budget = ReadBudget(check, max_calls=ALB_MAX_PAGES + MAX_RETRIES, seconds=seconds)
    start = datetime.combine(day, datetime.min.time(), tzinfo=UTC)
    queries = [
        {
            "Id": key,
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/ApplicationELB",
                    "MetricName": metric,
                    "Dimensions": [{"Name": "LoadBalancer", "Value": config.load_balancer}],
                },
                "Period": ALB_PERIOD,
                "Stat": stat,
            },
            "ReturnData": True,
        }
        for key, (metric, stat) in ALB_METRICS.items()
    ]
    points: dict[str, dict[int, float]] = {key: {} for key in ALB_METRICS}
    token: str | None = None
    with client_factory() as client:
        for _ in range(ALB_MAX_PAGES):
            body: dict[str, Any] = {
                "MetricDataQueries": queries,
                "StartTime": int(start.timestamp()),
                "EndTime": int((start + timedelta(days=1)).timestamp()),
                "ScanBy": "TimestampAscending",
            }
            if token:
                body["NextToken"] = token
            page = _aws_call(
                budget,
                client,
                str(config.region),
                "GraniteServiceVersion20100801.GetMetricData",
                json.dumps(body).encode(),
                signing,
                service="monitoring",
                json_version="1.0",
            )
            for result in page.get("MetricDataResults") or []:
                key = result.get("Id")
                if key not in points:
                    continue
                for stamp, value in zip(
                    result.get("Timestamps") or [], result.get("Values") or [], strict=False
                ):
                    try:
                        at = datetime.fromtimestamp(float(stamp), UTC)
                        number = float(value)
                    except (TypeError, ValueError, OverflowError, OSError):
                        raise SourceUnavailable("invalid_source_data") from None
                    # A point outside the day would land on the wrong hour; drop it.
                    if at.date() == day and math.isfinite(number):
                        points[key][at.hour] = number
            token = page.get("NextToken")
            if not token:
                break
        else:
            raise SourceUnavailable("incomplete_pagination")
    budget.guard()
    hours = [
        {
            "hour": hour,
            **{
                key: (
                    round(points[key][hour], 4) if hour in points[key] else None
                ) if key in ALB_LATENCY else int(round(points[key].get(hour, 0.0)))
                for key in ALB_METRICS
            },
        }
        for hour in range(24)
    ]
    metrics = {
        "version": 1,
        "load_balancer": config.load_balancer,
        "period_seconds": ALB_PERIOD,
        "hours": hours,
        "total": alb_summary(hours),
    }
    digest = hashlib.sha256(json.dumps(metrics, sort_keys=True).encode()).hexdigest()
    return metrics, digest


def github_context(config: SourceConfig, credentials: dict, check: Callable[[], None]) -> dict:
    """Read exact files at a commit, return route metadata and hashes, never code."""
    if not config.commit or not config.paths:
        raise SourceUnavailable("invalid_configuration")
    budget = ReadBudget(check)
    files = []
    with client_factory() as client:
        for path in config.paths:
            url = (
                f"https://api.github.com/repos/{config.repository}/contents/"
                f"{quote(path, safe='/')}?ref={config.commit}"
            )
            headers = {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            if credentials.get("github_token"):
                headers["Authorization"] = f"Bearer {credentials['github_token']}"
            data = budget.request(client, "GET", url, headers=headers)
            if (
                data.get("type") != "file"
                or data.get("encoding") != "base64"
                or data.get("path") != path
                or data.get("target")
                or data.get("submodule_git_url")
            ):
                raise SourceUnavailable("invalid_source_data")
            try:
                content = base64.b64decode(str(data["content"]).replace("\n", ""), validate=True)
                if len(content) > 128_000:
                    raise SourceUnavailable("byte_limit")
                text = content.decode("utf-8")
            except (KeyError, ValueError, UnicodeError):
                raise SourceUnavailable("invalid_source_data") from None
            # Verify the Git object hash as well as the requested immutable ref.
            blob = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
            if data.get("sha") != blob:
                raise SourceUnavailable("revision_mismatch")
            routes = []
            for match in re.finditer(
                r"""\.(get|post|put|patch|delete|head|options)\(\s*["'](/[A-Za-z0-9_{}:/.-]*)["']""",
                text,
            ):
                route = re.sub(r":([A-Za-z_][A-Za-z0-9_]*)", r"{\1}", match[2])
                routes.append({"method": match[1].upper(), "path": route[:300]})
            files.append({"path": path, "sha": blob, "routes": routes[:100]})
    budget.guard()
    return {"repository": config.repository, "commit": config.commit, "files": files}
