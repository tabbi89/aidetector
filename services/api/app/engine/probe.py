"""The HTTP probe: request budget, retry policy, trace and redaction.

The probe is the one place a check's intent becomes an outbound request, so the
safety ceiling (the 750-request budget) and the archive (the request trace) both
live here rather than in any individual check.
"""
from __future__ import annotations

import json as jsonlib
import re
import threading
import time
from contextlib import contextmanager
from email.utils import parsedate_to_datetime
from math import ceil
from typing import Any

import httpx

from app.core.jsonsafe import jsonb_safe
from app.core.redact import Redactor
from app.engine.coverage import CoverageRecorder
from app.engine.credentials import ResolvedCredential, wire_kwargs
from app.engine.http_types import HEADER_NAME as _HEADER_NAME
from app.engine.http_types import HttpClient, ProbeResult
from app.engine.operations import TargetOperation
from app.engine.reauth import ReauthPolicy

# Shared by the probe, server scans and server-issued local-run budgets.
DEFAULT_MAX_REQUESTS = 750

_SENSITIVE_HEADER = re.compile(
    r"(?:authorization|proxy-authorization|cookie|set-cookie|api[-_]?key|"
    r"token|secret|password|passwd|session|csrf|xsrf|signature|credential)",
    re.IGNORECASE,
)
_IDENTIFIER_HEADER = re.compile(
    r"(?:^|[-_])(id|identifier|trace|correlation|request)(?:$|[-_])",
    re.IGNORECASE,
)
# ---- Request-trace limits -----------------------------------------------------
# The trace keeps a redacted sample of what came back, because "the write was
# rejected" is not an answer — "rejected with {"error":"tin required"}" is.
#
# Per row: a write or an error gets the long limit (it is the row someone opens),
# an ordinary 2xx read gets the short one (there are hundreds of them and each is
# the least interesting body in the trace).
_BODY_LIMIT_DETAIL = 4000
_BODY_LIMIT_ROUTINE = 1000
# Across the whole run: once this much body text is retained, later rows keep
# their structure and status but drop the body (``body_omitted``). Bounds one
# run's archive at roughly this plus ~600 bytes of structure per row, which is
# what keeps ``GET /scans/{id}/runs`` from shipping megabytes per run.
_BODY_BUDGET = 512_000
# Safety net on row count. The request budget (750) plus the discovery budget
# (150) already bound this; the cap exists so a future unbudgeted caller cannot
# grow the archive without limit.
_MAX_TRACE_ROWS = 2000
# Only these bodies are text worth keeping. A PDF, an image or a gzip stream
# decodes to 4000 characters of mojibake that helps nobody and still costs the
# budget.
_TEXTUAL_BODY = re.compile(
    r"^(?:text/|application/(?:json|xml|xhtml\+xml|javascript|x-www-form-urlencoded"
    r"|problem\+json|[\w.+-]*\+json|[\w.+-]*\+xml))",
    re.IGNORECASE,
)
# Request payload retained per row. The request body is what *we* generated, so
# it is far safer to keep than a response — and it is the half that answers "why
# was this rejected". Still redacted and capped.
_REQUEST_BODY_LIMIT = 2000
# A JSON shape's serialized size. The server refuses an upload whose trace holds a
# larger one (``app/api/schemas/runner.py:_TRACE_SHAPE_CHARS``), so the probe keeps
# under it: a wide, nested response (a job carrying its user, company and account)
# drops depth until it fits rather than failing the whole run's upload.
_SHAPE_CHARS = 8000
_SHAPE_DEPTHS = (5, 3, 2, 1)
# C0 control characters other than tab/newline/carriage-return. A gRPC-Web or
# other binary response decodes to text with NUL bytes, which Postgres JSONB
# refuses to store; stripping them keeps the trace JSON-safe without dropping
# the readable part of a text response.
_BODY_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
#: Methods whose trace row gets the long body limit — a write is the row a
#: reviewer opens, and the response is the proof it landed.
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# Methods the scanner may call without the explicit target-mutation opt-in.
# TRACE is intentionally excluded despite HTTP's historical "safe" label: it
# can expose credentials through intermediaries and is not needed by core checks.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
#: Transport failures worth one more attempt: the request may simply have met a
#: slow or cold host. A TLS, protocol or egress-guard error is not transient and
#: is never retried.
_TRANSIENT = (httpx.TimeoutException, httpx.NetworkError)


def method_is_allowed(method: str, *, allow_mutation: bool) -> bool:
    """Whether a check may send this method under the run's mutation policy."""
    return allow_mutation or method.upper() in SAFE_METHODS


def _response_headers(resp: Any) -> dict[str, str]:
    """Lowercased response headers, with repeated ``Set-Cookie`` kept separate.

    httpx joins repeated ``Set-Cookie`` headers with ``, `` when read through
    ``.items()`` — but a cookie value may itself contain a comma (an ``Expires``
    date), and merging two cookies lets an insecure one inherit its sibling's
    ``Secure`` flag. ``multi_items()`` keeps the individual lines; we join them
    with a newline, which no cookie value can contain, and let the header policy
    split them back apart.
    """
    items = (
        resp.headers.multi_items()
        if callable(getattr(resp.headers, "multi_items", None))
        else resp.headers.items()
    )
    out: dict[str, str] = {}
    for name, value in items:
        key = name.lower()
        if key == "set-cookie":
            prior = out.get(key)
            out[key] = f"{prior}\n{value}" if prior else value
        else:
            out[key] = value
    return out


class HttpProbe:
    """Sends requests and counts them against a per-scan budget (rate safety).

    Also attributes each request to the operation it targeted (by path-template
    match) and the check that issued it (``check_context``, set by the runner),
    so the runner can build a per-endpoint coverage report without threading an
    operation id through every check. Attribution is best-effort: a request whose
    path does not match any template (e.g. a traversal payload in a path segment)
    is simply not attributed.
    """

    def __init__(
        self,
        client: HttpClient,
        max_requests: int = DEFAULT_MAX_REQUESTS,
        operations: list[TargetOperation] | None = None,
        credentials: list[ResolvedCredential] | None = None,
        redact: Redactor | None = None,
    ) -> None:
        self._client = client
        self._max = max_requests
        self._max_429_retries = 2
        self._max_backoff = 8.0
        self._lock = threading.Lock()
        self._local = threading.local()
        self.count = 0
        # Requests the global ceiling refused, and the check that hit it first.
        # A run cut short at the cap otherwise reads exactly like a complete one.
        self.refused = 0
        self.first_refused_check: str | None = None
        self._held = 0
        self._deferred_cleanup = 0
        self.test_cases: list[dict[str, Any]] = []
        self.cleanup_results: list[bool] = []
        self.manifest: dict[str, Any] = {}
        # The last transport failure per check: (exception, method, route). The
        # runner reads it when a check raises, to say where the check stopped.
        self._failures: dict[str, tuple[BaseException, str, str]] = {}
        ops = operations or []
        # Reporting lives in its own collaborator: the budget below is a safety
        # ceiling and must not be entangled with what the report renders.
        self._coverage = CoverageRecorder(ops)
        self._operation_counts: dict[str, int] = {}
        self._per_operation_max = (
            max(10, ceil(max_requests / len(ops)) * 2) if ops else max_requests
        )
        self._credentials = credentials or []
        # Masks secrets/PII from the bodies a trace retains, and reports the
        # sensitive field names it saw on the way past. Defaults to a
        # pattern-only redactor rather than to nothing: a caller that forgets to
        # pass one gets less redaction, never raw target data. The runner passes
        # a secret-aware one so the scan's own credentials are masked verbatim.
        self._redact = redact or Redactor()
        self._reauth = ReauthPolicy(
            self._credentials, client, self._reserve, self._redact.add_secret
        )
        # Request/response trace of every outbound call (read and write). Header
        # names and safe operational values are retained; credentials/cookies and
        # rendered ids are redacted. Bodies are stored as a redacted, truncated
        # sample so a human can see what was sent and what came back.
        self.mutations: list[dict[str, Any]] = []
        # Body text retained so far, against ``_BODY_BUDGET``.
        self._body_spent = 0
        # Requests made by passes that ran on their own probe and budget (the
        # discovery probe) and were merged in with :meth:`absorb`. Kept apart
        # from ``count`` so the 500-request budget still means 500.
        self.secondary_requests = 0

    @property
    def coverage(self) -> dict[str, dict[str, int]]:
        """operation id -> {check key -> request count}, for the run report."""
        return self._coverage.per_operation

    @property
    def client(self) -> HttpClient:
        """The underlying transport, so a second bounded pass (discovery) can
        reuse the same connection rather than opening a new one."""
        return self._client

    @property
    def check_context(self) -> str | None:
        return getattr(self._local, "check_context", None)

    @check_context.setter
    def check_context(self, value: str | None) -> None:
        self._local.check_context = value

    @contextmanager
    def test_case(self, requests: int, *, cleanup: int = 0, label: str = ""):
        """Reserve a whole case atomically; cleanup cannot be spent by probes.

        Slots remain inside the global ceiling. Reserved cases bypass endpoint
        fairness (a complete control/probe/read-back sequence is indivisible).
        Automatic retries are disabled within cases so they cannot consume a
        later control's slot. Unused slots are returned even after exceptions.
        """
        if getattr(self._local, "case", None) is not None:
            raise RuntimeError("nested request reservations are unsupported")
        if requests < 1 or cleanup < 0 or cleanup >= requests:
            raise ValueError("invalid complete-case budget")
        row = {
            "check": self.check_context,
            "label": label,
            "outcome": "inconclusive",
            "baseline_valid": None,
            "requests": 0,
            "reserved": requests,
        }
        with self._lock:
            available = self.count + self._held + requests <= self._max
            if available:
                self._held += requests
            else:
                row["outcome"] = "budget_exhausted"
            if len(self.test_cases) < 2000:
                self.test_cases.append(row)
        if not available:
            yield None
            return
        case: dict[str, Any] = {"active": requests - cleanup, "cleanup": cleanup, "row": row}
        self._local.case = case
        try:
            yield row
        except Exception:
            row["outcome"] = "error"
            raise
        finally:
            with self._lock:
                self._held -= case["active"] + case["cleanup"]
            self._local.case = None

    def defer_cleanup(self) -> None:
        """Keep one reserved teardown slot until provisioned fixtures are released."""
        case = getattr(self._local, "case", None)
        if case is None or case["cleanup"] < 1:
            raise RuntimeError("cleanup must be reserved before creating a fixture")
        with self._lock:
            case["cleanup"] -= 1
            self._deferred_cleanup += 1

    @contextmanager
    def cleanup_scope(self):
        previous = getattr(self._local, "cleaning", False)
        self._local.cleaning = True
        try:
            yield
        finally:
            self._local.cleaning = previous

    def _reserve(self, method: str, path: str, *, fairness_exempt: bool = False) -> bool:
        """Atomically reserve one real outbound request from global/fair budgets.

        The two budgets are the whole of this method: the global ceiling that
        stops a scan becoming a DoS, and the per-operation fairness cap that
        stops one endpoint eating it. Attribution for the report is delegated —
        it can never refuse a request, only describe one that was allowed.
        """
        op_id = self._coverage.operation_id(method, path)
        with self._lock:
            case = getattr(self._local, "case", None)
            if case is not None:
                pool = "cleanup" if getattr(self._local, "cleaning", False) else "active"
                if case[pool] <= 0:
                    case["row"]["outcome"] = "budget_exhausted"
                    return False
                case[pool] -= 1
                self._held -= 1
                case["row"]["requests"] += 1
                fairness_exempt = True
            elif getattr(self._local, "cleaning", False) and self._deferred_cleanup:
                self._deferred_cleanup -= 1
                self._held -= 1
                fairness_exempt = True
            elif self.count + self._held >= self._max:
                if not self.refused:
                    self.first_refused_check = self.check_context
                self.refused += 1
                return False
            if (
                not fairness_exempt
                and op_id is not None
                and self._operation_counts.get(op_id, 0) >= self._per_operation_max
            ):
                return False
            self.count += 1
            if op_id is not None:
                self._operation_counts[op_id] = self._operation_counts.get(op_id, 0) + 1
                self._coverage.note(op_id, self.check_context)
        return True

    def send(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json: Any | None = None,
        content: bytes | None = None,
        fairness_exempt: bool = False,
    ) -> ProbeResult | None:
        if not self._reserve(method, path, fairness_exempt=fairness_exempt):
            return None
        kwargs: dict[str, Any] = {
            "headers": (headers or {}),
            "params": params or {},
        }
        if json is not None:
            kwargs["json"] = json
        if content is not None:
            kwargs["content"] = content

        start = time.perf_counter()
        resp = self._transport(method, path, kwargs, fairness_exempt=fairness_exempt)
        attempt_statuses = [resp.status_code]
        reserved_case = getattr(self._local, "case", None) is not None
        if resp.status_code == 401 and not reserved_case:
            resp = self._reauth.retry(method, path, kwargs, headers or {}, resp)
            if resp.status_code != attempt_statuses[-1]:
                attempt_statuses.append(resp.status_code)
        # Respect a rate-limited target: back off on 429 so results aren't
        # poisoned by throttling. Bounded retries, and each retry reserves its
        # own budget slot — the budget counts real outbound requests, so a
        # target that 429s everything exhausts it rather than retrying for free.
        # A retry that cannot reserve stops the loop and returns the 429.
        attempts = 0
        while not reserved_case and resp.status_code == 429 and attempts < self._max_429_retries:
            delay = self._retry_after(resp.headers) or (0.5 * (2**attempts))
            time.sleep(min(delay, self._max_backoff))
            attempts += 1
            if not self._reserve(method, path, fairness_exempt=fairness_exempt):
                break
            resp = self._request_or_record(method, path, kwargs)
            attempt_statuses.append(resp.status_code)
        elapsed = (time.perf_counter() - start) * 1000
        result = ProbeResult(
            status=resp.status_code,
            headers=_response_headers(resp),
            text=resp.text,
            elapsed_ms=round(elapsed, 1),
            content=getattr(resp, "content", b"") or b"",
            attempt_statuses=tuple(attempt_statuses),
        )
        self._record_mutation(method, path, kwargs, result)
        return result

    def _transport(
        self, method: str, path: str, kwargs: dict[str, Any], *, fairness_exempt: bool
    ) -> Any:
        """Send one already-reserved request, retrying a transient failure once.

        One retry, and only for a safe method outside a reserved test case: a
        write that timed out may still have landed, and a case's slots are
        counted out in advance. The retry reserves its own slot like a 429
        retry does, so a host that never answers spends the budget rather than
        retrying for free. A failure that survives (or is not retried) is
        recorded on the trace and re-raised — the check stops, and the runner
        reports it as a check that did not finish rather than one that found
        nothing.
        """
        retryable = (
            method.upper() in SAFE_METHODS and getattr(self._local, "case", None) is None
        )
        try:
            return self._request_or_record(method, path, kwargs)
        except _TRANSIENT:
            if not retryable or not self._reserve(method, path, fairness_exempt=fairness_exempt):
                raise
        return self._request_or_record(method, path, kwargs)

    def _request_or_record(self, method: str, path: str, kwargs: dict[str, Any]) -> Any:
        """One outbound request. A raised transport error leaves a trace row
        naming its class — "ReadTimeout", not a bare missing status — and is
        noted against the check, whether or not it is about to be retried."""
        try:
            return self._client.request(method.upper(), path, **wire_kwargs(kwargs))
        except Exception as exc:
            self._record_mutation(method, path, kwargs, None, error=type(exc).__name__)
            self._note_failure(exc, method, path)
            raise

    def _note_failure(self, exc: BaseException, method: str, path: str) -> None:
        key = self.check_context
        if key is None:
            return
        route = self._coverage._route(method, path) or "(unattributed)"
        with self._lock:
            self._failures[key] = (exc, method.upper(), route)

    def failure_site(self, check: str, exc: BaseException) -> str | None:
        """``"GET /users/{id}"`` when ``exc`` is the transport failure that
        stopped ``check`` (directly or as a cause), else ``None``.

        Matched on the exception object, so a check that swallowed one timeout
        and later raised for another reason is not blamed on the old route.
        """
        with self._lock:
            noted = self._failures.get(check)
        if noted is None:
            return None
        seen: BaseException | None = exc
        for _ in range(5):
            if seen is None:
                break
            if seen is noted[0]:
                return f"{noted[1]} {noted[2]}"
            seen = seen.__cause__ or seen.__context__
        return None

    def can_burst(self) -> bool:
        """Whether the transport supports a concurrent, un-rate-limited burst.

        Only the async bridge does; the sync test client cannot, so the race
        check no-ops there rather than firing a serialized 'burst' that could
        never catch a race."""
        return callable(getattr(self._client, "burst", None))

    def burst(
        self,
        method: str,
        path: str,
        *,
        count: int,
        headers: dict[str, str] | None = None,
        json: Any | None = None,
    ) -> list[ProbeResult] | None:
        """Fire ``count`` identical requests at once, bypassing the rate limiter.

        Each still reserves a slot from the global request budget — the budget
        counts real outbound requests, and a burst is no exception. Returns one
        ProbeResult per request that actually went out (exceptions dropped), or
        None when the transport cannot burst. For the race check only.
        """
        client_burst = getattr(self._client, "burst", None)
        if not callable(client_burst):
            return None
        reserved = 0
        for _ in range(max(0, count)):
            if not self._reserve(method, path):
                break
            reserved += 1
        if reserved == 0:
            return None
        kwargs: dict[str, Any] = {"headers": (headers or {})}
        if json is not None:
            kwargs["json"] = json
        raw = client_burst(
            [(method.upper(), path, wire_kwargs(kwargs)) for _ in range(reserved)]
        )
        results: list[ProbeResult] = []
        for resp in raw:
            if isinstance(resp, BaseException):
                # Dropped from the results, but the request went out: the
                # trace says so and names the failure.
                self._record_mutation(method, path, kwargs, None, error=type(resp).__name__)
                continue
            result = ProbeResult(
                status=resp.status_code,
                headers=_response_headers(resp),
                text=resp.text,
                elapsed_ms=0.0,
                content=getattr(resp, "content", b"") or b"",
                attempt_statuses=(resp.status_code,),
            )
            results.append(result)
            self._record_mutation(method, path, kwargs, result)
        return results

    @staticmethod
    def _shape(value: Any) -> Any:
        """Describe JSON structure while discarding every scalar value.

        Bounded to ``_SHAPE_CHARS`` serialized: the deepest description that fits.
        """
        for max_depth in _SHAPE_DEPTHS:
            shape = HttpProbe._describe(value, 0, max_depth)
            if len(jsonlib.dumps(shape, default=str)) <= _SHAPE_CHARS:
                return shape
        return {"type": "truncated"}

    @staticmethod
    def _describe(value: Any, depth: int, max_depth: int) -> Any:
        if depth >= max_depth:
            return {"type": "truncated"}
        if isinstance(value, dict):
            return {
                str(key)[:80]: HttpProbe._describe(item, depth + 1, max_depth)
                for key, item in list(value.items())[:50]
            }
        if isinstance(value, list):
            sample = HttpProbe._describe(value[0], depth + 1, max_depth) if value else None
            return {"type": "array", "items": len(value), "sample": sample}
        if isinstance(value, str):
            return {"type": "string", "length": min(len(value), 100000)}
        if isinstance(value, bool):
            return {"type": "boolean"}
        if isinstance(value, int | float):
            return {"type": "number"}
        if value is None:
            return {"type": "null"}
        return {"type": type(value).__name__}

    @staticmethod
    def _safe_headers(headers: Any) -> dict[str, str]:
        """Keep useful header metadata without persisting credentials or IDs."""
        if not hasattr(headers, "items"):
            return {}
        safe: dict[str, str] = {}
        for raw_name, raw_value in list(headers.items())[:80]:
            name = str(raw_name).strip().lower()[:80]
            if not name or not _HEADER_NAME.fullmatch(name):
                continue
            if _SENSITIVE_HEADER.search(name):
                safe[name] = "<redacted>"
                continue
            value = str(raw_value)
            # Location values commonly contain the newly-created identifier;
            # retain the header's presence but never the concrete URL/id.
            if name in {
                "location",
                "content-location",
                "etag",
                "traceparent",
            } or _IDENTIFIER_HEADER.search(name):
                safe[name] = "<redacted>"
            else:
                safe[name] = value[:240] + ("…" if len(value) > 240 else "")
        return safe

    def _identity_of(self, headers: dict[str, Any]) -> str:
        """Which credential sent this request, by matching its auth headers.

        The trace redacts the Authorization value, so without this a reviewer
        reading a BOLA row cannot tell the low-privilege identity from the
        owner — which is the single fact that row exists to establish. Matching
        on the header the credential itself would contribute keeps every check
        out of it. Returns ``"anonymous"`` when no credential's headers are
        present, which is itself a meaningful baseline in the authz checks.
        """
        sent = {str(k).lower(): str(v) for k, v in headers.items()}
        for credential in self._credentials:
            contributed = credential.headers()
            if contributed and all(
                sent.get(name.lower()) == value for name, value in contributed.items()
            ):
                return credential.name
        return "anonymous"

    def _response_body(
        self, response: ProbeResult, method: str
    ) -> tuple[str, bool, bool, list[str]]:
        """The retained sample and what it exposed: ``(text, truncated, omitted, sensitive)``.

        **Detection is independent of retention.** The body is scanned for
        sensitive field names whether or not its text is kept, so the archive's
        size limits cannot blind ``data_exposure``: a response past the run's
        body budget still reports that it carried a password hash. Only the
        *names* travel — never a value, never a sample of the body.

        Non-textual responses are dropped without scanning; a PDF has no JSON
        field names to read, and decoding one is wasted work.
        """
        content_type = response.headers.get("content-type", "")
        if not _TEXTUAL_BODY.match(content_type.strip()):
            return "", False, True, []
        scan = self._redact.scan_body(_BODY_CONTROL.sub("", response.text))
        with self._lock:
            over_budget = self._body_spent >= _BODY_BUDGET
        if over_budget:
            return "", False, True, scan.sensitive
        limit = (
            _BODY_LIMIT_DETAIL
            if method.upper() in _WRITE_METHODS or response.status >= 400
            else _BODY_LIMIT_ROUTINE
        )
        body = scan.text
        truncated = len(body) > limit
        body = body[:limit]
        with self._lock:
            self._body_spent += len(body)
        return body, truncated, False, scan.sensitive

    def _record_mutation(
        self,
        method: str,
        path: str,
        kwargs: dict[str, Any],
        response: ProbeResult | None,
        *,
        error: str | None = None,
    ) -> None:
        response_shape: Any = None
        body, truncated, omitted = "", False, False
        sensitive: list[str] = []
        if response is not None:
            try:
                response_shape = self._shape(jsonlib.loads(response.text))
            except (TypeError, ValueError, RecursionError):
                response_shape = {"type": "text", "length": len(response.text)}
            body, truncated, omitted, sensitive = self._response_body(response, method)
        request_headers = dict(kwargs.get("headers") or {})
        if "json" in kwargs and not any(
            str(name).lower() == "content-type" for name in request_headers
        ):
            # httpx adds this header for ``json=`` at the transport boundary;
            # include it so the trace reflects what was actually sent.
            request_headers["Content-Type"] = "application/json"
        row = {
            "sequence": 0,
            "method": method.upper(),
            "route": self._coverage._route(method, path) or "(unattributed)",
            "check": self.check_context or "?",
            # Which pass made the call. Rewritten by :meth:`absorb` for rows
            # merged in from a secondary probe.
            "pass": "engine",
            # Whose credentials went out on this request.
            "identity": self._identity_of(request_headers),
            "elapsed_ms": response.elapsed_ms if response is not None else None,
            # The transport failure's class ("ReadTimeout", "ConnectError") when
            # no response came back. The class only: an exception message can
            # carry the target URL or a header value.
            "error": error,
            "request": {
                "headers": self._safe_headers(request_headers),
                "query_fields": sorted(str(k)[:80] for k in (kwargs.get("params") or {})),
                "json_shape": self._shape(kwargs["json"]) if "json" in kwargs else None,
                # The payload we generated, redacted and capped. Unlike a
                # response this is our own data, and it is what answers "why was
                # this rejected" when read next to the response body.
                "json_body": self._request_body(kwargs.get("json")),
                "content_bytes": len(kwargs.get("content") or b""),
            },
            "response": {
                "status": response.status if response is not None else None,
                "attempt_statuses": (
                    list(response.attempt_statuses) if response is not None else []
                ),
                "headers": self._safe_headers(response.headers if response is not None else {}),
                "content_type": (
                    response.headers.get("content-type", "")[:80] if response is not None else ""
                ),
                "body_bytes": len(response.content or b"") if response is not None else 0,
                "body": body,
                "truncated": truncated,
                "body_omitted": omitted,
                # Sensitive field *names* this response carried — the signal
                # ``data_exposure`` grades. Recorded even when the body itself
                # was not retained.
                "sensitive_fields": sensitive,
                "json_shape": response_shape,
            },
        }
        # Fuzzed parameter names and echoed headers can carry NUL, which the
        # run archive's jsonb column refuses — and one such row failed the run.
        row = jsonb_safe(row)
        with self._lock:
            if len(self.mutations) >= _MAX_TRACE_ROWS:
                return
            row["sequence"] = len(self.mutations) + 1
            self.mutations.append(row)

    def absorb(self, other: HttpProbe, *, label: str) -> None:
        """Merge a secondary probe's trace into this one under ``label``.

        A pass that runs on its own budget (the discovery probe) still belongs
        in one request log: the run archive is built from this probe alone, so
        without this the one pass that probes undeclared endpoints leaves no
        trace and its requests go uncounted. Sequence numbers are reassigned so
        the merged log reads in order.
        """
        with self._lock:
            self.secondary_requests += other.count
            for row in other.mutations:
                if len(self.mutations) >= _MAX_TRACE_ROWS:
                    break
                merged = dict(row)
                merged["pass"] = label
                merged["sequence"] = len(self.mutations) + 1
                self.mutations.append(merged)

    def _request_body(self, payload: Any) -> str:
        """Redacted, capped JSON text of the payload we sent, if any."""
        if payload is None:
            return ""
        try:
            raw = jsonlib.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        except (TypeError, ValueError, RecursionError):
            return ""
        return self._redact.body(raw)[:_REQUEST_BODY_LIMIT]

    @staticmethod
    def _retry_after(headers: Any) -> float | None:
        """Seconds from numeric or HTTP-date ``Retry-After``, if present."""
        try:
            raw = {k.lower(): v for k, v in headers.items()}.get("retry-after")
            if raw is None:
                return None
            try:
                return max(0.0, float(raw))
            except ValueError:
                dt = parsedate_to_datetime(str(raw))
                return max(0.0, dt.timestamp() - time.time())
        except (TypeError, ValueError):
            return None


def budget_exhausted_message(probe: HttpProbe) -> str:
    """The one line that says a run stopped sending at the request budget."""
    where = probe.first_refused_check
    return (
        f"request budget of {probe.count} spent"
        + (f" during {where}" if where else "")
        + " — later requests were not sent, so checks after this point are incomplete"
    )
