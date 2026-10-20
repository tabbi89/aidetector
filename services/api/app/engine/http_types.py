"""Transport-facing value types shared by credentials and the probe.

These live apart from the probe so a credential can mint a token without
importing the request budget, and a check can name a response shape without
pulling in the trace machinery.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Protocol

# RFC 7230 ``token`` — a legal HTTP header name. Validated at both the
# credential boundary and the trace boundary, so an illegal name cannot crash a
# scan or become a header-injection vector.
HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


@dataclass
class ProbeResult:
    status: int
    headers: dict[str, str]
    text: str
    elapsed_ms: float
    # Raw response body — binary-safe, for probes that speak a non-text protocol
    # (gRPC-Web). Defaults empty so text-only checks and the in-process client
    # are unaffected.
    content: bytes = b""
    # Every wire response folded into this logical send. Normally one; longer
    # when the shared probe backed off and retried a 429.
    attempt_statuses: tuple[int, ...] = ()

    @property
    def was_throttled(self) -> bool:
        return self.status == 429 or 429 in self.attempt_statuses


@dataclass
class HeaderSnapshot:
    """One endpoint's response, captured once per scan.

    The header-based checks (`security_headers`, `info_disclosure`),
    `data_exposure` and `potential_secrets` all read the same sweep rather than
    each re-probing every endpoint — see
    ``engine/checks/misconfig.py:sweep_headers``. That is why the body sample
    lives here too: reading what a response gives away costs no request the
    sweep had not already spent.
    """

    operation_id: str | None
    method: str
    path: str
    status: int
    headers: dict[str, str]
    #: Truncated response body. Values never reach findings: consumers retain
    #: field names or value-free detector/structural-location metadata only.
    body: str = ""

    @property
    def label(self) -> str:
        return f"{self.method} {self.path}"


class HttpClient(Protocol):
    def request(self, method: str, url: str, **kwargs: Any) -> Any: ...
