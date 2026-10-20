"""Run the core checks against what discovery found (OWASP API9).

The Kali adjuncts (ffuf, katana, arjun) report paths and parameters the target
serves but the spec never documents — and the engine, on its first pass, never
tested them, because it only knows the spec. That is exactly backwards for
API9: shadow endpoints are *where* the missing authz and the forgotten debug
routes live, precisely because nobody wrote them down.

This closes the loop. After the adjunct phase, the discovered paths/params are
already persisted as findings; ``synthetic_operations`` reconstructs
``TargetOperation``s from them, and the runner runs a reduced check set against
those in a **second, separately-budgeted pass**
(``settings.discovery_probe_budget``, default 150). Keeping it off the main
750-request budget is deliberate: testing shadow endpoints must not consume the
budget the documented ones need. Gated on ``kali`` — without discovery there is
nothing here to test.

A discovered path has no spec: no declared body, no types, no response schema.
So the checks that need those (the write oracle, mass assignment, schema fuzz)
are not in the set — they would no-op anyway. What does work on a bare path is
the header sweep (hardening, disclosure, over-exposure), the authorization
oracles, and — on the *parameters* arjun found, attached as query params —
reflection and SSRF. TLS is host-level and already audited once, so it is not
repeated per path.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from app.engine.base import TargetOperation
from app.models.finding import Finding

# The checks worth running against an endpoint we know only by its URL. Keyed by
# ``Check.key`` and filtered from the live registry, so a check that leaves the
# engine cannot linger here.
DISCOVERY_CHECK_KEYS: frozenset[str] = frozenset(
    {
        "security_headers",
        "info_disclosure",
        "data_exposure",
        "bola",
        "bfla",
        "broken_auth",
        "reflected_injection",
        "signature_injection",
        "ssrf",
    }
)

# Checks in the set above (the fuzzers) only earn a request when the path has a
# parameter to fuzz; the rest are worth running on a bare path.
_NEEDS_A_PARAM = frozenset({"reflected_injection", "signature_injection", "ssrf"})


def _path_of(value: str) -> str | None:
    """The path component of a discovered path or full URL, or None.

    ffuf/katana may report either ``/admin`` or ``https://host/admin``; only the
    path is used, so a discovered URL can never redirect the probe to another
    host (that would be an SSRF via our own findings).
    """
    value = (value or "").strip()
    if not value:
        return None
    if "://" in value:
        value = urlsplit(value).path or "/"
    else:
        # A bare path may still carry a query/fragment (?debug=1).
        value = value.split("?")[0].split("#")[0]
    if not value.startswith("/"):
        value = "/" + value
    return value


def _matches_template(template: str, concrete: str) -> bool:
    left = [part for part in template.strip("/").split("/") if part]
    right = [part for part in concrete.strip("/").split("/") if part]
    return len(left) == len(right) and all(
        (a.startswith("{") and a.endswith("}")) or a == b
        for a, b in zip(left, right, strict=True)
    )


def synthetic_operations(
    findings: list[Finding], documented: list[TargetOperation] | None = None
) -> list[TargetOperation]:
    """Build ``TargetOperation``s from discovery findings. Pure.

    - ``kali_discovery`` / ``kali_crawl`` → ``GET`` on the discovered path.
    - ``kali_params`` → ``GET`` on the path carrying the found parameters as
      query params, so the reflection/SSRF checks have somewhere to inject.

    Deduplicated by ``(method, path)`` with parameter sets merged, so a path
    reported by both ffuf and arjun becomes one operation that carries the
    params. Ids are prefixed ``discovered:`` so coverage and findings can tell a
    shadow endpoint apart from a spec'd one.
    """
    # path -> set of query param names
    params_by_path: dict[str, set[str]] = {}
    paths: set[str] = set()

    for f in findings:
        ev = f.evidence if isinstance(f.evidence, dict) else {}
        if f.check in ("kali_discovery", "kali_crawl"):
            path = _path_of(str(ev.get("path") or ""))
            if path:
                paths.add(path)
        elif f.check == "kali_params":
            path = _path_of(str(ev.get("url") or ""))
            names = ev.get("params")
            if path and isinstance(names, list):
                bucket = params_by_path.setdefault(path, set())
                bucket.update(str(n) for n in names if n)
                paths.add(path)

    ops: list[TargetOperation] = []
    for path in sorted(paths):
        declared = next(
            (
                op
                for op in documented or []
                if op.method.upper() == "GET" and _matches_template(op.path, path)
            ),
            None,
        )
        discovered_params = params_by_path.get(path, set())
        new_params = (
            discovered_params - set(declared.query_params)
            if declared is not None
            else discovered_params
        )
        # Crawlers rediscover documented endpoints routinely. Re-probe only
        # when arjun found a genuinely undeclared parameter on that route.
        if declared is not None and not new_params:
            continue
        params = [
            {"name": name, "in": "query", "required": False}
            for name in sorted(new_params)
        ]
        ops.append(
            TargetOperation(
                id=f"discovered:GET:{path}",
                method="GET",
                path=path,
                params=params,
            )
        )
    return ops


def relevant_checks(checks: list, operations: list[TargetOperation]) -> list:
    """The discovery check set, minus fuzzers when nothing has a parameter.

    ``checks`` is the live ``ALL_CHECKS`` registry; filtering from it rather than
    instantiating here means the discovery pass can never run a check the engine
    has retired, and picks up a new core check automatically once its key is
    added to ``DISCOVERY_CHECK_KEYS``.
    """
    any_params = any(op.params for op in operations)
    selected = []
    for check in checks:
        key = getattr(check, "key", None)
        if key not in DISCOVERY_CHECK_KEYS:
            continue
        if key in _NEEDS_A_PARAM and not any_params:
            continue
        selected.append(check)
    return selected
