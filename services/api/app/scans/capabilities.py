"""Which opt-in passes this deployment can actually perform right now.

A pass the run panel offers but the deployment cannot run is the worst kind of
option: the run "succeeds", the tool never looks, and nothing found reads as a
clean result. The panel asks here first so it can say so before the run.

The answer is advisory. The worker decides for itself at run time and records
what it could not do on the run; this only saves the user a wasted run. Results
are cached briefly because the panel asks on open and the probes are network
calls to sidecars.
"""
from __future__ import annotations

import shutil
import threading
import time
from collections.abc import Callable
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.scans.workspace import is_premium

CACHE_SECONDS = 30
PROBE_TIMEOUT = 1.5

Capability = dict[str, Any]
Get = Callable[[str, dict[str, str]], int]

_lock = threading.Lock()
_cached: tuple[float, dict[str, Capability]] | None = None


def _http_status(url: str, headers: dict[str, str]) -> int:
    return httpx.get(url, headers=headers, timeout=PROBE_TIMEOUT).status_code


def _ok() -> Capability:
    return {"available": True, "reason": None}


def _no(reason: str) -> Capability:
    return {"available": False, "reason": reason}


def _service(name: str, base: str, path: str, headers: dict[str, str], get: Get) -> Capability:
    if not base:
        return _no(f"{name} is not configured on this server")
    try:
        status = get(base.rstrip("/") + path, headers)
    except httpx.HTTPError:
        return _no(f"{name} is configured but not reachable — is its container running?")
    if status >= 500:
        return _no(f"{name} answered {status}")
    return _ok()


def _confirm_tools() -> Capability:
    configured = {
        "sqlmap": settings.sqlmap_bin,
        "dalfox": settings.dalfox_bin,
        "commix": settings.commix_bin,
        "tplmap": settings.tplmap_bin,
    }
    present = [tool for tool, path in configured.items() if path and shutil.which(path)]
    if not present:
        return _no("no confirmation tool (sqlmap, dalfox, commix, tplmap) is installed")
    missing = sorted(set(configured) - set(present))
    return {
        "available": True,
        "reason": f"{', '.join(missing)} not installed" if missing else None,
    }


def _testssl() -> Capability:
    if not settings.testssl_bin:
        return _no("TESTSSL_BIN is not set on this server")
    if not shutil.which(settings.testssl_bin):
        return _no("testssl.sh is not installed in the worker image")
    return _ok()


def _ai_runtime() -> Capability:
    from app.ai.planner import _AGENT_SCRIPT, OpusPlanner

    if not OpusPlanner().python.exists() or not _AGENT_SCRIPT.exists():
        return _no("the AI runtime is not installed on this server (see ai_runtime/README.md)")
    if settings.planner_provider == "deepseek" and not settings.deepseek_api_key:
        return _no("DEEPSEEK_API_KEY is not set on this server")
    return _ok()


def probe(get: Get = _http_status) -> dict[str, Capability]:
    zap_headers = {"X-ZAP-API-Key": settings.zap_api_key} if settings.zap_api_key else {}
    kali_headers = {"X-API-Key": settings.kali_api_key} if settings.kali_api_key else {}
    ai = _ai_runtime()
    return {
        "zap": _service("OWASP ZAP", settings.zap_base_url, "/JSON/core/view/version/",
                        zap_headers, get),
        "kali": _service("The Kali service", settings.kali_base_url, "/health",
                         kali_headers, get),
        "confirm": _confirm_tools(),
        "testssl": _testssl(),
        "plan": ai,
        "adjudicate": ai,
        "security_review": ai,
        "genai_payloads": ai,
    }


def entitlement(tenant: str, db: Session) -> dict[str, object]:
    """Whether this tenant may use the premium tier, and what it unlocks.

    Answering costs one workspace-plan lookup (or the ``premium_tenants``
    override), not a subscription service, so it is deliberately **not**
    cached: a tenant whose plan changed must see the new answer on the next
    request rather than after a cache window. Unlike the deployment probes
    above, this is not advisory — the premium routes enforce it.
    """
    if is_premium(db, tenant):
        return {"available": True, "plan": "premium", "reason": None}
    return {
        "available": False,
        "plan": "free",
        "reason": (
            "This tenant is on the free plan — premium detections, AI question "
            "answering and the pentest report need a premium plan."
        ),
    }


def capabilities(now: Callable[[], float] = time.monotonic) -> dict[str, Capability]:
    global _cached
    with _lock:
        if _cached is not None and now() - _cached[0] < CACHE_SECONDS:
            return _cached[1]
    result = probe()
    with _lock:
        _cached = (now(), result)
    return result


def reset_cache() -> None:
    global _cached
    with _lock:
        _cached = None
