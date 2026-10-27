"""Which optional passes a run was launched with.

One value object carried end to end — API request → Celery message → engine —
so the set of opt-ins is declared once and every layer names its fields.

This replaces a chain of positional booleans that had already drifted: the new-
scan wizard forwarded only four of them, and ``fuzz`` was unreachable from the
UI entirely. It also matters for the queue: Celery serialises task arguments,
so a task enqueued before a deploy is decoded by the new signature afterwards.
Positionally that silently re-maps the flags; as a named dict, an argument that
moves or disappears degrades to its default instead.

Every flag is off by default. That is a safety property, not a convenience:
``mutate`` writes to the target, ``confirm``/``zap``/``kali`` fire far more
traffic than the engine's budget allows, ``testssl`` takes minutes, and
``plan``/``adjudicate`` spend tokens. ``authorized`` deliberately lives on the
request, not here — it gates whether a run may start at all rather than
configuring one.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from typing import Any


@dataclass(frozen=True)
class RunOptions:
    """The opt-in passes for a single run. All default to off."""

    #: AI cascade adjudicates the judgment-heavy findings. Costs tokens.
    adjudicate: bool = False
    #: Static DeepSeek security design suggestions, separate from findings.
    security_review: bool = False
    #: OWASP ZAP active scan, outside the engine's request budget.
    zap: bool = False
    #: Kali adjunct service (nuclei, ffuf, nikto, whatweb, katana, arjun).
    kali: bool = False
    #: Write testing (BOLA/BFLA-on-write + body-sink injection). MUTATES the target.
    mutate: bool = False
    #: sqlmap / dalfox / commix / tplmap confirmation of the engine's leads. Slow.
    confirm: bool = False
    #: testssl.sh deep TLS audit of an HTTPS target. Up to five minutes of
    #: wall-clock, so it is a heavy-lane pass (the Deep level) rather than part of
    #: every run — a fast-lane scan relies on the built-in ``tls_config`` check.
    testssl: bool = False
    #: AI pre-scan plan: risk-rank operations so the budget hits risk first.
    plan: bool = False
    #: AI payload design: DeepSeek proposes extra reflection-payload variants that
    #: enrich the rotation pool. Advisory like ``plan`` — spends tokens, never
    #: changes which findings can exist (reflection identity excludes the family).
    genai_payloads: bool = False
    #: Schemathesis schema fuzzing: generated boundary/negative inputs.
    fuzz: bool = False
    #: Heavy-lane bounded whitebox agent (CLI local runner only): spends a small
    #: capped budget driving sandboxed tools to confirm/widen the engine's leads.
    #: A no-op on the server fast lane. Off by default like every pass.
    agent: bool = False
    #: Premium tier: run the checks reserved for the paid tier (host-header
    #: probing and the confirmation-tier scanners). Off by default like the rest.
    premium: bool = False
    #: Premium adaptive validation loop. Default-off and bounded.
    adaptive: bool = False
    #: Total payload attempts per selected endpoint/test, including the first.
    adaptive_attempts: int = 3
    #: Premium AI refinement for rejected resource-create bodies. Requires mutate.
    resource_refine: bool = False
    #: Total create attempts per resource, including the deterministic first try.
    resource_attempts: int = 3
    #: User-supplied resource-name -> id values for dependent path parameters.
    predefined_resource_ids: dict[str, str] = field(default_factory=dict)
    #: Engine-tier check keys to run. Empty means every registered check — the
    #: scope narrows a run, it never enables anything the flags above keep off.
    checks: tuple[str, ...] = ()
    seed: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialisable form for the Celery message."""
        data = dict(asdict(self))
        if self.seed is None:
            data.pop("seed", None)
        # Keep the historical boolean-only payload stable when the adaptive
        # pass is disabled; older workers can continue to decode queued jobs.
        if not self.adaptive:
            data.pop("adaptive_attempts", None)
        if not self.resource_refine:
            data.pop("resource_attempts", None)
        if self.checks:
            data["checks"] = list(self.checks)
        else:
            data.pop("checks", None)
        return data

    def archived(self) -> dict[str, Any]:
        """What a run's record keeps: :meth:`to_dict` without supplied resource ids.

        Those ids are target data the user handed in for this run; the archive,
        the diff and the manifest's options digest describe what was asked, not
        which fixtures it was pointed at.
        """
        data = self.to_dict()
        data.pop("predefined_resource_ids", None)
        return data

    def selects(self, check: str) -> bool:
        """Whether this run's scope includes the engine check ``check``."""
        return not self.checks or check in self.checks

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> RunOptions:
        """Rebuild from a queue message, ignoring flags this version doesn't know."""
        if not data:
            return cls()
        known = {f.name for f in fields(cls)}
        values: dict[str, Any] = {}
        for key, value in data.items():
            if key not in known:
                continue
            if key == "seed":
                if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**31:
                    values[key] = value
            elif key in {"adaptive_attempts", "resource_attempts"}:
                attempts = int(value)
                values[key] = attempts if attempts in (2, 3) else 3
            elif key == "predefined_resource_ids":
                if isinstance(value, dict):
                    values[key] = {
                        str(k): str(v) for k, v in list(value.items())[:50]
                        if str(k) and str(v)
                    }
            elif key == "checks":
                if isinstance(value, list | tuple):
                    values[key] = tuple(dict.fromkeys(str(c) for c in value[:64] if c))
            else:
                values[key] = bool(value)
        return cls(**values)

    @property
    def enabled(self) -> list[str]:
        """Names of the flags that are on — for logging and events."""
        return sorted(
            k for k, v in self.to_dict().items()
            if isinstance(v, bool) and v
        )


#: The grammar of a ``predefined_resource_ids`` entry. A name is
#: identifier-shaped (it cannot smuggle path syntax); an id is opaque and
#: target-owned but cannot break out of the path segment it is rendered into.
RESOURCE_NAME_PATTERN = r"^[A-Za-z][A-Za-z0-9_.-]{0,79}$"
RESOURCE_ID_PATTERN = r"^[^/?#\r\n]+$"
MAX_RESOURCE_IDS = 50


def supplied_resource_ids(value: Any) -> dict[str, str]:
    """A resource-id map from outside the API (the local runner's stdin), validated.

    Entries that break the grammar are dropped rather than trusted: the map is
    rendered into request paths, so it gets the same rule the run request does.
    """
    import re

    if not isinstance(value, dict):
        return {}
    name_re, id_re = re.compile(RESOURCE_NAME_PATTERN), re.compile(RESOURCE_ID_PATTERN)
    out: dict[str, str] = {}
    for raw_name, raw_id in list(value.items())[:MAX_RESOURCE_IDS]:
        if not isinstance(raw_name, str) or not isinstance(raw_id, str):
            continue
        name, ident = raw_name.strip(), raw_id.strip()
        if name_re.match(name) and 0 < len(ident) <= 256 and id_re.match(ident):
            out[name] = ident
    return out


#: Passes that decide whether a finding can exist at all. ``adjudicate`` and
#: ``plan`` change verdicts and ordering, never which findings a run produces.
_FINDING_PASSES = (
    "mutate", "zap", "kali", "confirm", "testssl", "fuzz", "premium", "adaptive",
)
#: Checks gated on mutate inside ``run`` rather than by a ``mutates`` trait
#: (which would also serialise them): they post bodies under premium + mutate.
_MUTATE_GATED = frozenset({"xxe_confirmation", "deserialization"})
#: Injection checks whose POST/PUT/PATCH body-sink findings exist only under
#: mutate. Their GET query/path findings share the key, so the method decides.
_BODY_SINK_CHECKS = frozenset({"reflected_injection", "signature_injection", "oob_injection"})
_READ_METHODS = frozenset({"GET", "HEAD"})
#: Evidence signals only the ``confirm`` pass produces, reported under a check
#: key the engine tier also reports without it: the arithmetic template oracle
#: (``independent_injection``) files a verified SSTI as ``reflected_injection``.
CONFIRM_SIGNALS = frozenset({"independent_arithmetic"})
#: The arithmetic oracle's title, for snapshots archived before ``signal`` was.
_ARITHMETIC_TITLE = "Template expression evaluated on "


def snapshot_signal(row: dict[str, Any]) -> str | None:
    """A snapshot row's evidence signal, for ``required_passes``.

    Rows archived before the snapshot recorded it are read from what they do
    carry: a verified ``reflected_injection`` titled as the arithmetic oracle
    can only have come from the confirm pass.
    """
    if "signal" in row:
        signal = row["signal"]
        return signal if isinstance(signal, str) else None
    if (
        row.get("check") == "reflected_injection"
        and row.get("confidence") == "verified"
        and str(row.get("title") or "").startswith(_ARITHMETIC_TITLE)
    ):
        return "independent_arithmetic"
    return None


def dropped_passes(older: dict[str, Any] | None, newer: dict[str, Any] | None) -> frozenset[str]:
    """Finding-producing passes the older run had on and the newer left off."""
    old, new = RunOptions.from_dict(older), RunOptions.from_dict(newer)
    return frozenset(p for p in _FINDING_PASSES if getattr(old, p) and not getattr(new, p))


def descoped(check: str, older: dict[str, Any] | None, newer: dict[str, Any] | None) -> bool:
    """Whether the older run tested engine check ``check`` and the newer's scope left it out.

    Only engine-tier keys are scoped; adjunct findings (``zap``, ``kali_*``) are
    governed by their own flags and never count here.
    """
    new = RunOptions.from_dict(newer)
    if new.selects(check):
        return False
    from app.engine.checks import ALL_CHECKS

    if check not in {c.key for c in ALL_CHECKS}:
        return False
    return RunOptions.from_dict(older).selects(check)


def required_passes(
    check: str, method: str | None = None, signal: str | None = None
) -> frozenset[str]:
    """The opt-in passes that must be on for ``check`` to report anything.

    Derived from the registry's own traits (``mutates``, premium) plus the
    adjunct naming, so a new mutating or premium check is covered without an
    entry here. Findings the discovery pass (``kali``) produces carry core check
    keys and cannot be told apart from engine-tier ones by key alone.
    ``signal`` is the finding's evidence signal, archived on the snapshot; it
    tells a ``confirm``-only finding from a lead sharing its check key.
    """
    from app.engine.checks import ALL_CHECKS, premium_check_keys

    needed: set[str] = set()
    if check == "zap":
        needed.add("zap")
    elif check.startswith("kali_"):
        needed.add("kali")
    elif check.endswith("_confirm"):
        needed.add("confirm")
    elif check == "testssl":
        needed.add("testssl")
    elif check == "schema_fuzz":
        needed.add("fuzz")
    elif check == "adaptive_validation":
        needed.update({"premium", "adaptive"})
    if signal in CONFIRM_SIGNALS:
        needed.add("confirm")
    if check in premium_check_keys():
        needed.add("premium")
    if check in _MUTATE_GATED or any(
        getattr(c, "key", None) == check and getattr(c, "mutates", False) for c in ALL_CHECKS
    ):
        needed.add("mutate")
    # ``method`` is absent on snapshots archived before it was recorded; such a
    # row is judged by its key alone.
    if check in _BODY_SINK_CHECKS and method and method.upper() not in _READ_METHODS:
        needed.add("mutate")
    return frozenset(needed)


def producing_tool(check: str) -> str | None:
    """The external tool behind an adjunct finding's check key, if any."""
    if check in {"zap", "testssl"}:
        return check
    if check.startswith("kali_"):
        return "kali"
    if check.endswith("_confirm"):
        return check.removesuffix("_confirm")
    return None


def unperformed(check: str, gaps: dict[str, Any] | None) -> bool:
    """Whether a run whose outcome is ``gaps`` could not have re-found ``check``.

    A tool in ``not_run`` never looked, an engine check in a run that hit the
    request cap may have been refused the requests that would have found it,
    and an identity check in a run that left an identity out lacked the
    credentials. Either way its absence is not a fix.
    """
    # A web run, an older runner, no directory or an offline advisory service
    # cannot establish that an older source finding has been fixed.
    if check == "source_runtime_cve":
        return not gaps or gaps.get("source_audit_complete") is not True
    if not gaps:
        return False
    tool = producing_tool(check)
    if tool is not None:
        return tool in set(gaps.get("not_run") or ())
    # The check declared itself inapplicable and never looked — say, BFLA once
    # the identities no longer form a privilege boundary.
    if check in set(gaps.get("skipped_checks") or ()):
        return True
    # The check started but raised part-way (a timeout on a slow host): what it
    # would have found is unknown, which is not the same as nothing.
    if check in set(gaps.get("failed_checks") or ()):
        return True
    if gaps.get("identities_missing"):
        from app.engine.checks import ALL_CHECKS
        from app.engine.contracts import needs_identities

        if any(getattr(c, "key", None) == check and needs_identities(c) for c in ALL_CHECKS):
            return True
    return bool(gaps.get("budget_exhausted"))
