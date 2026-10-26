"""The probe loop the reflection checks share.

``reflected_injection`` and ``signature_injection`` differ only in which payloads
they send and how they read the response. Everything around that — walking the
operation's spec-shaped injection points, minting a unique marker, shaping the
value to the parameter's schema, filling the other required params with valid
baselines, sending, and stopping cleanly when the request budget runs out — is
identical, so it lives here.

Each send is described by an :class:`Attempt`, which carries the *rendered* path
alongside the value that produced it. That pairing matters: for a ``path``
injection point the payload is substituted into the URL, so the path differs per
payload and evidence built from a different attempt's path would be wrong.
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

from app.engine.base import ProbeResult, ScanContext, TargetOperation, render_path
from app.engine.request_shapes import control_value, points, request
from app.engine.spec_values import InjectionPoint, injection_value

#: Characters a response context would *neutralise* if it encoded output
#: correctly. A payload metacharacter that survives one of these contexts is the
#: reflection signal; a context that has none (``text``) can't be injection-broken
#: by a reflected value at all.
_CONTEXT_ACTIVE: dict[str, frozenset[str]] = {
    "html": frozenset("<>\"'"),
    "json": frozenset('"{}[]'),
    "text": frozenset(),
}


def response_context(response: ProbeResult) -> str:
    """Classify a response as ``html`` / ``json`` / ``text`` for reflection grading.

    Prefers the declared ``Content-Type`` and falls back to sniffing the body,
    because a reflected ``<script>`` only matters where it lands in markup and a
    reflected ``"`` only matters where it breaks a JSON string.
    """
    content_type = ""
    for key, value in response.headers.items():
        if key.lower() == "content-type":
            content_type = value.lower()
            break
    if "html" in content_type:
        return "html"
    if "json" in content_type:
        return "json"
    if not content_type:
        head = response.text.lstrip()[:200].lower()
        if head.startswith("<") or "<html" in head:
            return "html"
        if head.startswith(("{", "[")):
            return "json"
    return "text"


@dataclass(frozen=True)
class Attempt:
    """One payload delivered to one injection point, with its response."""

    op: TargetOperation
    point: InjectionPoint
    #: Index of the template that produced this attempt, so the caller can pair
    #: it back to whatever payload object it derived the template from.
    index: int
    #: The unique ``aidx<hex>`` needle to look for in the response body.
    needle: str
    #: The value actually sent (schema-shaped, marker substituted).
    value: str
    #: The rendered path this value was sent to — payload-dependent for `path` points.
    path: str
    response: ProbeResult
    case: dict[str, Any] | None = None

    def mark_finding(self) -> None:
        if self.case is not None:
            self.case["outcome"] = "finding"

    @property
    def echoed(self) -> bool:
        """Whether the marker came back at all — escaped, case-folded or not.

        Case-insensitive: a target that uppercases or lowercases its output has
        still echoed the marker, and case-folding is not neutralisation.
        """
        return self.needle.lower() in self.response.text.lower()

    @property
    def reflected(self) -> bool:
        """Whether the payload came back *unneutralised*.

        The marker is deliberately alphanumeric (``aidx<hex>``) so it survives
        transport intact — which means it also survives HTML escaping, JSON
        encoding and quote stripping. Looking for the marker alone therefore
        cannot tell "the response echoes your payload verbatim" from "the
        response escaped your payload correctly and the harmless part of it came
        back": an endpoint that turns ``<script>`` into ``&lt;script&gt;`` — the
        textbook correct behaviour — reported as a reflection lead.

        So the test is the payload's *own text* either side of the marker. Split
        the value at the marker and look for ``prefix + marker`` or
        ``marker + suffix`` in the body: escaping breaks both, because escaping
        is precisely what rewrites those characters. A payload that is nothing
        but the marker has no sides to check, and its bare echo stands.

        Two things this deliberately does not do. It does not search the whole
        body for a surviving metacharacter — every HTML page contains ``<`` in
        its own markup, so that reports every escaped reflection. And it does not
        match a fixed window around the marker — a window wide enough for a long
        payload swallows the page around a short one.

        The comparison is case-insensitive end to end: case-folding the echo is
        not neutralising it. A payload whose dangerous part sits on only one side
        of the marker (``javascript:aidx<hex>``) is reported only when that side
        survives — a target that strips the ``javascript:`` scheme and echoes the
        rest is treated as neutralised, which is the conservative direction.

        **A percent-encoded payload must have decoded.** ``%0d%0a`` is inert text
        until something turns it into a newline, and ``..%2f..%2f`` until
        something turns it into a path, so an encoded side is compared in its
        decoded form — and the raw escape coming back is positive proof the
        target never decoded it.
        """
        if not self.echoed:
            return False
        prefix, found, suffix = self.value.partition(self.needle)
        if not found or (not prefix and not suffix):
            # Nothing around the marker to neutralise; the echo is the finding.
            return True

        body = self.response.text.lower()
        needle = self.needle.lower()
        prefix = prefix.lower()
        suffix = suffix.lower()
        plain_prefix, plain_suffix = unquote(prefix), unquote(suffix)

        # An encoded side that came back verbatim was never decoded.
        if (plain_prefix != prefix and prefix and prefix + needle in body) or (
            plain_suffix != suffix and suffix and needle + suffix in body
        ):
            return False

        return bool(
            (plain_prefix and plain_prefix + needle in body)
            or (plain_suffix and needle + plain_suffix in body)
        )

    @property
    def injected(self) -> bool:
        """Whether a reflection survived into a context that *should* have neutralised it.

        :attr:`reflected` proves the payload's own text came back unencoded.
        That is necessary but not sufficient: ``../../`` or ``;echo`` coming back
        in an HTML page is inert — those characters are not markup — so an
        endpoint that renders them unchanged is behaving correctly. The lead only
        holds when a character the *response context* treats as active (``< > " '``
        in HTML, a structural ``" { } [ ]`` in JSON) survived beside the marker.

        This is what separates a truly unescaped reflection (``<`` comes back as
        ``<``) from correct output encoding (``<`` comes back as ``&lt;``), which
        the marker alone — alphanumeric by design — cannot tell apart.
        """
        if not self.reflected:
            return False
        prefix, found, suffix = self.value.partition(self.needle)
        if not found:
            return False
        body = self.response.text.lower()
        needle = self.needle.lower()
        active = _CONTEXT_ACTIVE[response_context(self.response)]
        surviving = ""
        plain_prefix = unquote(prefix).lower()
        plain_suffix = unquote(suffix).lower()
        if plain_prefix and plain_prefix + needle in body:
            surviving += plain_prefix
        if plain_suffix and needle + plain_suffix in body:
            surviving += plain_suffix
        return any(char in active for char in surviving)

    @property
    def header_injected(self) -> bool:
        """Whether a CRLF payload split the response into a new *header*.

        The curated CRLF payload carries ``X-aidx<marker>: 1``; the weakness is
        real only when that header name comes back among the response headers, so
        the marker echoed into the body (inert text) is not enough.
        """
        wanted = f"x-{self.needle}".lower()
        return any(key.lower() == wanted for key in self.response.headers)


def probe_point(
    ctx: ScanContext,
    op: TargetOperation,
    point: InjectionPoint,
    headers: dict[str, str],
    templates: list[str],
) -> Iterator[Attempt]:
    """Send each template to ``point``, yielding one :class:`Attempt` per send.

    ``{m}`` in a template is replaced with a fresh marker per send. Iteration
    stops silently once the probe's request budget is spent (``send`` returns
    ``None``), so callers get the attempts that did complete.
    """
    label = f"{op.method} {op.path} {point.location}:{point.name} variant={point.variant}"
    with ctx.probe.test_case(len(templates) + 1, label=label) as case:
        if case is None:
            return
        path, kwargs = request(ctx, op, point, control_value(point), headers)
        baseline_response = ctx.probe.send(op.method, path, **kwargs)
        case["baseline_valid"] = bool(baseline_response and 200 <= baseline_response.status < 300)
        if not case["baseline_valid"]:
            case["outcome"] = "blocked"
            return
        for index, template in enumerate(templates):
            material = f"{ctx.seed}:{label}:{index}:{template}"
            marker = hashlib.sha256(material.encode()).hexdigest()[:8]
            value = injection_value(point.schema, template.replace("{m}", marker))
            path, kwargs = request(ctx, op, point, value, headers)
            response = ctx.probe.send(op.method, path, **kwargs)
            if response is None:
                return
            yield Attempt(op=op, point=point, index=index, needle=f"aidx{marker}",
                          value=value, path=path, response=response, case=case)
        if case["outcome"] != "finding":
            case["outcome"] = "passed"


def walk_points(ctx: ScanContext) -> Iterator[tuple[TargetOperation, InjectionPoint]]:
    """Every (operation, injection point) pair in scope for this scan."""
    for op in ctx.operations:
        for point in points(ctx, op):
            yield op, point


def _item_read(ctx: ScanContext, op: TargetOperation) -> TargetOperation | None:
    """The GET that reads what ``op`` writes, by matching the item path shape."""
    from app.engine.resource_map import collection_of

    target = op.path if op.method in {"PUT", "PATCH"} else None
    for cand in ctx.operations:
        if cand.method != "GET":
            continue
        if target is not None and cand.path == target:
            return cand
        if target is None and collection_of(cand.path) == op.path:
            return cand
    return None


def _leaf_value(body: Any, point: InjectionPoint) -> Any:
    """The current value at ``point`` inside a read-back object, or None."""
    node = body
    for part in (point.pointer or (point.name,)):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def probe_body_point(
    ctx: ScanContext,
    op: TargetOperation,
    point: InjectionPoint,
    writer: Any,
    templates: list[str],
) -> Iterator[Attempt]:
    """Fuzz a POST/PUT/PATCH body field, sent as a writer, and tear down after.

    A body payload changes target state, so this runs only under ``mutate`` and
    always restores: a created object is deleted as its creator, and an updated
    field is put back to the value read before the probe. An update whose
    original value cannot be captured is skipped rather than left changed —
    never overwrite what cannot be restored.
    """
    from app.engine.cleanup import cleanup_as
    from app.engine.resource_map import build_body, created_id, path_values
    from app.engine.sequence import child_delete_op

    headers = writer.headers()
    is_update = op.method in {"PUT", "PATCH"}
    read_op = _item_read(ctx, op)
    field = str((point.pointer or (point.name,))[0])

    original: Any = None
    if is_update:
        if point.pointer and len(point.pointer) > 1:
            return  # a nested update field cannot be sent alone; leave it
        # Only touch a field we can put back. No read pairing, no restore → skip.
        # Nothing was written, so this is not a cleanup failure: recording one
        # per field and variant read as hundreds of unrestored writes.
        if read_op is None:
            return
        rpath = render_path(read_op.path, path_values(op, ctx.resource_ids))
        before = ctx.probe.send(read_op.method, rpath, headers=headers)
        if before is None or before.status >= 400:
            return
        from app.engine.resource_map import json_object

        obj = json_object(before.text)
        original = _leaf_value(obj, point) if obj is not None else None
        if not isinstance(original, str):
            return  # cannot restore a non-string / absent field

    created: list[str] = []
    # One slot per payload, plus the before-read, plus a teardown per payload.
    reserve = len(templates) + (1 if is_update else 0)
    cleanup = 1 if is_update else len(templates)
    label = f"{op.method} {op.path} body:{point.name} variant={point.variant}"
    with ctx.probe.test_case(reserve + 1, cleanup=cleanup, label=label) as case:
        if case is None:
            return
        try:
            for index, template in enumerate(templates):
                material = f"{ctx.seed}:{label}:{index}:{template}"
                marker = hashlib.sha256(material.encode()).hexdigest()[:8]
                value = injection_value(point.schema, template.replace("{m}", marker))
                path, kwargs = request(ctx, op, point, value, headers)
                if is_update:
                    kwargs.pop("content", None)
                    kwargs["json"] = {field: value}
                response = ctx.probe.send(op.method, path, **kwargs)
                if response is None:
                    return
                if not is_update and 200 <= response.status < 300:
                    cid = created_id(response.headers, response.text, read_op or op)
                    if cid:
                        created.append(cid)
                yield Attempt(
                    op=op, point=point, index=index, needle=f"aidx{marker}",
                    value=value, path=path, response=response, case=case,
                )
        finally:
            if is_update and original is not None:
                wpath = render_path(op.path, path_values(op, ctx.resource_ids))
                cleanup_as(ctx, op, wpath, [writer], json=build_body(op, field, original))
            for cid in created:
                delete = child_delete_op(ctx.operations, read_op) if read_op else None
                if delete is None:
                    ctx.cleanup_failures.append(
                        f"{op.method} {op.path}: no DELETE to remove a created object"
                    )
                    break
                # Resolve any parent ids from the run, then the item id by its
                # own param name (not its resource key, which path_values uses).
                dvals = path_values(delete, ctx.resource_ids)
                dvals[delete.path_params[-1]] = cid
                cleanup_as(ctx, delete, render_path(delete.path, dvals), [writer])
