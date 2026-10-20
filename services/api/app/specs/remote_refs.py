"""Bounded, allowlisted resolution of *remote* OpenAPI ``$ref``s.

Internal ``$ref``s (``#/components/...``) are always safe to inline — they never
leave the document. A **remote** ``$ref`` (``https://schemas.acme.com/x.yaml#/Y``)
is different: fetching it is an outbound request driven by the uploaded spec, i.e.
a server-side request forgery primitive. So remote refs are **off by default**
and only resolved when an operator has configured ``spec_ref_allowlist``.

When enabled, every fetch goes through the same egress guard as a scan target
(``core/target_guard.check_target_allowed``): the allowlist is authoritative, the
cloud-metadata block is always refused, and private ranges are refused unless the
host is explicitly allowlisted. On top of that this module bounds the blast
radius — a cap on the number of documents fetched, a byte cap per document, a
per-request timeout, a recursion-depth cap, and **redirects disabled** so a
200→302 cannot bounce the fetch to a host the allowlist never approved.

Every failure degrades to leaving the ``$ref`` untouched: a blocked host, a
timeout, a non-2xx, an oversized or unparseable body, or an exhausted budget
never raises — the upload proceeds with that ref unresolved, exactly as if remote
resolution were disabled. Pure apart from the injected fetch, so tests drive it
with a fake fetcher and no network.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from copy import deepcopy
from typing import Any, TypeGuard

import yaml

from app.core.target_guard import TargetNotAllowed, check_target_allowed

#: Conservative bounds. The allowlist is the real gate; these keep a permitted
#: but hostile/looping host from turning one upload into a fetch storm.
MAX_FETCHES = 20
MAX_BYTES = 2_000_000
TIMEOUT_SECONDS = 5.0
MAX_DEPTH = 12

#: A fetcher maps an absolute http(s) URL to its body text, or None on any
#: failure. Injected so tests need no network.
Fetch = Callable[[str], "str | None"]


def inline_remote_refs(
    root: dict[str, Any],
    *,
    allowlist: list[str],
    allow_private: bool = False,
    fetch: Fetch | None = None,
    max_fetches: int = MAX_FETCHES,
) -> dict[str, Any]:
    """Return ``root`` with allowlisted remote ``$ref``s inlined.

    Disabled (returns ``root`` unchanged) when ``allowlist`` is empty. Internal
    ``#/...`` refs in ``root`` are left for the caller's internal resolver; only
    remote refs are touched here.
    """
    if not allowlist:
        return root
    resolver = _RemoteResolver(
        allowlist=allowlist,
        allow_private=allow_private,
        fetch=fetch or _httpx_fetch,
        max_fetches=max_fetches,
    )
    return resolver.inline_remote(root, 0)


def _is_remote_ref(ref: Any) -> TypeGuard[str]:
    return isinstance(ref, str) and (ref.startswith("http://") or ref.startswith("https://"))


def _split_ref(ref: str) -> tuple[str, str]:
    """``https://h/x.yaml#/a/b`` → (``https://h/x.yaml``, ``/a/b``)."""
    base, _, fragment = ref.partition("#")
    return base, fragment


def _navigate(doc: Any, pointer: str) -> Any:
    """Resolve a JSON pointer (``/a/b/0``) within ``doc``; None if it misses."""
    if pointer in ("", "/"):
        return doc
    node: Any = doc
    for raw in pointer.lstrip("/").split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict):
            if token not in node:
                return None
            node = node[token]
        elif isinstance(node, list):
            try:
                node = node[int(token)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return node


class _RemoteResolver:
    def __init__(
        self, *, allowlist: list[str], allow_private: bool, fetch: Fetch, max_fetches: int
    ) -> None:
        self._allowlist = allowlist
        self._allow_private = allow_private
        self._fetch = fetch
        self._budget = max_fetches
        #: base URL → self-contained document (internal refs already inlined), or
        #: None when that base is known-bad (blocked, unfetchable, unparseable).
        self._docs: dict[str, dict[str, Any] | None] = {}

    def inline_remote(self, node: Any, depth: int) -> Any:
        if depth > MAX_DEPTH:
            return node
        if isinstance(node, dict):
            ref = node.get("$ref")
            if _is_remote_ref(ref):
                target = self._resolve(ref, depth)
                return node if target is None else target
            return {k: self.inline_remote(v, depth + 1) for k, v in node.items()}
        if isinstance(node, list):
            return [self.inline_remote(v, depth + 1) for v in node]
        return node

    def _resolve(self, ref: str, depth: int) -> Any:
        base, pointer = _split_ref(ref)
        doc = self._document(base)
        if doc is None:
            return None
        target = _navigate(doc, pointer)
        return None if target is None else deepcopy(target)

    def _document(self, base: str) -> dict[str, Any] | None:
        if base in self._docs:
            return self._docs[base]
        if self._budget <= 0:
            self._docs[base] = None
            return None
        try:
            # allow_private=False: a spec ref never reaches a private/metadata
            # host unless the operator explicitly allowlisted it (the allowlist is
            # authoritative in the guard, and metadata is refused regardless).
            check_target_allowed(base, allow_private=self._allow_private, allowlist=self._allowlist)
        except TargetNotAllowed:
            self._docs[base] = None
            return None
        self._budget -= 1
        text = self._fetch(base)
        parsed = _parse(text) if text is not None else None
        if parsed is None:
            self._docs[base] = None
            return None
        # Resolve the fetched doc's OWN remote refs first (guarded + budgeted),
        # then its internal refs, so a pointer into it lands on self-contained
        # content — its `#/...` scope is this document, not our root spec.
        resolved = self.inline_remote(parsed, 0)
        document = _inline_internal(resolved) if isinstance(resolved, dict) else parsed
        self._docs[base] = document
        return document


def _parse(text: str) -> dict[str, Any] | None:
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError:
            return None
    return data if isinstance(data, dict) else None


def _inline_internal(doc: dict[str, Any]) -> dict[str, Any]:
    """Inline a document's own ``#/...`` refs against itself.

    Scoped to ``doc`` so a fetched schema file's cross-references resolve against
    that file, not the root spec. Cycle-safe: a ref whose target is already being
    expanded on the current path is left as a ``$ref`` rather than looped on.
    """

    def walk(node: Any, active: frozenset[str], depth: int) -> Any:
        if depth > MAX_DEPTH:
            return node
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and ref.startswith("#"):
                pointer = ref[1:]
                if pointer in active:
                    return node  # cyclic — stop, keep the ref
                target = _navigate(doc, pointer)
                if target is None:
                    return node
                return walk(deepcopy(target), active | {pointer}, depth + 1)
            return {k: walk(v, active, depth + 1) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(v, active, depth + 1) for v in node]
        return node

    result = walk(doc, frozenset(), 0)
    return result if isinstance(result, dict) else doc


def _httpx_fetch(url: str) -> str | None:
    """Fetch ``url`` with redirects disabled and a byte cap. None on any failure."""
    try:
        import httpx
    except Exception:  # noqa: BLE001 — httpx always present in the service; belt-and-braces
        return None
    try:
        with httpx.Client(follow_redirects=False, timeout=TIMEOUT_SECONDS) as client:
            with client.stream("GET", url) as resp:
                if resp.status_code >= 300:
                    return None
                chunks: list[bytes] = []
                total = 0
                for chunk in resp.iter_bytes():
                    total += len(chunk)
                    if total > MAX_BYTES:
                        return None
                    chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 — any transport/decoding error → unresolved ref
        return None
