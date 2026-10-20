"""GraphQL introspection (premium): is the schema exposed to any caller?

GraphQL's introspection system is a development tool that reveals the entire
API surface — types, fields, arguments — when left enabled in production. This is
the first, self-contained slice of GraphQL scanning: it sends a standard
introspection query and flags when the response returns a schema. The deeper
GraphQL work (running the engine's authorization and injection checks against
resolved queries) builds on the schema this check confirms is reachable.

Premium: off unless ``premium: true``.
"""
from __future__ import annotations

import json

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding, ScanContext, TargetOperation, render_path
from app.engine.resource_map import path_values

_INTROSPECTION_QUERY = "{ __schema { queryType { name } } }"


def _graphql_targets(ctx: ScanContext) -> list[TargetOperation]:
    """Operations that look like a GraphQL endpoint, plus the conventional path."""
    targets = [op for op in ctx.operations if "graphql" in op.path.lower()]
    if not targets:
        # The conventional single endpoint.
        targets.append(TargetOperation(id=None, method="POST", path="/graphql", params=[]))
    return targets


def _is_introspection(body: str) -> bool:
    """Whether a GraphQL response body discloses a schema via introspection."""
    try:
        data = json.loads(body)
    except (TypeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    return "__schema" in data.get("data", {}) or "__schema" in data


class GraphQLIntrospectionCheck:
    key = "graphql_introspection"
    #: Premium: reserved for the paid tier, off unless ``premium: true``.
    premium = True

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        if not ctx.premium:
            return []
        findings: list[EngineFinding] = []
        for op in _graphql_targets(ctx):
            path = render_path(op.path, path_values(op, ctx.resource_ids))
            # Introspection available only to an authenticated/privileged
            # identity is not public schema exposure. Prove the anonymous
            # boundary first, and make the finding's "any caller" claim true.
            r = ctx.probe.send(
                "POST", path, headers={}, json={"query": _INTROSPECTION_QUERY}
            )
            if r is None:
                return findings  # budget spent
            if not _is_introspection(r.text or ""):
                continue
            findings.append(
                EngineFinding(
                    check=self.key,
                    confidence=Confidence.verified,
                    owasp_id="API8:2023",
                    severity=Severity.medium,
                    title=f"GraphQL introspection enabled on POST {op.path}",
                    description=(
                        f"POST {op.path} answered a standard introspection query with "
                        "the schema, so any caller can enumerate the entire API "
                        "surface. Disable introspection outside development, or gate "
                        "it behind authentication."
                    ),
                    evidence={"method": "POST", "route": op.path, "introspection": True},
                    operation_id=op.id,
                )
            )
        return findings
