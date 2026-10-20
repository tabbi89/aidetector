"""Spec design review (premium, A06): design-level risks visible in the OpenAPI spec.

A black-box scanner cannot *detect* insecure design — A06 is a design-level risk.
But the spec is the design artifact, and the scanner already parses it. This check
reads the operations and schemas (no secrets, no values) and flags six
design-level risks that are visible there and invisible to the behavioral engine:

1. a sensitive operation with no declared authentication;
2. credential material declared in a query/path parameter (secrets in the URL);
3. a server-owned field (role, is_admin, owner…) declared in a client request body.
4. no declared error response contract;
5. no declared rate-limit response or response headers;
6. a success response whose collection schema has no ``maxItems`` bound.

All six are static design signals, so findings are heuristic — the spec may be
stale, and a declared flaw is not yet an exploited one. Premium: no-ops unless
``premium: true``.
"""
from __future__ import annotations

from typing import Any

from app.domain.enums import Confidence, Severity
from app.domain.privilege import is_privileged
from app.engine.base import EngineFinding, ScanContext, TargetOperation
from app.specs.parser import spec_operation

#: Secret-bearing parameter names that should never be carried in a URL.
_SECRET_PARAM_NAMES = (
    "apikey", "api_key", "key", "token", "password", "secret",
    "authorization", "access_token", "client_secret", "credential",
    "passwd", "pwd", "auth",
)

#: Field names that name server-owned state (privilege/ownership/state), which
#: a client request schema should not declare writable.
_SERVER_OWNED_FIELDS = (
    "role", "roles", "is_admin", "admin", "permissions", "scopes",
    "owner", "owner_id", "tenant_id", "created_by", "balance", "credits",
    "verified", "approved", "is_verified", "is_active", "status",
)

#: Path tokens that mark an operation as sensitive for the "no auth" signal.
#: Deliberately narrow — ``login``/``signup`` are public by design, so excluded.
_SENSITIVE_PATH_TOKENS = (
    "admin", "reset", "password", "payment", "secret", "credential",
    "token", "apikey", "api_key",
)

_COLLECTION_FIELDS = frozenset(
    {"data", "edges", "entries", "items", "nodes", "records", "results", "values"}
)
_RATE_LIMIT_HEADERS = frozenset(
    {
        "ratelimit-limit",
        "ratelimit-policy",
        "ratelimit-remaining",
        "retry-after",
        "x-rate-limit-limit",
        "x-rate-limit-remaining",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
    }
)


def _norm(name: str) -> str:
    """Comparison form: lowercase alphanumerics only (``api_key`` ≡ ``apikey``)."""
    return "".join(ch for ch in name.lower() if ch.isalnum())


def secret_param(param: dict[str, Any]) -> bool:
    """A credential-bearing parameter declared in the query or path."""
    if param.get("in") not in ("query", "path"):
        return False
    return _norm(str(param.get("name", ""))) in {_norm(n) for n in _SECRET_PARAM_NAMES}


def server_owned_field(name: str) -> bool:
    """A request-body field whose name means server-owned state."""
    return _norm(name) in {_norm(n) for n in _SERVER_OWNED_FIELDS}


def sensitive(op: TargetOperation) -> bool:
    """An operation a design review should treat as sensitive."""
    if is_privileged(op.path, op.auth_scope):
        return True
    return any(tok in op.path.lower() for tok in _SENSITIVE_PATH_TOKENS)


def _follow_ref(value: Any, root: dict[str, Any], depth: int = 0) -> Any:
    """Resolve bounded local refs only; remote refs remain inert by policy."""
    seen: set[str] = set()
    while isinstance(value, dict) and depth < 10:
        ref = value.get("$ref")
        if not isinstance(ref, str) or not ref.startswith("#/") or ref in seen:
            break
        seen.add(ref)
        node: Any = root
        for part in ref[2:].split("/"):
            if not isinstance(node, dict):
                return value
            node = node.get(part.replace("~1", "/").replace("~0", "~"))
        value = node
        depth += 1
    return value


def _requires_auth(
    spec: dict[str, Any] | None, op: TargetOperation, target_base_url: str | None = None
) -> bool:
    """Return effective auth, respecting inheritance and anonymous alternatives."""
    raw = spec_operation(spec, op.method, op.path, target_base_url)
    if raw is None or not isinstance(spec, dict):
        return bool(op.auth_scope)
    security = raw["security"] if "security" in raw else spec.get("security")
    if not isinstance(security, list) or not security:
        return False
    # Security Requirement Objects are alternatives. An empty object explicitly
    # permits anonymous access even when authenticated alternatives also exist.
    return all(isinstance(requirement, dict) and bool(requirement) for requirement in security)


def _responses(
    spec: dict[str, Any], raw: dict[str, Any]
) -> list[tuple[str, dict[str, Any]]]:
    declared = raw.get("responses")
    if not isinstance(declared, dict):
        return []
    output: list[tuple[str, dict[str, Any]]] = []
    for status, response in declared.items():
        resolved = _follow_ref(response, spec)
        if isinstance(resolved, dict):
            output.append((str(status).lower(), resolved))
    return output


def _has_error_contract(responses: list[tuple[str, dict[str, Any]]]) -> bool:
    return any(status == "default" or status.startswith(("4", "5")) for status, _ in responses)


def _has_rate_limit_contract(responses: list[tuple[str, dict[str, Any]]]) -> bool:
    if any(status == "429" for status, _ in responses):
        return True
    for _, response in responses:
        headers = response.get("headers")
        if isinstance(headers, dict) and any(
            str(name).lower() in _RATE_LIMIT_HEADERS for name in headers
        ):
            return True
    return False


def _response_schemas(
    spec: dict[str, Any], responses: list[tuple[str, dict[str, Any]]]
) -> list[Any]:
    schemas: list[Any] = []
    for status, response in responses:
        if not status.startswith("2"):
            continue
        content = response.get("content")
        if isinstance(content, dict):
            for content_type, media in content.items():
                if "json" in str(content_type).lower() and isinstance(media, dict):
                    schemas.append(_follow_ref(media.get("schema"), spec))
        elif "schema" in response:  # Swagger 2
            schemas.append(_follow_ref(response.get("schema"), spec))
    return schemas


def _unbounded_collection(
    schema: Any, root: dict[str, Any], depth: int = 0
) -> str | None:
    """Return a stable structural location for a top-level unbounded collection."""
    if depth > 8:
        return None
    schema = _follow_ref(schema, root, depth)
    if not isinstance(schema, dict):
        return None
    if schema.get("type") == "array" or "items" in schema:
        maximum = schema.get("maxItems")
        return None if isinstance(maximum, int) and maximum >= 0 else "response"
    for composition in ("allOf", "oneOf", "anyOf"):
        members = schema.get(composition)
        if isinstance(members, list):
            for member in members[:16]:
                location = _unbounded_collection(member, root, depth + 1)
                if location:
                    return location
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for name in sorted(properties, key=str)[:64]:
            if str(name).lower() not in _COLLECTION_FIELDS:
                continue
            child = _follow_ref(properties[name], root, depth + 1)
            if isinstance(child, dict) and (
                child.get("type") == "array" or "items" in child
            ):
                maximum = child.get("maxItems")
                if not (isinstance(maximum, int) and maximum >= 0):
                    return f"response.{name}"
    return None


class DesignReviewCheck:
    key = "design_review"
    #: Premium: reserved for the paid tier, off unless ``premium: true``.
    premium = True

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        if not ctx.premium:
            return []
        findings: list[EngineFinding] = []
        for op in ctx.operations:
            no_auth = self._no_auth(ctx, op)
            if no_auth is not None:
                findings.append(no_auth)
            for param in op.params:
                if secret_param(param):
                    findings.append(self._secret_in_url(op, param))
                if param.get("in") == "body" and server_owned_field(str(param.get("name", ""))):
                    findings.append(self._server_owned_field(op, param))
            findings.extend(self._contract_findings(ctx, op))
        return findings

    def _no_auth(self, ctx: ScanContext, op: TargetOperation) -> EngineFinding | None:
        if not sensitive(op) or _requires_auth(ctx.spec, op, ctx.base_url):
            return None
        return EngineFinding(
            check=self.key,
            owasp_id="API2:2023",
            severity=Severity.medium,
            confidence=Confidence.heuristic,
            title=f"Sensitive operation with no declared auth: {op.method} {op.path}"[:255],
            description=(
                f"{op.method} {op.path} looks sensitive but the spec declares no "
                "authentication for it. Review the design: an admin, password or "
                "payment operation that is public is a design-level access-control "
                "risk."
            ),
            evidence={"method": op.method, "route": op.path, "signal": "no_auth"},
            operation_id=op.id,
        )

    def _contract_findings(
        self, ctx: ScanContext, op: TargetOperation
    ) -> list[EngineFinding]:
        spec = ctx.spec
        raw = spec_operation(spec, op.method, op.path, ctx.base_url)
        if not isinstance(spec, dict) or raw is None:
            return []
        responses = _responses(spec, raw)
        findings: list[EngineFinding] = []
        if not _has_error_contract(responses):
            findings.append(
                self._contract_finding(
                    op,
                    signal="missing_error_contract",
                    owasp_id="API8:2023",
                    title="Missing error response contract",
                    description=(
                        "The specification declares no 4xx, 5xx or default response. "
                        "Clients cannot distinguish documented failures from drift, and "
                        "reviewers cannot assess the error body's information exposure."
                    ),
                )
            )
        if not _has_rate_limit_contract(responses):
            findings.append(
                self._contract_finding(
                    op,
                    signal="missing_rate_limit_contract",
                    owasp_id="API4:2023",
                    title="Undocumented rate-limit behavior",
                    description=(
                        "The specification declares neither a 429 response nor standard "
                        "rate-limit response headers. This does not prove throttling is "
                        "absent, but leaves clients without a retry/backoff contract."
                    ),
                )
            )
        for schema in _response_schemas(spec, responses):
            location = _unbounded_collection(schema, spec)
            if location:
                findings.append(
                    self._contract_finding(
                        op,
                        signal="unbounded_collection",
                        owasp_id="API4:2023",
                        title="Unbounded collection response schema",
                        description=(
                            "The success response declares a collection without a "
                            "maxItems constraint. This is a design-review lead: runtime "
                            "pagination may exist, but the contract does not bound it."
                        ),
                        location=location,
                    )
                )
                break
        return findings

    def _contract_finding(
        self,
        op: TargetOperation,
        *,
        signal: str,
        owasp_id: str,
        title: str,
        description: str,
        location: str | None = None,
    ) -> EngineFinding:
        evidence = {
            "method": op.method,
            "route": op.path,
            # ``issue`` participates in the established fingerprint policy, so
            # the three rules cannot collide without changing existing hashes.
            "issue": signal,
            "signal": signal,
        }
        if location:
            evidence["location"] = location
        return EngineFinding(
            check=self.key,
            owasp_id=owasp_id,
            severity=Severity.low,
            confidence=Confidence.heuristic,
            title=f"{title}: {op.method} {op.path}"[:255],
            description=f"{op.method} {op.path}: {description}",
            evidence=evidence,
            operation_id=op.id,
        )

    def _secret_in_url(self, op: TargetOperation, param: dict[str, Any]) -> EngineFinding:
        return EngineFinding(
            check=self.key,
            owasp_id="API2:2023",
            severity=Severity.medium,
            confidence=Confidence.heuristic,
            title=f"Credential in URL parameter '{param['name']}' on {op.method} {op.path}"[:255],
            description=(
                f"{op.method} {op.path} declares credential material "
                f"('{param['name']}') in the {param['in']} string. Secrets in URLs "
                "land in logs and history; move them to a header or the request body."
            ),
            evidence={
                "method": op.method,
                "route": op.path,
                "param": param["name"],
                "signal": "secret_in_url",
            },
            operation_id=op.id,
        )

    def _server_owned_field(self, op: TargetOperation, param: dict[str, Any]) -> EngineFinding:
        return EngineFinding(
            check=self.key,
            owasp_id="API6:2023",
            severity=Severity.high,
            confidence=Confidence.heuristic,
            title=f"Server-owned field '{param['name']}' on {op.method} {op.path}"[:255],
            description=(
                f"{op.method} {op.path} declares '{param['name']}' client-writable, "
                "but that field names server-owned state (privilege, ownership, "
                "balance). The client request schema should not expose it."
            ),
            evidence={
                "method": op.method,
                "route": op.path,
                "field": param["name"],
                "signal": "server_owned_field",
            },
            operation_id=op.id,
        )
