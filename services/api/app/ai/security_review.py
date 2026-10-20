"""Bounded structural input and validated advisory output for design review."""
from __future__ import annotations

import json
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Text = Annotated[str, Field(min_length=1, max_length=1600)]
Reference = Annotated[str, Field(min_length=1, max_length=2048)]


class DesignSuggestion(BaseModel):
    model_config = ConfigDict(extra="forbid", json_schema_serialization_defaults_required=True)
    title: Annotated[str, Field(min_length=1, max_length=160)]
    priority: Literal["high", "medium", "low"]
    observation: Text
    risk: Text
    recommendation: Text
    validation: Text
    assumptions: list[Text] = Field(default_factory=list, max_length=5)
    references: list[Reference] = Field(min_length=1, max_length=8)


class SecurityReview(BaseModel):
    model_config = ConfigDict(extra="forbid", json_schema_serialization_defaults_required=True)
    status: Literal["not_requested", "running", "completed", "unavailable"] = "not_requested"
    schema_status: Literal["not_provided", "available", "unavailable"] = "not_provided"
    model: str = ""
    suggestions: list[DesignSuggestion] = Field(default_factory=list, max_length=8)


# Free prose, examples, defaults, enum values, URLs and vendor extensions are
# intentionally absent. Named maps preserve identifiers, never arbitrary values.
_MAPS = frozenset({
    "paths", "properties", "schemas", "definitions", "responses", "content",
    "securitySchemes", "securityDefinitions", "$defs", "patternProperties",
})
_OBJECTS = frozenset({
    "get", "head", "post", "put", "patch", "delete", "options", "trace",
    "components", "schema", "items", "requestBody", "additionalProperties",
    "not", "contains", "propertyNames",
})
_SCALARS = frozenset({
    "type", "format", "in", "name", "scheme", "readOnly", "writeOnly", "nullable",
    "deprecated", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
    "minLength", "maxLength", "minItems", "maxItems", "uniqueItems", "minProperties",
    "maxProperties", "multipleOf", "additionalProperties",
})
_LISTS = frozenset({"allOf", "anyOf", "oneOf", "parameters"})


def structural_spec(spec: dict) -> dict:
    """OpenAPI 3 / Swagger 2 shape only, retaining internal references."""
    def walk(node: Any, depth: int = 0) -> Any:
        if depth > 32:
            raise ValueError("spec too deep")
        if not isinstance(node, dict):
            return node if isinstance(node, bool) else {}
        out: dict[str, Any] = {}
        for key, value in node.items():
            if key in _MAPS and isinstance(value, dict):
                out[key] = {str(k): walk(v, depth + 1) for k, v in value.items()}
            elif key in _OBJECTS and isinstance(value, dict | bool):
                out[key] = walk(value, depth + 1)
            elif key in _SCALARS and isinstance(value, str | int | float | bool):
                out[key] = value
            elif key == "type" and isinstance(value, list):
                out[key] = [v for v in value if isinstance(v, str)]
            elif key in _LISTS and isinstance(value, list):
                out[key] = [walk(v, depth + 1) for v in value]
            elif key == "parameters" and isinstance(value, dict):
                out[key] = {str(k): walk(v, depth + 1) for k, v in value.items()}
            elif key == "required" and isinstance(value, bool | list):
                out[key] = (
                    value if isinstance(value, bool) else [v for v in value if isinstance(v, str)]
                )
            elif key == "security" and isinstance(value, list):
                out[key] = [
                    {str(k): [s for s in scopes if isinstance(s, str)]
                     for k, scopes in req.items() if isinstance(scopes, list)}
                    for req in value if isinstance(req, dict)
                ]
            elif key == "$ref" and isinstance(value, str):
                out[key] = value if value.startswith("#/") else "[external ref omitted]"
            elif key == "enum" and isinstance(value, list):
                out["enum_count"] = len(value)
        return out

    return dict(walk(spec))


def reference_paths(payload: dict) -> set[str]:
    refs: set[str] = set()

    def visit(value: Any, path: str) -> None:
        refs.add(path)
        if isinstance(value, dict):
            for key, child in value.items():
                visit(child, path + "/" + str(key).replace("~", "~0").replace("/", "~1"))
        elif isinstance(value, list):
            for i, child in enumerate(value):
                visit(child, f"{path}/{i}")

    for source in ("openapi", "database"):
        if payload.get(source) is not None:
            visit(payload[source], source + "#")
    return refs


def build_review_payload(spec: dict, database: dict | None, schema_status: str) -> dict:
    payload = {
        "openapi": structural_spec(spec), "database": database,
        "schema_status": schema_status,
    }
    if len(json.dumps(payload).encode()) > 96_000:
        raise ValueError("review input too large")
    return payload


def validate_suggestions(raw: Any, payload: dict) -> list[DesignSuggestion]:
    if not isinstance(raw, dict) or set(raw) != {"suggestions"}:
        raise ValueError("invalid review response")
    review = SecurityReview.model_validate({"suggestions": raw["suggestions"]})
    allowed = reference_paths(payload)
    for item in review.suggestions:
        if any(ref not in allowed or "#/" not in ref for ref in item.references):
            raise ValueError("unsupported schema reference")
    # Stable priority order; duplicate advice with identical title/references is suppressed.
    unique = {(s.title, tuple(sorted(s.references))): s for s in review.suggestions}
    return sorted(unique.values(), key=lambda s: {"high": 0, "medium": 1, "low": 2}[s.priority])


def redact_structure(value: Any, redactor: Any) -> Any:
    """Metadata names and paths can contain secrets too; redact map keys as well."""
    if isinstance(value, dict):
        return {redactor.text(str(k)): redact_structure(v, redactor) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_structure(v, redactor) for v in value]
    return redactor.value(value)
