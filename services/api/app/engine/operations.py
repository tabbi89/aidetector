"""Target operations, decoupled from the ORM row."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TargetOperation:
    id: str | None
    method: str
    path: str
    params: list[dict[str, Any]] = field(default_factory=list)
    auth_scope: str | None = None

    @property
    def path_params(self) -> list[str]:
        return [p["name"] for p in self.params if p.get("in") == "path" and p.get("name")]

    @property
    def query_params(self) -> list[str]:
        return [p["name"] for p in self.params if p.get("in") == "query" and p.get("name")]

    @property
    def body_params(self) -> list[str]:
        """Top-level JSON request-body field names (``in: "body"``).

        Surfaced by the spec parser from an OpenAPI ``requestBody`` /
        Swagger ``in: body`` schema so body-sink fuzzing has targets.
        """
        return [p["name"] for p in self.params if p.get("in") == "body" and p.get("name")]


_PATH_VAR = re.compile(r"\{([^}]+)\}")


def render_path(path: str, values: dict[str, Any]) -> str:
    """Substitute {name} path templates with concrete values (default '1')."""
    return _PATH_VAR.sub(lambda m: str(values.get(m.group(1), "1")), path)
