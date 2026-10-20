"""Workspace roles and the actions they may perform.

Pure vocabulary: no SQLAlchemy, FastAPI, engine or model imports. The API layer
maps database rows onto :class:`Role`; routes ask :func:`can` rather than
comparing role strings inline, so a new action has one place to be granted.
"""
from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class Action(str, Enum):
    read = "read"
    scan_write = "scan_write"
    scan_delete = "scan_delete"
    collaborate = "collaborate"
    workspace_admin = "workspace_admin"


_GRANTS: dict[Role, frozenset[Action]] = {
    Role.viewer: frozenset({Action.read}),
    Role.analyst: frozenset(
        {Action.read, Action.scan_write, Action.collaborate}
    ),
    Role.admin: frozenset(Action),
}


def can(role: Role, action: Action) -> bool:
    return action in _GRANTS[role]
