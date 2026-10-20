"""Stateless MCP JSON transport exposing only authorized retained metadata."""

from __future__ import annotations

import json
import uuid
from datetime import date
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import require_api_key
from app.core.config import settings
from app.core.db import get_db
from app.models.monitoring import EvidenceSource, MonitoringRun
from app.monitoring import service, sources
from app.monitoring.context import readable_context

router = APIRouter(prefix="/monitoring/mcp", tags=["monitoring MCP"])
TOOLS = {
    "get_openapi_contract": "Read pinned route metadata for a bound monitor.",
    "get_code_context": "Read pinned repository route metadata, never source code.",
    "get_database_schema": "Read the bound schema-only metadata snapshot, never database rows.",
    "aggregate_waf_behavior": "Read one completed day of retained value-free aggregates.",
}


class Arguments(BaseModel):
    model_config = ConfigDict(extra="forbid")
    monitor_id: uuid.UUID
    observation_date: date | None = None


class Rpc(BaseModel):
    model_config = ConfigDict(extra="forbid")
    jsonrpc: Literal["2.0"]
    id: str | int | None = None
    method: str = Field(max_length=80)
    params: dict = Field(default_factory=dict, max_length=8)


@router.post("")
def mcp(
    body: Rpc,
    request: Request,
    tenant_id: str = Depends(require_api_key),
    db: Session = Depends(get_db),
):
    if not settings.api_key_set():
        raise HTTPException(403, "MCP requires configured API authentication")
    if request.headers.get("origin") not in {None, "http://localhost:3000"}:
        raise HTTPException(403, "origin not allowed")
    if body.id is None:
        return Response(status_code=202)
    result: dict
    if body.method == "initialize":
        result = {
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "aidetector-monitoring", "version": "1"},
        }
    elif body.method == "tools/list":
        result = {
            "tools": [
                {
                    "name": name,
                    "description": description,
                    "inputSchema": Arguments.model_json_schema(),
                    "annotations": {
                        "readOnlyHint": True,
                        "destructiveHint": False,
                        "openWorldHint": False,
                    },
                }
                for name, description in TOOLS.items()
            ]
        }
    elif body.method == "tools/call":
        try:
            if set(body.params) != {"name", "arguments"} or body.params.get("name") not in TOOLS:
                raise ValueError("unsupported tool")
            args = Arguments.model_validate(body.params["arguments"])
            monitor = service.get_monitor(db, args.monitor_id, tenant_id)
            if monitor is None:
                raise HTTPException(404, "monitor not found")
            context = readable_context(db, monitor)
            name = body.params["name"]
            if name == "aggregate_waf_behavior":
                row = db.scalar(
                    select(MonitoringRun).where(
                        MonitoringRun.monitor_id == monitor.id,
                        MonitoringRun.observation_date == args.observation_date,
                    )
                )
                value = (
                    {"state": row.state, "metrics": row.metrics} if row else {"state": "no_data"}
                )
            else:
                key = {
                    "get_openapi_contract": "routes",
                    "get_code_context": "repository",
                    "get_database_schema": "database",
                }[name]
                value = context.get(key, {})
            encoded = json.dumps(value, default=str)
            if len(encoded.encode()) > 128_000:
                raise ValueError("output limit")
            for source_id in monitor.source_ids:
                source = db.get(EvidenceSource, source_id)
                if source:
                    if source.status == "revoked":
                        raise HTTPException(409, "source revoked")
                    sources.audit(db, source, "mcp_read", "complete")
            db.commit()
            result = {"content": [{"type": "text", "text": encoded}], "isError": False}
        except (ValueError, HTTPException):
            db.rollback()
            result = {
                "content": [{"type": "text", "text": "evidence unavailable or request invalid"}],
                "isError": True,
            }
    else:
        return {
            "jsonrpc": "2.0",
            "id": body.id,
            "error": {"code": -32601, "message": "method not found"},
        }
    return {"jsonrpc": "2.0", "id": body.id, "result": result}
