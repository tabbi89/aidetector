"""Held-out paired workflow and expression targets; no production dependencies."""

import re

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse


def target(*, vulnerable: bool, expression_mode: str = "compute"):
    app = FastAPI()
    rows: dict[str, dict] = {}
    counter = 0
    project_seq = item_seq = batch_seq = record_seq = 0

    @app.get("/preview")
    def preview(template: str = ""):
        match = re.fullmatch(r"\{\{(\d+)\*(\d+)\}\}", template)
        if expression_mode == "reject":
            return JSONResponse({"error": "invalid input"}, status_code=422)
        if expression_mode == "static":
            return PlainTextResponse("100000")
        if vulnerable and match and expression_mode == "compute":
            return PlainTextResponse(str(int(match[1]) * int(match[2])))
        return PlainTextResponse(template)

    @app.post("/drafts")
    async def create(request: Request):
        nonlocal counter
        if request.headers.get("authorization") != "owner-token":
            return JSONResponse({}, status_code=403)
        counter += 1
        rows[str(counter)] = {"approved": False, "count": 0}
        return {"id": str(counter)}

    @app.get("/drafts/{id}")
    def read(id: str):
        return rows[id]

    @app.post("/drafts/{id}/approve")
    def approve(id: str):
        rows[id]["approved"] = True
        return {"ok": True}

    @app.post("/drafts/{id}/settle")
    async def settle(id: str, request: Request):
        row = rows[id]
        if not vulnerable and (
            not row["approved"]
            or row["count"]
            or request.headers.get("authorization") != "owner-token"
        ):
            return JSONResponse({}, status_code=403)
        row["count"] += 1
        return {"ok": True}

    @app.delete("/drafts/{id}")
    def delete(id: str):
        rows.pop(id, None)
        return {"ok": True}

    # ---- nested ownership: a child object under a parent collection ----------

    @app.post("/projects")
    def create_project(request: Request):
        nonlocal project_seq
        if request.headers.get("authorization") != "owner-token":
            return JSONResponse({}, status_code=403)
        project_seq += 1
        project_id = f"p{project_seq}"
        rows[f"project:{project_id}"] = {"owner": "owner"}
        return {"id": project_id}

    @app.post("/projects/{project_id}/items")
    def create_project_item(project_id: str, request: Request):
        nonlocal item_seq
        if request.headers.get("authorization") != "owner-token":
            return JSONResponse({}, status_code=403)
        if f"project:{project_id}" not in rows:
            return JSONResponse({}, status_code=404)
        item_seq += 1
        item_id = f"i{item_seq}"
        rows[f"item:{item_id}"] = {
            "project": project_id,
            "published": False,
        }
        return {"id": item_id}

    @app.post("/projects/{project_id}/items/{item_id}/publish")
    def publish_project_item(project_id: str, item_id: str, request: Request):
        item = rows.get(f"item:{item_id}")
        if item is None or item["project"] != project_id:
            return JSONResponse({}, status_code=404)
        if not vulnerable and request.headers.get("authorization") != "owner-token":
            return JSONResponse({}, status_code=403)
        item["published"] = True
        return {"ok": True}

    @app.get("/projects/{project_id}/items/{item_id}")
    def read_project_item(project_id: str, item_id: str):
        item = rows.get(f"item:{item_id}")
        if item is None or item["project"] != project_id:
            return JSONResponse({}, status_code=404)
        return {"published": item["published"]}

    @app.delete("/projects/{project_id}/items/{item_id}")
    def delete_project_item(project_id: str, item_id: str):
        rows.pop(f"item:{item_id}", None)
        return {"ok": True}

    @app.delete("/projects/{project_id}")
    def delete_project(project_id: str):
        rows.pop(f"project:{project_id}", None)
        return {"ok": True}

    # ---- bulk approval: a batch transition that must not be replayed ---------

    @app.post("/batches")
    def create_batch(request: Request):
        nonlocal batch_seq
        if request.headers.get("authorization") != "owner-token":
            return JSONResponse({}, status_code=403)
        batch_seq += 1
        batch_id = f"b{batch_seq}"
        rows[f"batch:{batch_id}"] = {"approved": 0, "settled": 0, "effects": 0}
        return {"id": batch_id}

    @app.post("/batches/{batch_id}/approve")
    def approve_batch(batch_id: str, request: Request):
        batch = rows.get(f"batch:{batch_id}")
        if batch is None:
            return JSONResponse({}, status_code=404)
        if not vulnerable and (
            request.headers.get("authorization") != "owner-token"
            or batch["approved"]
            or batch["settled"]
        ):
            return JSONResponse({}, status_code=403)
        batch["approved"] += 1
        batch["effects"] += 1
        return {"ok": True}

    @app.post("/batches/{batch_id}/settle")
    def settle_batch(batch_id: str, request: Request):
        batch = rows.get(f"batch:{batch_id}")
        if batch is None:
            return JSONResponse({}, status_code=404)
        if not vulnerable and (
            request.headers.get("authorization") != "owner-token"
            or batch["approved"] != 1
            or batch["settled"]
        ):
            return JSONResponse({}, status_code=403)
        batch["settled"] += 1
        batch["effects"] += 1
        return {"ok": True}

    @app.get("/batches/{batch_id}")
    def read_batch(batch_id: str):
        batch = rows.get(f"batch:{batch_id}")
        if batch is None:
            return JSONResponse({}, status_code=404)
        return {"effects": batch["effects"]}

    @app.delete("/batches/{batch_id}")
    def delete_batch(batch_id: str):
        rows.pop(f"batch:{batch_id}", None)
        return {"ok": True}

    # ---- soft delete / restore: a terminal restore must be one-shot ----------

    @app.post("/records")
    def create_record(request: Request):
        nonlocal record_seq
        if request.headers.get("authorization") != "owner-token":
            return JSONResponse({}, status_code=403)
        record_seq += 1
        record_id = f"r{record_seq}"
        rows[f"record:{record_id}"] = {"archived": False, "restored": 0}
        return {"id": record_id}

    @app.post("/records/{record_id}/archive")
    def archive_record(record_id: str, request: Request):
        record = rows.get(f"record:{record_id}")
        if record is None:
            return JSONResponse({}, status_code=404)
        if not vulnerable and (
            request.headers.get("authorization") != "owner-token"
            or record["archived"]
            or record["restored"]
        ):
            return JSONResponse({}, status_code=403)
        record["archived"] = True
        return {"ok": True}

    @app.post("/records/{record_id}/restore")
    def restore_record(record_id: str, request: Request):
        record = rows.get(f"record:{record_id}")
        if record is None:
            return JSONResponse({}, status_code=404)
        if not vulnerable and (
            request.headers.get("authorization") != "owner-token"
            or not record["archived"]
            or record["restored"]
        ):
            return JSONResponse({}, status_code=403)
        record["archived"] = False
        record["restored"] += 1
        return {"ok": True}

    @app.get("/records/{record_id}")
    def read_record(record_id: str):
        record = rows.get(f"record:{record_id}")
        if record is None:
            return JSONResponse({}, status_code=404)
        return {"restored": record["restored"]}

    @app.delete("/records/{record_id}")
    def delete_record(record_id: str):
        rows.pop(f"record:{record_id}", None)
        return {"ok": True}

    return app, rows


def _step(method: str, path: str, **kwargs) -> dict:
    return {"method": method, "path": path, "identity": "owner", **kwargs}


def _approval_workflow() -> dict:
    return {
        "name": "approval",
        "setup": [_step("POST", "/drafts", save={"id": "/id"})],
        "transitions": [
            _step("POST", "/drafts/{id}/approve"),
            _step("POST", "/drafts/{id}/settle"),
        ],
        "observe": _step("GET", "/drafts/{id}"),
        "pointer": "/count",
        "expected": 1,
        "cleanup": [_step("DELETE", "/drafts/{id}")],
        "tests": [
            {"kind": "skip", "index": 0, "forbidden": 1},
            {"kind": "replay", "index": 1, "forbidden": 2},
            {"kind": "cross_identity", "index": 1, "identity": "peer", "forbidden": 1},
        ],
    }


def _nested_ownership_workflow() -> dict:
    return {
        "name": "nested-ownership",
        "setup": [
            _step("POST", "/projects", save={"project_id": "/id"}),
            _step(
                "POST",
                "/projects/{project_id}/items",
                save={"item_id": "/id"},
            ),
        ],
        "transitions": [
            _step("POST", "/projects/{project_id}/items/{item_id}/publish"),
        ],
        "observe": _step("GET", "/projects/{project_id}/items/{item_id}"),
        "pointer": "/published",
        "expected": True,
        "cleanup": [
            # Reversed at teardown: the child goes before its parent.
            _step("DELETE", "/projects/{project_id}"),
            _step("DELETE", "/projects/{project_id}/items/{item_id}"),
        ],
        "tests": [
            {
                "kind": "cross_identity",
                "index": 0,
                "identity": "peer",
                "forbidden": True,
            }
        ],
    }


def _bulk_approval_workflow() -> dict:
    return {
        "name": "bulk-approval",
        "setup": [_step("POST", "/batches", save={"batch_id": "/id"})],
        "transitions": [
            _step("POST", "/batches/{batch_id}/approve"),
            _step("POST", "/batches/{batch_id}/settle"),
        ],
        "observe": _step("GET", "/batches/{batch_id}"),
        "pointer": "/effects",
        "expected": 2,
        "cleanup": [_step("DELETE", "/batches/{batch_id}")],
        "tests": [
            {"kind": "skip", "index": 0, "forbidden": 1},
            {"kind": "replay", "index": 0, "forbidden": 3},
            {"kind": "cross_identity", "index": 1, "identity": "peer", "forbidden": 2},
        ],
    }


def _soft_delete_workflow() -> dict:
    return {
        "name": "archive-restore",
        "setup": [_step("POST", "/records", save={"record_id": "/id"})],
        "transitions": [
            _step("POST", "/records/{record_id}/archive"),
            _step("POST", "/records/{record_id}/restore"),
        ],
        "observe": _step("GET", "/records/{record_id}"),
        "pointer": "/restored",
        "expected": 1,
        "cleanup": [_step("DELETE", "/records/{record_id}")],
        "tests": [
            {"kind": "skip", "index": 0, "forbidden": 1},
            {"kind": "replay", "index": 1, "forbidden": 2},
            {"kind": "cross_identity", "index": 1, "identity": "peer", "forbidden": 1},
        ],
    }


def workflow_spec():
    """The original approval workflow, kept for the focused workflow tests."""
    return {"x-aidetector-workflows": [_approval_workflow()]}


def expanded_workflow_specs():
    """The four-workflow benchmark corpus: approval, nested, bulk, restore."""
    return {
        "x-aidetector-workflows": [
            _approval_workflow(),
            _nested_ownership_workflow(),
            _bulk_approval_workflow(),
            _soft_delete_workflow(),
        ]
    }
