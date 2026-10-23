"""FastAPI application entrypoint."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import (
    auth,
    domains,
    health,
    notifications,
    ops,
    runner,
    scans,
    schema_context,
    specs,
    workspace,
)
from app.core.config import settings

log = logging.getLogger("aidetector.api")

app = FastAPI(
    title="runpentests API",
    version="0.1.0",
    description="OpenAPI-driven API security scanner.",
)

class InternalErrorResponse:
    """Answer an unhandled error with a JSON 500 from *inside* CORS.

    Starlette's own error page is produced by the outermost middleware, past
    CORS, so the browser saw a 500 as a CORS failure and the UI could only say
    "Failed to fetch" — for a missing migration as much as for a dead server.
    The error is still logged in full; the response names nothing internal.
    """

    def __init__(self, inner) -> None:
        self.inner = inner

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.inner(scope, receive, send)
            return
        started = False

        async def tracked(message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.inner(scope, receive, tracked)
        except Exception:
            if started:
                raise
            log.exception("unhandled error on %s %s", scope.get("method"), scope.get("path"))
            response = JSONResponse(
                status_code=500,
                content={"detail": "The server hit an internal error. It has been logged."},
            )
            await response(scope, receive, send)


# Added before CORS, so it sits inside it and its 500s carry CORS headers.
app.add_middleware(InternalErrorResponse)

# The Next.js dev server talks to this API from the browser.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.web_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    # Downloads go through fetch (so they carry the API key); the browser only
    # lets script read the server's filename when this header is exposed.
    expose_headers=["Content-Disposition"],
)

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(specs.router)
app.include_router(workspace.router)
app.include_router(notifications.router)
app.include_router(domains.router)
app.include_router(ops.router)
app.include_router(runner.router)
app.include_router(schema_context.router)


@app.get("/")
def root() -> dict[str, str]:
    return {"service": "aidetector", "env": settings.env, "docs": "/docs"}


@app.exception_handler(RequestValidationError)
async def safe_connection_validation(request: Request, exc: RequestValidationError):
    # Pydantic's input echo can expose password/DSN values on invalid requests.
    if request.url.path.startswith("/auth/"):
        return JSONResponse(
            status_code=422,
            content={"detail": _auth_validation_detail(exc)},
        )
    if "/database-connection" in request.url.path:
        return JSONResponse(
            status_code=422,
            content={
                "detail": "invalid database connection request"
            },
        )
    return await request_validation_exception_handler(request, exc)


def _auth_validation_detail(exc: RequestValidationError) -> list[dict[str, object]]:
    """Field locations and messages only — never the submitted input, which
    for these routes is a password."""
    return [
        {"loc": list(err.get("loc", ())), "msg": err.get("msg", ""), "type": err.get("type", "")}
        for err in exc.errors()
    ]
