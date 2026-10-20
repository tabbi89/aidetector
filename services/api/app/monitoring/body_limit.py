"""Bound monitoring input before FastAPI/Pydantic parses it, including secrets."""

from starlette.responses import JSONResponse

from app.monitoring.connectors import MAX_SNAPSHOT_BYTES


class MonitoringBodyLimit:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope.get("path", "").startswith("/monitoring"):
            return await self.app(scope, receive, send)
        messages = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            total += len(message.get("body", b""))
            if total > MAX_SNAPSHOT_BYTES:
                return await JSONResponse(
                    {"detail": "monitoring input exceeds byte limit"}, status_code=413
                )(scope, receive, send)
            messages.append(message)
            if not message.get("more_body", False):
                break

        async def replay():
            if messages:
                return messages.pop(0)
            return await receive()

        await self.app(scope, replay, send)
