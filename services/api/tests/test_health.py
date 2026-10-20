"""Phase-0 smoke tests: the app boots and /health answers."""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_ok() -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "examples": True}


def test_root() -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json()["service"] == "aidetector"


def test_an_unhandled_error_reaches_the_browser_as_a_json_500(client, monkeypatch):
    """A 500 must carry CORS headers, or the web can only say "Failed to fetch"."""
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.testclient import TestClient

    from app.main import app

    # The origin the middleware was built with at import (WEB_ORIGIN), not the
    # per-test settings defaults.
    cors = next(m for m in app.user_middleware if m.cls is CORSMiddleware)
    origin = cors.kwargs["allow_origins"][0]

    def broken():
        raise RuntimeError("synthetic failure")

    # A throwaway route on the real app, so the real middleware order is tested.
    monkeypatch.setattr(app.router, "routes", list(app.router.routes))
    app.router.add_api_route("/__synthetic_failure", broken)
    with TestClient(app, raise_server_exceptions=False) as raw:
        response = raw.get("/__synthetic_failure", headers={"Origin": origin})
    assert response.status_code == 500
    assert response.headers.get("access-control-allow-origin") == origin
    assert response.json()["detail"].startswith("The server hit an internal error")
    assert "synthetic" not in response.text
