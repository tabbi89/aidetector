"""Production transport keeps every request on an approved origin."""
from __future__ import annotations

import httpx
import pytest

from app.engine.transport import AsyncHttpClientBridge
from tests.vulnapp import vulnapp


def test_redirects_are_returned_without_following_the_destination():
    seen: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(
            302, headers={"Location": "http://169.254.169.254/latest/meta-data"}
        )

    with AsyncHttpClientBridge(
        "https://public.example.test", transport=httpx.MockTransport(handler)
    ) as client:
        response = client.request("GET", "/start")

    assert response.status_code == 302
    assert seen == ["https://public.example.test/start"]


def test_base_url_path_is_preserved_for_operation_paths():
    seen: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200)

    with AsyncHttpClientBridge(
        "https://api.example.test/v2", transport=httpx.MockTransport(handler)
    ) as client:
        client.request("GET", "/users")

    assert seen == ["https://api.example.test/v2/users"]


def test_every_resolved_request_runs_the_egress_validator():
    checked: list[str] = []

    def validate(url: str) -> None:
        checked.append(url)
        if "blocked.example" in url:
            raise ValueError("blocked")

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    with AsyncHttpClientBridge(
        "https://api.example.test",
        transport=httpx.MockTransport(handler),
        url_validator=validate,
    ) as client:
        client.request("GET", "/users")
        with pytest.raises(ValueError, match="blocked"):
            client.request("GET", "https://blocked.example/path")

    assert checked == [
        "https://api.example.test/users",
        "https://blocked.example/path",
    ]


def test_async_transport_bridge_serves_in_process_app():
    import httpx

    from app.engine.transport import AsyncHttpClientBridge

    transport = httpx.ASGITransport(app=vulnapp)
    bridge = AsyncHttpClientBridge(
        "http://testserver", transport=transport, requests_per_second=100
    )
    try:
        r = bridge.request("GET", "/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"
        for _ in range(3):  # loop stays alive across calls
            assert bridge.request("GET", "/health").status_code == 200
    finally:
        bridge.close()
