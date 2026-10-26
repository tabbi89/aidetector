"""One shared async HTTP transport exposed through the engine's sync client API.

Checks remain small synchronous units, but production requests are submitted to
one ``httpx.AsyncClient`` running on a dedicated event loop. Multiple checks can
therefore execute concurrently while a single per-host leaky bucket bounds the
actual outbound rate.
"""
from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from concurrent.futures import Future
from typing import Any
from urllib.parse import urljoin

import httpx
from aiolimiter import AsyncLimiter


class AsyncHttpClientBridge:
    """Thread-safe sync facade over one rate-limited ``httpx.AsyncClient``."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 10.0,
        requests_per_second: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        url_validator: Callable[[str], None] | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/") + "/"
        self._timeout = timeout
        self._rate = max(0.1, requests_per_second)
        # Injectable transport lets tests bind an in-process ASGI app (no network),
        # exactly like the sync engine binds a Starlette TestClient.
        self._transport = transport
        self._url_validator = url_validator
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._client: httpx.AsyncClient | None = None
        self._limiter: AsyncLimiter | None = None
        self._startup_error: BaseException | None = None
        self._thread = threading.Thread(
            target=self._serve,
            name="runpentests-http",
            daemon=True,
        )
        self._thread.start()
        self._ready.wait(timeout=10)
        if self._startup_error is not None:
            raise RuntimeError("async HTTP transport failed to start") from self._startup_error
        if self._client is None:
            raise RuntimeError("async HTTP transport did not start")

    def _serve(self) -> None:
        asyncio.set_event_loop(self._loop)
        try:
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                timeout=self._timeout,
                verify=False,  # scanner targets commonly use lab/self-signed TLS
                # Redirect destinations have not passed the target egress
                # policy. Checks can inspect a 3xx directly; they must never
                # turn a permitted target into an open redirect to metadata.
                follow_redirects=False,
                transport=self._transport,
            )
            self._limiter = AsyncLimiter(self._rate, 1.0)
        except BaseException as exc:  # pragma: no cover - constructor failures are rare
            self._startup_error = exc
            self._ready.set()
            return
        self._ready.set()
        self._loop.run_forever()

    async def _request(self, method: str, url: str, kwargs: dict[str, Any]) -> httpx.Response:
        assert self._client is not None and self._limiter is not None
        request_url = self._request_url(url)
        async with self._limiter:
            return await self._client.request(method, request_url, **kwargs)

    def _request_url(self, url: str) -> str:
        """Resolve operation paths under the configured base path and validate egress."""
        absolute = urljoin(self._base_url, url.lstrip("/")) if url.startswith("/") else urljoin(
            self._base_url, url
        )
        if self._url_validator is not None:
            self._url_validator(absolute)
        return absolute

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        future: Future[httpx.Response] = asyncio.run_coroutine_threadsafe(
            self._request(method, url, kwargs), self._loop
        )
        return future.result(timeout=self._timeout + 15)

    async def _burst(
        self, requests: list[tuple[str, str, dict[str, Any]]]
    ) -> list[httpx.Response | BaseException]:
        assert self._client is not None
        # Deliberately NOT wrapped in the limiter: the whole point of a race
        # probe is to land these requests at the same instant. gather runs them
        # concurrently on this loop, which against a live target (or an ASGI
        # target in tests) is genuine parallelism. The caller bounds the count.
        tasks = [self._client.request(m, self._request_url(u), **kw) for (m, u, kw) in requests]
        return await asyncio.gather(*tasks, return_exceptions=True)

    def burst(
        self, requests: list[tuple[str, str, dict[str, Any]]]
    ) -> list[httpx.Response | BaseException]:
        """Fire several requests concurrently, bypassing the rate limiter.

        For the race/limit-overrun check only. Every other path goes through
        ``request`` and stays rate-limited; this one exists precisely to defeat
        that, so it is small, explicit, and used by one check under mutate:true.
        """
        future: Future[list[httpx.Response | BaseException]] = (
            asyncio.run_coroutine_threadsafe(self._burst(requests), self._loop)
        )
        return future.result(timeout=self._timeout + 30)

    def close(self) -> None:
        if self._client is not None and self._loop.is_running():
            future = asyncio.run_coroutine_threadsafe(self._client.aclose(), self._loop)
            future.result(timeout=10)
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join(timeout=10)
        if not self._loop.is_closed():
            self._loop.close()

    def __enter__(self) -> AsyncHttpClientBridge:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
