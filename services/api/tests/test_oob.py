"""Persistent interactsh OOB client — session capture, streaming correlation,
and graceful degradation. A fake streaming process stands in for the real
``interactsh-client`` binary, so no network or CLI is needed."""
from __future__ import annotations

import json
import queue
import time

from app.engine.oob import InteractshClient


class FakeInteractsh:
    """A fake ``interactsh-client`` process: a blocking line stream we feed.

    ``for line in proc.stdout`` blocks until a line is fed; ``terminate`` unblocks
    the reader by pushing a sentinel that ends the stream (like a closed pipe)."""

    def __init__(self, initial: tuple[str, ...] = ()) -> None:
        self._q: queue.Queue = queue.Queue()
        for line in initial:
            self._q.put(line)
        self.stdout = self
        self.terminated = False

    def __iter__(self) -> FakeInteractsh:
        return self

    def __next__(self) -> str:
        item = self._q.get()
        if item is None:
            raise StopIteration
        return item

    def feed(self, line: str) -> None:
        self._q.put(line)

    def terminate(self) -> None:
        self.terminated = True
        self._q.put(None)

    def wait(self, timeout: float | None = None) -> int:
        return 0


def _poll_until(client: InteractshClient, tries: int = 100):
    for _ in range(tries):
        got = client.poll()
        if got:
            return got
        time.sleep(0.02)
    return client.poll()


def test_persistent_session_captures_domain_and_correlates():
    proc = FakeInteractsh(("abcd.oast.test",))  # startup prints the session domain
    client = InteractshClient("oast.test", spawn=lambda: proc, startup_timeout=5)
    try:
        assert client.active
        assert client.payload_domain("tok1") == "tok1.abcd.oast.test"
        assert client.payload_url("tok1") == "http://tok1.abcd.oast.test/tok1"
        assert client.poll() == []  # nothing yet

        # The target calls back → the client streams a JSON interaction record.
        proc.feed(json.dumps({
            "protocol": "HTTP",
            "full-id": "tok1.abcd.oast.test",
            "remote-address": "9.9.9.9",
        }))
        got = _poll_until(client)
        assert len(got) == 1
        assert got[0].token == "tok1"  # correlated by the subdomain label
        assert got[0].protocol == "http"
        assert got[0].source_ip == "9.9.9.9"
        assert client.poll() == []  # drained
    finally:
        client.close()
    assert not client.active
    assert proc.terminated


def test_domain_derived_from_first_json_interaction():
    """If the first line is already an interaction, the session domain is derived
    from it and the interaction is not lost."""
    rec = {"protocol": "dns", "full-id": "tokX.zzz.oast.test", "remote-address": "1.1.1.1"}
    proc = FakeInteractsh((json.dumps(rec),))
    client = InteractshClient("oast.test", spawn=lambda: proc, startup_timeout=5)
    try:
        assert client.active
        assert client.payload_domain("q") == "q.zzz.oast.test"
        got = _poll_until(client)
        assert got and got[0].token == "tokX"
    finally:
        client.close()


def test_degrades_when_spawn_fails():
    def boom() -> FakeInteractsh:
        raise OSError("no interactsh-client binary")

    client = InteractshClient("oast.test", spawn=boom, startup_timeout=0.5)
    assert not client.active
    assert client.payload_domain("t") is None
    assert client.payload_url("t") is None
    assert client.poll() == []


def test_inactive_without_startup_domain():
    proc = FakeInteractsh(())  # never emits a domain
    client = InteractshClient("oast.test", spawn=lambda: proc, startup_timeout=0.3)
    assert not client.active
    assert client.payload_domain("t") is None
    client.close()
    assert proc.terminated
