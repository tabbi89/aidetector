"""HTTP request smuggling (premium): ambiguous-framing probes over a raw socket."""
from __future__ import annotations

from app.engine.checks.request_smuggling import (
    RequestSmugglingCheck,
    cl_te_probe,
    is_desync,
    response_count,
    te_cl_probe,
)
from tests import factories

_ONE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
_TWO = (
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
)


def test_cl_te_probe_carries_ambiguous_framing_and_a_smuggled_get():
    probe = cl_te_probe("example.com", "/")
    assert b"Content-Length:" in probe
    assert b"Transfer-Encoding: chunked" in probe
    assert b"GET / HTTP/1.1" in probe  # the smuggled request


def test_te_cl_probe_carries_a_chunk_hiding_a_smuggled_get():
    probe = te_cl_probe("example.com", "/")
    assert b"Transfer-Encoding: chunked" in probe
    assert b"GET / HTTP/1.1" in probe


def test_two_responses_on_one_connection_is_a_desync():
    assert response_count(_TWO) == 2
    assert is_desync(_TWO) is True


def test_a_single_response_is_not_a_desync():
    assert response_count(_ONE) == 1
    assert is_desync(_ONE) is False


def test_a_body_mentioning_the_http_token_is_not_a_second_response():
    # A benign reply whose body echoes the request line must not read as a desync,
    # or the check emits a verified/high false positive.
    body = (
        b"HTTP/1.1 400 Bad Request\r\nContent-Length: 41\r\n\r\n"
        b"bad request: GET / HTTP/1.1 was malformed"
    )
    assert response_count(body) == 1
    assert is_desync(body) is False


def test_none_is_not_a_desync():
    assert is_desync(None) is False


def test_premium_check_noops_without_premium():
    assert RequestSmugglingCheck().run(factories.scan_context([])) == []


def test_unreachable_target_is_not_a_finding(monkeypatch):
    import socket

    def refused(*_args, **_kwargs):
        raise ConnectionRefusedError("controlled target refusal")

    monkeypatch.setattr(socket, "create_connection", refused)
    ctx = factories.scan_context([], premium=True)
    assert RequestSmugglingCheck().run(ctx) == []
