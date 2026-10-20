"""Target base URLs are judged when a scan is created, not when it runs.

The schema used to accept any non-empty string, so two URLs pasted together
(or a port that is not a number) were stored and only surfaced as a failed run.
The rules live on the schema, so create and edit agree; private/loopback policy
is deliberately elsewhere — at the run endpoint.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.api.schemas import ScanCreate

#: (what the user types, what gets stored) — normalisation is part of the contract.
ACCEPTED = [
    ('http://target:9000', 'http://target:9000'),
    ('https://api.example.com/v1', 'https://api.example.com/v1'),
    ('http://host.docker.internal:8080', 'http://host.docker.internal:8080'),
    ('  https://api.example.com/v1  ', 'https://api.example.com/v1'),
    ('https://api.example.com/', 'https://api.example.com'),
]

#: (what the user types, a fragment of the message explaining why it is refused).
REJECTED = [
    ('http://localhost:9000http://localhost:9000', 'not a valid URL'),
    ('api.example.com', 'must start with http:// or https://'),
    ('ftp://api.example.com', 'must start with http:// or https://'),
    ('http://', 'must include a hostname'),
    ('http://api.example.com:notaport', 'not a valid URL'),
    ('http://user:pass@api.example.com', 'must not contain credentials'),
    ('https://api.example.com/v1?key=1', 'must not contain a query string'),
    ('https://api.example.com/v1#top', 'must not contain a fragment'),
    ('http://api.example.com/a b', 'must not contain whitespace'),
    ('   ', 'is required'),
]

def detail(response) -> str:
    return '\n'.join(str(e.get('msg', e)) for e in response.json().get('detail'))


def payload(url: str) -> dict[str, str]:
    return dict(target_base_url=url)


@pytest.mark.parametrize(('typed', 'stored'), ACCEPTED)
def test_schema_stores_the_normalised_url(typed: str, stored: str):
    # No database needed: the rule sits on the schema, so every caller gets it.
    assert ScanCreate(**payload(typed)).target_base_url == stored


@pytest.mark.parametrize(('typed', 'fragment'), REJECTED)
def test_schema_refuses_malformed_urls(typed: str, fragment: str):
    with pytest.raises(ValidationError) as exc:
        ScanCreate(**payload(typed))
    assert fragment in str(exc.value)


@pytest.mark.parametrize(('typed', 'stored'), ACCEPTED)
def test_create_accepts_and_normalises(client, typed: str, stored: str):
    r = client.post('/scans', json=payload(typed))
    assert r.status_code == 201, r.text
    assert r.json().get('target_base_url') == stored


@pytest.mark.parametrize(('typed', 'fragment'), REJECTED)
def test_create_refuses_malformed_urls(client, typed: str, fragment: str):
    r = client.post('/scans', json=payload(typed))
    assert r.status_code == 422, r.text
    assert fragment in detail(r)


@pytest.mark.parametrize(('typed', 'stored'), ACCEPTED)
def test_edit_accepts_and_normalises(client, new_scan, typed: str, stored: str):
    sid = new_scan()
    r = client.patch(f'/scans/{sid}', json=payload(typed))
    assert r.status_code == 200, r.text
    assert r.json().get('target_base_url') == stored
    assert client.get(f'/scans/{sid}').json().get('target_base_url') == stored


@pytest.mark.parametrize(('typed', 'fragment'), REJECTED)
def test_edit_refuses_malformed_urls(client, new_scan, typed: str, fragment: str):
    sid = new_scan()
    r = client.patch(f'/scans/{sid}', json=payload(typed))
    assert r.status_code == 422, r.text
    assert fragment in detail(r)
    # A refused edit leaves the stored target alone.
    assert client.get(f'/scans/{sid}').json().get('target_base_url') == 'http://t'
