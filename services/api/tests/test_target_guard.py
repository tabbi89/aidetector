"""The egress guard: what a scan, a spec fetch or a notification may connect to.

Cloud metadata is blocked whatever the settings say, including IPv6 spellings
that embed the IPv4 address; the allowlist is authoritative.
"""
from __future__ import annotations

import pytest

from app.core.target_guard import TargetNotAllowed, check_target_allowed


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",  # AWS/GCP metadata
        "http://metadata.google.internal/",
        "http://metadata.google.internal./",  # trailing dot names the same host
        # IPv6 spellings of the IPv4 metadata address: an IPv4-only rule missed these.
        "http://[::ffff:169.254.169.254]/",
        "http://[::ffff:a9fe:a9fe]/",
        "http://[::169.254.169.254]/",       # deprecated IPv4-compatible
        "http://[2002:a9fe:a9fe::]/",        # 6to4
        "http://[64:ff9b::a9fe:a9fe]/",      # NAT64
        "http://[fd00:ec2::254]/",           # AWS IMDS over IPv6
        "http://[fe80::1]/",                 # IPv6 link-local
        "http://100.100.100.200/",           # Alibaba Cloud metadata
        "http://168.63.129.16/",             # Azure WireServer
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/",
        "ftp://example.com/",
        "://nohost",
    ],
)
def test_guard_always_blocks(url):
    with pytest.raises(TargetNotAllowed):
        check_target_allowed(url, allow_private=True, allowlist=[])


def test_guard_allows_private_when_enabled():
    # Local-lab default: loopback / unresolvable lab names are permitted.
    check_target_allowed("http://127.0.0.1:9000", allow_private=True, allowlist=[])
    check_target_allowed("http://target:9000", allow_private=True, allowlist=[])


def test_guard_blocks_private_when_disabled():
    with pytest.raises(TargetNotAllowed):
        check_target_allowed("http://127.0.0.1:9000", allow_private=False, allowlist=[])
    with pytest.raises(TargetNotAllowed):
        check_target_allowed("http://10.0.0.5/", allow_private=False, allowlist=[])
    # A private IPv4 address hidden inside an IPv6 literal is still private.
    with pytest.raises(TargetNotAllowed):
        check_target_allowed("http://[::ffff:10.0.0.5]/", allow_private=False, allowlist=[])


def test_guard_allows_public_ipv6_when_private_disabled():
    # Unwrapping embedded IPv4 must not make ordinary public IPv6 unreachable.
    check_target_allowed("http://[2606:4700:4700::1111]/", allow_private=False, allowlist=[])


def test_guard_blocks_metadata_even_when_allowlisted():
    with pytest.raises(TargetNotAllowed):
        check_target_allowed(
            "http://[::ffff:169.254.169.254]/",
            allow_private=True,
            allowlist=["::ffff:169.254.169.254"],
        )


def test_guard_allowlist_is_authoritative():
    check_target_allowed(
        "http://10.0.0.5/", allow_private=False, allowlist=["10.0.0.5"]
    )
    check_target_allowed(
        "https://api.corp.example/", allow_private=False, allowlist=[".example"]
    )
    with pytest.raises(TargetNotAllowed):
        check_target_allowed(
            "https://evil.test/", allow_private=True, allowlist=["good.test"]
        )
