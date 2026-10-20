"""Per-run runner tokens: minted once, stored hashed, matched constant-time."""
from __future__ import annotations

from app.scans.run_token import hash_run_token, new_run_token, token_matches


def test_new_token_is_random_and_hash_is_deterministic():
    clear1, hash1 = new_run_token()
    clear2, hash2 = new_run_token()
    assert clear1 != clear2 and hash1 != hash2
    # The hash is the stored form, 64 hex chars, and never the clear token.
    assert len(hash1) == 64 and all(c in "0123456789abcdef" for c in hash1)
    assert clear1 not in hash1
    assert hash_run_token(clear1) == hash1


def test_token_matches_only_the_right_token():
    clear, stored = new_run_token()
    assert token_matches(clear, stored) is True
    assert token_matches(clear + "x", stored) is False
    assert token_matches("totally-wrong", stored) is False


def test_missing_sides_never_match():
    clear, stored = new_run_token()
    # A run with no token (server run, or already ended) is unpostable.
    assert token_matches(clear, None) is False
    assert token_matches(None, stored) is False
    assert token_matches(None, None) is False
    assert token_matches("", stored) is False
