"""The vault's key handling: rotation, refusal outside dev, and a named failure.

``vault`` builds its cipher at import from settings, so these exercise
``_build`` directly under a patched settings object rather than re-importing.
"""
from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from app.core import vault


def _use(monkeypatch, *, key: str, env: str = "dev") -> None:
    monkeypatch.setattr(vault.settings, "vault_key", key)
    monkeypatch.setattr(vault.settings, "env", env)
    monkeypatch.setattr(vault, "_fernet", vault._build())


def test_a_listed_old_key_still_decrypts_after_rotation(monkeypatch):
    old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    _use(monkeypatch, key=old)
    token = vault.encrypt("secret-value")

    # Prepend the new key: it encrypts from now on, the old one still opens.
    _use(monkeypatch, key=f"{new},{old}")
    assert vault.decrypt(token) == "secret-value"
    assert Fernet(new.encode()).decrypt(vault.encrypt("x").encode()) == b"x"


def test_a_secret_saved_under_another_key_fails_by_name(monkeypatch):
    _use(monkeypatch, key=Fernet.generate_key().decode())
    token = vault.encrypt("secret-value")
    _use(monkeypatch, key=Fernet.generate_key().decode())
    with pytest.raises(vault.UndecryptableSecret):
        vault.decrypt(token)


def test_an_unset_key_is_refused_outside_dev(monkeypatch):
    monkeypatch.setattr(vault.settings, "vault_key", "")
    monkeypatch.setattr(vault.settings, "env", "production")
    with pytest.raises(vault.VaultKeyError):
        vault._build()


def test_an_unset_key_in_dev_falls_back_and_warns(monkeypatch):
    monkeypatch.setattr(vault.settings, "vault_key", "")
    monkeypatch.setattr(vault.settings, "env", "dev")
    # The app's loggers do not propagate to pytest's capture handler.
    warnings: list[str] = []
    monkeypatch.setattr(vault.log, "warning", lambda msg, *a, **k: warnings.append(msg))
    vault._build()
    assert any("VAULT_KEY is unset" in w for w in warnings)


def test_a_credential_saved_under_another_key_is_dropped_with_its_role(monkeypatch):
    """The run removes that identity and says why, instead of failing unexplained."""
    from types import SimpleNamespace

    from app.domain.enums import AuthType, GrantType
    from app.engine import runner

    _use(monkeypatch, key=Fernet.generate_key().decode())
    stale = vault.encrypt("old-secret")
    _use(monkeypatch, key=Fernet.generate_key().decode())
    fresh = vault.encrypt("new-secret")

    def profile(role: str, ref: str) -> SimpleNamespace:
        return SimpleNamespace(
            name=role, role=role, privilege=None, tenant=None,
            auth_type=AuthType.bearer, header_name=None,
            secret_ref=ref, refresh_url=None, refresh_secret_ref=None,
            refresh_token_field="refresh_token", access_token_field="access_token",
            grant_type=GrantType.static, token_url=None, grant_params={}, local_only=False,
        )

    scan = SimpleNamespace(credential_profiles=[profile("admin", stale), profile("user", fresh)])
    resolved, unreadable = runner._resolve_credentials(scan)
    assert [c.role for c in resolved] == ["user"]
    assert resolved[0].secret == "new-secret"
    assert unreadable == ["admin"]


def test_a_malformed_key_is_refused_by_name(monkeypatch):
    monkeypatch.setattr(vault.settings, "vault_key", "not-a-fernet-key")
    with pytest.raises(vault.VaultKeyError):
        vault._build()
