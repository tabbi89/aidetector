"""Fernet-backed secret vault for uploaded API credentials.

Secrets are encrypted at rest and only decrypted inside the scan worker.

``VAULT_KEY`` may list several comma-separated keys: the first encrypts, every
one decrypts. That is how a key is rotated without stranding stored secrets —
prepend the new key, re-save credentials, then drop the old one.

An unset ``VAULT_KEY`` is tolerated only under ``ENV=dev``, where it falls back
to an ephemeral per-process key. That key is private to one process: under
docker compose the api encrypts with one and the worker decrypts with another,
so a scan cannot read the credentials it was given. Hence the loud warning, and
the refusal to start anywhere else.
"""
from __future__ import annotations

import logging

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from app.core.config import settings

log = logging.getLogger("aidetector.vault")


class VaultKeyError(RuntimeError):
    """The vault has no usable key for this environment."""


class UndecryptableSecret(ValueError):
    """A stored secret was encrypted under a key this process does not hold."""


def _build() -> MultiFernet:
    keys = [k.strip() for k in settings.vault_key.split(",") if k.strip()]
    if keys:
        try:
            return MultiFernet([Fernet(k.encode()) for k in keys])
        except ValueError as exc:
            raise VaultKeyError(
                "VAULT_KEY is not a valid Fernet key (32 url-safe base64-encoded bytes)"
            ) from exc
    if settings.env != "dev":
        raise VaultKeyError(
            f"VAULT_KEY must be set when ENV={settings.env}: an ephemeral key "
            "loses every stored credential on restart and differs per process"
        )
    log.warning(
        "VAULT_KEY is unset; using an ephemeral key. Credentials saved by this "
        "process cannot be decrypted by any other process (the worker) or after a "
        "restart. Run `make env` or set VAULT_KEY."
    )
    return MultiFernet([Fernet(Fernet.generate_key())])


_fernet = _build()


def encrypt(plaintext: str) -> str:
    """Encrypt a secret and return a storable token."""
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str:
    """Decrypt a stored token back to plaintext.

    Raises :class:`UndecryptableSecret` when no configured key opens it — the
    usual cause is a VAULT_KEY that changed (or was never shared between the
    api and the worker) after the secret was saved.
    """
    try:
        return _fernet.decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise UndecryptableSecret(
            "stored secret was encrypted with a different VAULT_KEY"
        ) from exc
