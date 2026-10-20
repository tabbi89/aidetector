"""What a field name implies, and the two answers that differ on purpose.

``app/domain/sensitive.py`` is one list serving two consumers with opposite
jobs: ``engine/exposure_policy`` *reports* a ``password_hash`` and
``core/redact`` *hides* it. They were independent lists, which is the kind of
duplication that fails silently — a family added to one is missed by the other,
and the one that misses it is whichever you did not think of.

So the split is the thing to pin: the categories each consumer acts on, and the
allowlist that applies to reporting but deliberately not to masking.
"""
from __future__ import annotations

import pytest

from app.domain.sensitive import (
    ALLOWED,
    CATEGORY_PATTERNS,
    REPORTABLE,
    classify,
    is_sensitive,
    normalise,
)


@pytest.mark.parametrize(
    ("name", "category"),
    [
        ("password_hash", "credential"),
        ("client_secret", "credential"),
        ("api_key", "credential"),
        ("session_token", "token"),
        ("refreshToken", "token"),
        ("routing_number", "payment"),
        ("bank_account_number", "payment"),
        ("iban", "payment"),
        ("ssn", "government_id"),
        ("tin", "government_id"),
        ("taxId", "government_id"),
        ("internal_notes", "internal"),
        ("_private", "internal"),
        ("stack_trace", "internal"),
    ],
)
def test_reportable_names_are_classified(name: str, category: str):
    assert classify(name, categories=REPORTABLE) == category


@pytest.mark.parametrize("name", ["id", "handle", "label", "created_at", "status", "name"])
def test_ordinary_names_are_neither_reported_nor_masked(name: str):
    assert classify(name, categories=REPORTABLE) is None
    assert is_sensitive(name) is False


# ---- The split that matters ----------------------------------------------------


@pytest.mark.parametrize(
    "name", ["first_name", "last_name", "date_of_birth", "phone", "street_address", "zip"]
)
def test_personal_data_is_masked_but_never_reported(name: str):
    """An API returning a user their own name is doing its job, not leaking.

    It must still stay out of the run archive — a trace is not a place to
    accumulate customer records — so the two answers differ, and that is the
    whole reason the vocabulary is categorised rather than a single list.
    """
    assert is_sensitive(name) is True
    assert classify(name, categories=REPORTABLE) is None


@pytest.mark.parametrize("name", ["token", "signature", "credential"])
def test_loose_credential_names_are_masked_but_not_reported(name: str):
    """``token`` may hold a bearer token or the string "Bearer".

    Too weak to accuse an endpoint over, far too risky to store — so it is
    masked without becoming a finding, like personal data and for the same
    reason: the two consumers ask different questions.
    """
    assert is_sensitive(name) is True
    assert classify(name, categories=REPORTABLE) is None


def test_only_personal_and_opaque_sit_outside_reportable():
    assert set(CATEGORY_PATTERNS) - set(REPORTABLE) == {"personal", "opaque"}


# ---- The allowlist -------------------------------------------------------------


@pytest.mark.parametrize("name", ["has_password", "card_last4", "token_type"])
def test_benign_lookalikes_are_not_reported(name: str):
    assert classify(name, categories=REPORTABLE) is None


def test_secretary_is_not_credential_material():
    """``secret`` would otherwise match ``secretary`` — an assistant's job
    title, not a password. The allowlist must stop it."""
    assert classify("secretary", categories=REPORTABLE) is None
    assert classify("secretarial", categories=REPORTABLE) is None
    # The real thing still is.
    assert classify("client_secret", categories=REPORTABLE) == "credential"


def test_a_word_boundary_anchor_sees_camel_case():
    """``tax_tin`` and ``taxTin`` are the same field: the ``\\btin\\b`` anchor
    must see the camelCase boundary that normalising erased."""
    assert classify("tax_tin", categories=REPORTABLE) == "government_id"
    assert classify("taxTin", categories=REPORTABLE) == "government_id"


@pytest.mark.parametrize("name", ["has_password", "token_type"])
def test_the_allowlist_does_not_relax_masking(name: str):
    """Over-masking a benign field costs nothing; under-masking a real one does.

    ``is_sensitive`` therefore ignores the allowlist. ``card_last4`` is the
    exception that proves it — it matches no pattern at all, allowlist aside.
    """
    assert is_sensitive(name) is True


def test_every_allowlist_entry_is_already_normalised():
    """An entry with punctuation could never match and would silently do nothing."""
    for entry in ALLOWED:
        assert entry == normalise(entry), f"{entry!r} is not in normalised form"


def test_the_allowlist_stops_the_entries_that_need_stopping():
    """``password_changed_at`` is a timestamp; the credential rule sees a password.

    Not every entry is load-bearing — several are belt-and-braces against
    patterns that were later narrowed — so this pins the ones that are.
    """
    for name in ("password_changed_at", "has_password", "requires_password_change"):
        assert CATEGORY_PATTERNS["credential"].search(normalise(name)), (
            f"{name} no longer needs allow-listing; the rule stopped matching it"
        )
        assert classify(name, categories=REPORTABLE) is None


def test_an_anchored_rule_matches_the_raw_name():
    """Normalising strips the separator an anchored rule depends on.

    ``^_`` is meant to catch ``_internal``. Against the normalised ``internal``
    it can never fire — and for a long time it never did.
    """
    assert classify("_private", categories=REPORTABLE) == "internal"
    assert classify("_debug_state", categories=REPORTABLE) == "internal"
    # And a name that merely contains an underscore is still not "internal".
    assert classify("created_at", categories=REPORTABLE) is None


# ---- Normalisation -------------------------------------------------------------


@pytest.mark.parametrize(
    "spelling", ["routing_number", "routingNumber", "Routing-Number", "ROUTING.NUMBER"]
)
def test_house_style_does_not_change_the_answer(spelling: str):
    assert classify(spelling, categories=REPORTABLE) == "payment"


def test_the_exposure_policy_reads_the_same_vocabulary():
    """The duplication this module exists to remove must not come back."""
    from app.engine.exposure_policy import SENSITIVE_RULES

    for rule in SENSITIVE_RULES:
        assert rule.pattern is CATEGORY_PATTERNS[rule.key], (
            f"{rule.key} carries its own copy of the pattern again"
        )
    assert {r.key for r in SENSITIVE_RULES} == set(REPORTABLE)
