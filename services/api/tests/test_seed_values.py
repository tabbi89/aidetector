"""Values for fields an OpenAPI document leaves untyped.

``spec_values.base_value`` covers what a schema declares. Real APIs validate far
more: a spec says a merchant's ``tin`` is ``{"type": "string"}`` and the server
rejects anything that is not nine digits. The deterministic create then 400s,
resource setup gives up, and every write-side check that needed a real object
silently does nothing.

So this table is a list of guesses about naming conventions, and these tests pin
the two properties that make it safe: the guesses are ordered so a specific rule
beats a general one, and nothing in it is a real identifier.
"""
from __future__ import annotations

import re

import pytest

from app.engine.seed_values import FIELD_VALUES, FORMAT_VALUES, plain, string_value


def value(name: str, schema: dict | None = None) -> str:
    return string_value(name, schema or {}, "abc123")


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("ssn", "123-45-6789"),
        ("social_security_number", "123-45-6789"),
        ("tin", "123456789"),
        ("routing_number", "021000021"),
        ("bank_account_number", "123456789012"),
        ("zip_code", "10001"),
        ("state", "NY"),
        ("mcc_code", "5812"),
        ("imei", "123456789012345"),
    ],
)
def test_named_fields_get_a_shape_the_server_will_accept(name: str, expected: str):
    assert value(name) == expected


def test_a_declared_format_beats_a_name_guess():
    """A format is a fact; a field name is a guess."""
    assert value("start", {"format": "date"}) == "2020-01-01"
    assert value("callback", {"format": "uri"}) == "https://example.com"


def test_email_is_unique_per_create():
    """Two resources provisioned in one run must be distinguishable on target."""
    first = string_value("email", {}, "aaa111")
    second = string_value("email", {}, "bbb222")
    assert first != second
    assert first.endswith("@example.invalid")


def test_a_specific_rule_beats_the_name_catch_all():
    """Ordering is the whole contract of the table.

    ``first_name`` must not fall through to the trailing ``…name`` rule, which
    would give a person the business's name.
    """
    assert value("first_name") == "Aidx"
    assert value("legal_business_name") == "Aidx Merchant"


def test_an_unknown_field_gets_a_seeded_marker():
    """Recognisable as ours in a target's database, and unique per create."""
    assert value("wholly_unknown_field") == "aidxabc123"


def test_naming_style_does_not_change_the_answer():
    for spelling in ("routing_number", "routingNumber", "Routing-Number"):
        assert value(spelling) == "021000021"


# ---- Safety --------------------------------------------------------------------


def test_nothing_in_the_table_is_a_usable_identifier():
    """These values are written into someone else's system, so they are the
    canonical documentation placeholders — recognisable as ours, worthless if
    they leak, and never a real person's data.
    """
    # A card number that passes Luhn would be a plausible real card.
    real_looking = set()
    for _, v in FIELD_VALUES:
        digits = re.sub(r"\D", "", v)
        if len(digits) >= 13 and _luhn(digits):
            real_looking.add(v)
    assert not real_looking, f"table holds Luhn-valid card-shaped values: {real_looking}"


def _luhn(digits: str) -> bool:
    if not digits:
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        n = int(char)
        if index % 2:
            n = n * 2 - 9 if n * 2 > 9 else n * 2
        total += n
    return total % 10 == 0


def test_every_rule_is_reachable():
    """A rule shadowed by an earlier one is dead weight that reads as coverage."""
    unreachable = []
    for index, (matches, expected) in enumerate(FIELD_VALUES):
        earlier = [m for m, _ in FIELD_VALUES[:index]]
        # Find any normalised name this rule claims that no earlier rule claims.
        candidates = [n for n in _CANDIDATE_NAMES if matches(plain(n))]
        if candidates and all(any(m(plain(n)) for m in earlier) for n in candidates):
            unreachable.append(expected)
    assert not unreachable, f"rules shadowed by an earlier entry: {unreachable}"


#: Names the reachability check probes with — one per rule family.
_CANDIDATE_NAMES = [
    "ssn", "social_security_number", "tin", "tin_type", "ein", "routing_number",
    "account_number", "iban", "zip", "state", "city", "country", "street_address",
    "first_name", "middle_name", "job_title", "mcc", "imei", "hardware_id",
    "ownership_percentage", "currency", "legal_business_name",
]


def test_formats_and_fields_do_not_disagree():
    """A field whose *name* and *format* both have rules must not conflict."""
    assert FORMAT_VALUES["date"] == value("business_established_date")
