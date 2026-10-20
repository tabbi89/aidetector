"""The redactor: secrets, personal identifiers and sensitive field names.

It sits between a scan and a copy of the target's data, so these pin both
what it must mask and the ordinary values it must leave readable.
"""
from __future__ import annotations

import jwt
import pytest

from app.core.redact import Redactor


def test_redactor_masks_known_secret_and_patterns():
    r = Redactor(["s3cr3t-token-value"])
    out = r.text("echoed s3cr3t-token-value back to alice@corp.example")
    assert "s3cr3t-token-value" not in out
    assert "alice@corp.example" not in out
    assert "«redacted»" in out


def test_redactor_accepts_tokens_minted_after_construction():
    redactor = Redactor(["grant-secret"])
    redactor.add_secret("short-opaque-token")
    assert redactor.text("echo short-opaque-token") == "echo «redacted»"


def test_redactor_masks_jwt_and_walks_evidence():
    token = jwt.encode({"sub": "u"}, "k"*32, algorithm="HS256")
    r = Redactor([])
    ev = r.evidence({"response_sample": f"Authorization: Bearer {token}", "n": [token]})
    assert token not in ev["response_sample"]
    assert token not in ev["n"][0]


# The trace keeps a sample of the target's own response body, so the redactor
# is what stands between a scan and a copy of someone's customer records. These
# pin the shapes it must catch — and, just as importantly, the ordinary values
# it must leave alone, because a redactor that masks every long number turns the
# request log into a wall of «redacted» and nobody reads it.


@pytest.mark.parametrize(
    "text",
    [
        "ssn 123-45-6789 on file",
        "ssn 123 45 6789 on file",
        "ein 12-3456789 filed",
        "card 4111 1111 1111 1111 charged",
        "card 4111-1111-1111-1111 charged",
        "call +1 555 867 5309 now",
        "call (555) 867-5309 now",
        "born 1984-07-02 in NY",
    ],
)
def test_redactor_masks_personal_identifiers_by_shape(text: str):
    """Values we cannot know up front, recognised by the shape they come in."""
    out = Redactor().text(text)
    assert "«redacted»" in out, out
    for token in text.split():
        if any(ch.isdigit() for ch in token) and len(token) > 3:
            assert token not in out, f"{token!r} survived in {out!r}"


@pytest.mark.parametrize(
    "text",
    [
        "order 987654321 shipped",       # bare 9 digits: an order number
        "quantity 42 units",
        "version 1.2.3 released",
        "1234567890123456789 rows",      # long, but not a valid card
    ],
)
def test_redactor_leaves_ordinary_numbers_alone(text: str):
    """A redactor nobody can read past is one nobody reads."""
    assert Redactor().text(text) == text


def test_card_masking_requires_a_valid_checksum():
    """Luhn is what separates a card from a request id of the same length."""
    assert "«redacted»" in Redactor().text("4111111111111111")   # valid
    assert Redactor().text("4111111111111112") == "4111111111111112"  # invalid


def test_redactor_masks_by_field_name_where_shape_cannot_help():
    """A routing number and an order number are both nine digits.

    Only the key tells them apart, which is why body redaction is name-driven
    and ``text`` redaction is not.
    """
    body = '{"routing_number":"021000021","order_number":"021000021"}'
    out = Redactor().body(body)
    assert '"routing_number":"«redacted»"' in out
    assert '"order_number":"021000021"' in out


def test_body_redaction_survives_input_that_is_not_json():
    """A body is untrusted input; redaction must not be what fails a scan."""
    assert "«redacted»" in Redactor(["s3cr3t-token-value"]).body(
        "<html>error: s3cr3t-token-value</html>"
    )
    assert Redactor().body("") == ""
    assert Redactor().body("{ truncated json") == "{ truncated json"


def test_scan_body_reports_reportable_names_only():
    """Detection rides along with redaction — but not everything masked is a finding."""
    scan = Redactor().scan_body(
        '{"ssn":"1","password_hash":"h","first_name":"Ada","id":7}'
    )
    assert scan.sensitive == ["ssn", "password_hash"]
    # ...while the personal field is still masked.
    assert "Ada" not in scan.text


def test_scan_body_deduplicates_and_bounds_what_it_reports():
    """One response must not put hundreds of names into the run archive."""
    from app.core.redact import _MAX_REPORTED_FIELDS

    rows = ",".join(f'{{"ssn":"{i}","f{i}":"x"}}' for i in range(60))
    scan = Redactor().scan_body(f'{{"rows":[{rows}]}}')
    assert scan.sensitive == ["ssn"]

    wide = ",".join(f'"secret_{i}":"x"' for i in range(60))
    assert len(Redactor().scan_body("{" + wide + "}").sensitive) == _MAX_REPORTED_FIELDS
