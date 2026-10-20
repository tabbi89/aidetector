"""Plausible values for fields an OpenAPI document leaves untyped.

``spec_values.base_value`` covers what a schema actually declares — enums,
formats, types. Real APIs validate far more than they declare: a spec says a
merchant's ``tin`` is ``{"type": "string"}`` and the server rejects anything
that is not nine digits. The deterministic resource create then 400s, resource
setup gives up, and every write-side check that needed a real object silently
does nothing.

So this is a **name**-driven table, deliberately kept as data and deliberately
kept out of the engine: it is a list of guesses about naming conventions, it
will grow one entry at a time as targets are met, and none of it is logic.
Matching is on the field name with punctuation and case stripped, so
``routing_number``, ``routingNumber`` and ``ROUTING-NUMBER`` are one rule.

Nothing here is a real identifier. The numbers are the canonical documentation
placeholders (``123-45-6789``, the ABA test routing number, a Luhn-invalid card
range) precisely so that a value in a trace or a target's database is
recognisable as ours and is worthless if it leaks.

Rules are tried in order and the first match wins, so put the specific ones
first — ``ssn`` before the ``…name`` catch-all.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

#: How a rule matches a normalized field name.
Match = Callable[[str], bool]


def _exact(*names: str) -> Match:
    wanted = frozenset(names)
    return lambda plain: plain in wanted


def _contains(*fragments: str) -> Match:
    return lambda plain: any(f in plain for f in fragments)


def _suffix(*endings: str) -> Match:
    return lambda plain: plain.endswith(endings)


#: ``(match, value)`` in priority order. Values are strings because this fills
#: string-typed fields; numeric and boolean shapes are handled by the caller.
FIELD_VALUES: tuple[tuple[Match, str], ...] = (
    # Identity documents and tax numbers — the shapes servers validate hardest.
    (_exact("ssn", "socialsecuritynumber"), "123-45-6789"),
    (_exact("tin", "taxid", "taxidnumber"), "123456789"),
    (_exact("tintype"), "EIN"),
    (_exact("ein"), "12-3456789"),
    # Banking.
    (_contains("routing"), "021000021"),
    (_exact("accountnumber", "bankaccountnumber", "account"), "123456789012"),
    (_exact("iban"), "GB82WEST12345698765432"),
    # Postal address.
    (_exact("zip", "zipcode", "postcode", "postalcode"), "10001"),
    (_exact("state", "stateprovince"), "NY"),
    (_exact("city"), "New York"),
    (_exact("country", "countrycode"), "US"),
    (_suffix("address", "addressline1", "street"), "123 Main St"),
    # People.
    (_exact("firstname", "lastname", "givenname", "surname"), "Aidx"),
    (_exact("middlename", "middleinitial"), "M"),
    (_exact("jobtitle", "title", "role"), "CEO"),
    # Commerce and devices.
    (_exact("mcc", "mcccode"), "5812"),
    (_exact("imei"), "123456789012345"),
    (_exact("hardwareid", "deviceid", "terminalid", "plantermid"), "hw-aidx"),
    (_contains("percentage", "percent"), "100"),
    (_exact("currency", "currencycode"), "USD"),
    # Catch-alls, last on purpose.
    (_suffix("name"), "Aidx Merchant"),
)

#: Rules keyed on the declared ``format`` rather than the name. Checked first,
#: because a declared format is a fact and a field name is a guess.
FORMAT_VALUES: dict[str, str] = {
    "date": "2020-01-01",
    "date-time": "2020-01-01T00:00:00Z",
    "uri": "https://example.com",
    "url": "https://example.com",
    "uuid": "00000000-0000-4000-8000-000000000000",
    "ipv4": "203.0.113.1",
    "hostname": "example.com",
}


def plain(name: str) -> str:
    """Lowercased, punctuation-free field name — the form rules match against."""
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def string_value(name: str, schema: dict[str, Any], seed: str) -> str:
    """A plausible string for a named field, or a seeded marker when unknown.

    ``seed`` makes the fallback unique per create so two resources provisioned
    in one run are distinguishable on the target.
    """
    key = plain(name)
    fmt = str(schema.get("format") or "")
    if fmt == "email" or "email" in key:
        return f"{seed}@example.invalid"
    if fmt in FORMAT_VALUES:
        return FORMAT_VALUES[fmt]
    if "phone" in key or "mobile" in key or "telephone" in key:
        digits = "".join(ch for ch in seed if ch.isdigit()).ljust(7, "7")[-7:]
        return "+1555" + digits
    for matches, value in FIELD_VALUES:
        if matches(key):
            return value
    # An undeclared date field: ``date_of_birth``, ``business_established_date``.
    if "date" in key:
        return "2020-01-01"
    if "url" in key or "website" in key or "domain" in key:
        return "https://example.com"
    declared = schema.get("type")
    if declared in ("integer", "number"):
        return "1"
    if declared == "boolean":
        return "false"
    return f"aidx{seed}"
