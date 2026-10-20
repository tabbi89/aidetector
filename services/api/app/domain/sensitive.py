"""What a field *name* says about the value behind it.

Two parts of the system need to recognise a sensitive field, for opposite
reasons:

- ``engine/exposure_policy`` reports it — a response carrying ``password_hash``
  is over-exposing, and that is a finding.
- ``core/redact`` hides it — the same field must not be copied into the run
  archive on its way past.

They were two independent lists of names, which is a bug waiting to happen: a
family added to one is silently missed by the other, and the one that misses it
is whichever you did not think of. So the names live here, once, categorised —
and each consumer chooses which categories it acts on.

The two consumers do not act on the same set, and that is deliberate.
:data:`REPORTABLE` names things that should never have been in a response at
all. The two categories outside it are masked but never reported: ``personal``
(name, address, phone, date of birth), because an API returning a user their own
name is doing its job; and ``opaque``, loose names like ``token`` that are too
weak to accuse an endpoint over but far too risky to store.

Matching is on the **normalised** name — lowercased with separators stripped —
so ``routing_number``, ``routingNumber`` and ``Routing-Number`` are one entry
rather than three.

Pure: this is vocabulary, so nothing here may import SQLAlchemy, FastAPI,
``app.engine`` or ``app.models`` (``tests/test_layering.py`` enforces it).
"""
from __future__ import annotations

import re

#: Categories that describe something which should not be in a response body at
#: all. ``exposure_policy`` reports these; ``redact`` masks them too.
REPORTABLE: tuple[str, ...] = (
    "credential",
    "token",
    "payment",
    "government_id",
    "internal",
)

#: Every category, in match order — most specific first, so a name matching
#: several is claimed by the one that describes it best.
CATEGORY_PATTERNS: dict[str, re.Pattern[str]] = {
    "credential": re.compile(
        r"(password|passwd|pwd|passphrase|secret|privatekey|apikey|accesskey|"
        r"secretkey|clientsecret|salt|otpseed|totpsecret)"
    ),
    "token": re.compile(
        r"(sessionid|sessiontoken|accesstoken|refreshtoken|bearertoken|"
        r"authtoken|idtoken|csrftoken|resettoken|verificationtoken)"
    ),
    "payment": re.compile(
        r"(cardnumber|creditcard|cardpan|cardpin|cvv|cvc|iban|swift|bic|"
        r"routingnumber|routingno|accountnumber|accountno|sortcode)"
    ),
    "government_id": re.compile(
        r"(ssn|socialsecurity|nationalid|passportnumber|passportno|taxid|"
        r"\btin\b|\bein\b|nino|driverslicense|drivinglicence|driverslicence)"
    ),
    "internal": re.compile(
        r"(^internal|^_|debug|stacktrace|traceback|querytime|sqlquery|"
        r"^rawsql|servername|hostname|^env$|^config$)"
    ),
    # Loose names that are credential-shaped but too weak to *report*: a field
    # called ``token`` may hold a bearer token or the string "Bearer", and the
    # compound names above are what distinguish those. Masked all the same,
    # because over-masking a ``token_type`` costs nothing and missing a real
    # token does not.
    "opaque": re.compile(r"(token|signature|credential)"),
    # Redacted, never reported — see the module docstring.
    "personal": re.compile(
        r"(dateofbirth|birthdate|\bdob\b|firstname|lastname|middlename|"
        r"fullname|surname|givenname|maidenname|phone|mobile|telephone|"
        r"street|address|postcode|zipcode|^zip$)"
    ),
}

#: Names that match a pattern above but routinely are not the thing itself.
#: Consulted by the *reporting* side only: over-masking a field called
#: ``cardLast4`` costs nothing, while reporting it is a false positive.
ALLOWED: frozenset[str] = frozenset(
    {
        # A boolean "does this account use a password" is not a password.
        "haspassword",
        "passwordset",
        "passwordchangedat",
        "passwordupdatedat",
        "passwordexpiresat",
        "requirespasswordchange",
        # An id of a token/session, not the token itself, is normal in admin APIs.
        "tokentype",
        "tokenexpiresin",
        # Payment *presence*, not the instrument.
        "hascard",
        "cardbrand",
        "cardlast4",
        "last4",
        # ``secret`` would otherwise match these two, but an assistant's job
        # title is not credential material.
        "secretary",
        "secretarial",
    }
)


def normalise(name: str) -> str:
    """Field name to its comparison form: lowercase, separators removed.

    ``password_hash``, ``passwordHash`` and ``Password-Hash`` are one name, so a
    rule is written once rather than once per house style.
    """
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


#: Word boundaries for the third spelling: camelCase transitions *and* runs of
#: separators. ``tax_tin`` and ``taxTin`` both become ``tax tin``, so a
#: word-boundary anchor (``\\btin\\b``) sees a boundary the normalised
#: ``taxtin`` erased and the raw ``tax_tin`` (where ``_`` is itself a word
#: character) did not.
_WORD_SPLIT = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|[^A-Za-z0-9]+")


def forms(name: str) -> tuple[str, str, str]:
    """The spellings a pattern is tried against.

    - **normalised** — separators stripped, so ``password_hash`` and
      ``passwordHash`` are one entry rather than one per house style;
    - **raw lowercase** — preserves the separators an *anchored* rule depends
      on (``^_`` catches ``_internal``; the normalised ``internal`` can never);
    - **word-split** — separators and camelCase boundaries become spaces, so a
      word-boundary anchor sees the word edges normalisation erased.
    """
    return (
        normalise(name),
        str(name).lower(),
        _WORD_SPLIT.sub(" ", str(name)).lower(),
    )


def _hit(pattern: re.Pattern[str], name: str) -> bool:
    return any(pattern.search(form) for form in forms(name) if form)


def classify(name: str, *, categories: tuple[str, ...] | None = None) -> str | None:
    """The first category ``name`` belongs to, or None.

    ``categories`` restricts the search — reporting passes :data:`REPORTABLE` so
    a customer's own first name is never a finding. The allowlist is honoured
    here, so a caller that must not miss anything (redaction) should use
    :func:`is_sensitive` instead.
    """
    if normalise(name) in ALLOWED:
        return None
    for category in categories or tuple(CATEGORY_PATTERNS):
        pattern = CATEGORY_PATTERNS.get(category)
        if pattern is not None and _hit(pattern, name):
            return category
    return None


def is_sensitive(name: str) -> bool:
    """Whether ``name`` is sensitive at all — the redaction question.

    Deliberately ignores :data:`ALLOWED`. Masking ``cardLast4`` when it did not
    need masking loses nothing; missing a real card number does.
    """
    return any(_hit(pattern, name) for pattern in CATEGORY_PATTERNS.values())
