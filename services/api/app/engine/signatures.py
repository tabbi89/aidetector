"""Signature corpus for the second-tier injection classes.

Two ingredients per class, both drawn from public, permissively-licensed
corpora (PayloadsAllTheThings, MIT; FuzzDB attack/detection regexes):

- ``payloads`` — benign, marker-carrying probes. Each template contains ``{m}``
  where a per-request unique marker is inserted; the ``aidx<marker>`` needle
  lets us confirm reflection, exactly as ``engine/payloads.py`` does.
- ``error_signatures`` — response-side regexes for the error/diagnostic strings
  a backend leaks when a malformed XPath / LDAP / NoSQL expression reaches it.
  A signature match is a *stronger* signal than bare reflection: it evidences
  that the payload was parsed by the target's query/interpreter layer, not just
  echoed. It is still short of exploitation, so findings stay "reflection leads".

The payload templates are deliberately malformed *and* marker-carrying, so one
request tests both signals at once. They reach the same spec-shaped sinks the
rest of the engine fuzzes: GET query + path params always, and POST/PUT/PATCH
JSON body fields under ``mutate`` (see ``app/engine/injection_probe.walk_points``
and ``spec_values.injection_points``).

Payloads here stay **curated**, deliberately not drawn from the vendored corpus
that feeds ``reflected_injection``. A signature finding's identity keys on its
``family`` (``app/engine/fingerprint.py``), so its *presence* must be stable
across the per-scan seed rotation — otherwise a rescan reports the same lead as
fixed-and-new and triage stops matching. Curated payloads chosen to trigger
their class reliably keep that presence deterministic; a large rotating pool,
whose members reflect or error inconsistently, would not. The corpus therefore
serves the reflection library, where identity excludes the family and rotation
is a designed-for property.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class SignatureClass:
    family: str                 # "xpath", "ldap", "nosqli", "ssi"
    label: str                  # human name for titles/copy
    owasp_id: str
    # Marker-carrying, intentionally-malformed probes. {m} -> unique marker.
    payloads: tuple[str, ...]
    # Compiled at import; a match evidences the payload hit an interpreter.
    error_signatures: tuple[re.Pattern[str], ...] = field(default_factory=tuple)


def _rx(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, re.IGNORECASE) for p in patterns)


# ---- XPath injection ----------------------------------------------------------
# Payloads break XPath quoting so a naive backend raises; markers confirm reach.
_XPATH = SignatureClass(
    family="xpath",
    label="XPath injection",
    owasp_id="CWE-74",
    payloads=(
        "aidx{m}']",
        "' or aidx{m}='aidx{m}",
        "count(//aidx{m})",
    ),
    error_signatures=_rx(
        r"XPathException",
        r"MS\.Internal\.Xml",
        r"Unknown error in XPath",
        r"org\.apache\.xpath",
        r"A closing (?:bracket|quote) expected",
        r"Expression must evaluate to a node-set",
        r"SimpleXMLElement::xpath",
        r"xmlXPathEval",
        r"Invalid (?:expression|predicate)",
    ),
)

# ---- LDAP injection -----------------------------------------------------------
# Unbalanced filter parens / invalid DN chars provoke the classic JNDI errors.
_LDAP = SignatureClass(
    family="ldap",
    label="LDAP injection",
    owasp_id="CWE-74",
    payloads=(
        "aidx{m})(|(cn=*",
        "*)(uid=aidx{m}))(|(uid=*",
        "aidx{m}\\",
    ),
    error_signatures=_rx(
        r"javax\.naming\.",
        r"LDAPException",
        r"com\.sun\.jndi\.ldap",
        r"Invalid DN syntax",
        r"supplied argument is not a valid ldap",
        r"Object class violation",
        r"Bad search filter",
        r"Protocol error occurred",
        r"Size limit exceeded",
    ),
)

# ---- NoSQL injection ----------------------------------------------------------
# Operator/JS-break payloads surface Mongo/BSON driver diagnostics.
_NOSQLI = SignatureClass(
    family="nosqli",
    label="NoSQL injection",
    owasp_id="CWE-74",
    payloads=(
        "aidx{m}'||'1'=='1",
        '{"$gt":"aidx{m}"}',
        "aidx{m}';return true;var x='",
    ),
    error_signatures=_rx(
        r"MongoError",
        r"MongoServerError",
        r"E11000 duplicate key",
        r"BSON(?:Error|TypeError)?",
        r"CastError",
        r"couldn't connect to server",
        r"\$where",
        r"unterminated string literal",
        r"SyntaxError:.*(?:JSON|Unexpected token)",
    ),
)

# ---- Server-Side Includes -----------------------------------------------------
# No reliable benign evaluation signal, so SSI stays reflection-only: we send a
# directive carrying the marker and flag when the raw directive comes back
# (input reaches an SSI-parsed surface). Kept honest as a lead, not a confirm.
_SSI = SignatureClass(
    family="ssi",
    label="Server-Side Includes (SSI)",
    owasp_id="CWE-74",
    payloads=(
        '<!--#echo var="aidx{m}" -->',
        '<!--#set var="aidx{m}" value="1" -->',
    ),
    error_signatures=_rx(
        r"\[an error occurred while processing this directive\]",
    ),
)


# ---- JSON injection -----------------------------------------------------------
# Payloads break out of a JSON string context so a server that reconstructs JSON
# from the value emits a parser error; the marker confirms the value reached that
# reconstruction. Distinct from NoSQLi (operator injection) — this is structural.
_JSON = SignatureClass(
    family="json",
    label="JSON injection",
    owasp_id="CWE-74",
    payloads=(
        'aidx{m}","injected":"aidx{m}',
        'aidx{m}"}],"x":[{"y":"1',
        '{"__proto__":{"aidx{m}":true}}',
    ),
    error_signatures=_rx(
        r"Unexpected token",
        r"Unexpected end of (?:JSON|input)",
        r"JSON\.parse",
        r"json\.decoder\.JSONDecodeError",
        r"Malformed (?:JSON|request)",
        r"could not (?:parse|decode) (?:the )?(?:request )?(?:body|json)",
        # NOTE: Python's generic ``Expecting value`` / ``Expecting ',' delimiter``
        # / ``Expecting property name`` messages are deliberately absent. A
        # FastAPI/Pydantic 422 wraps the json error verbatim in ``ctx.error`` for
        # any malformed request body, so matching on them flagged every
        # well-typed endpoint as a JSON-injection lead. ``json.decoder.JSONDecodeError``
        # above is the same class's *name* in a traceback, which the validation
        # envelope never carries.
    ),
)


SIGNATURE_CLASSES: tuple[SignatureClass, ...] = (_XPATH, _LDAP, _NOSQLI, _SSI, _JSON)
