"""Canonical public labels for finding security classifications.

``owasp_id`` is a legacy column name: external adjuncts also put CWE labels in
it. Keep both recognized taxonomies unambiguous, but never emit the historical
bare ``API1``/``INJ`` aliases in new findings or reports.
"""
from __future__ import annotations

import re

_API = re.compile(r"API(10|[1-9])(?::2023)?\Z", re.IGNORECASE)
_CWE = re.compile(r"CWE-([1-9][0-9]*)\Z", re.IGNORECASE)


def canonical_taxonomy_id(value: str | None) -> str | None:
    """Return an OWASP API 2023 or CWE label in its canonical public form."""
    if value is None:
        return None
    stripped = value.strip()
    api = _API.fullmatch(stripped)
    if api:
        return f"API{api.group(1)}:2023"
    cwe = _CWE.fullmatch(stripped)
    if cwe:
        return f"CWE-{cwe.group(1)}"
    if stripped.upper() == "INJ":
        return "CWE-74"
    raise ValueError(f"unsupported finding taxonomy id: {value!r}")


def fingerprint_taxonomy_id(value: str | None, *, dated_api: bool = False) -> str:
    """Legacy-stable spelling used only in stored finding fingerprints.

    Fingerprints predate canonical labels and include this value. Returning the
    historical alias prevents taxonomy cleanup from invalidating triage and
    turning every finding into fixed+new on the next scan.
    """
    canonical = canonical_taxonomy_id(value)
    if canonical is None:
        return ""
    if canonical == "CWE-74":
        return "INJ"
    if canonical.startswith("API"):
        return canonical if dated_api else canonical.removesuffix(":2023")
    return canonical
