"""Finding taxonomy labels are canonical without invalidating identity."""
from __future__ import annotations

import pytest

from app.domain.enums import Severity
from app.domain.taxonomy import canonical_taxonomy_id
from app.engine.base import EngineFinding
from app.engine.fingerprint import fingerprint


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("API1", "API1:2023"),
        ("API10:2023", "API10:2023"),
        ("INJ", "CWE-74"),
        ("CWE-89", "CWE-89"),
        (None, None),
    ],
)
def test_taxonomy_aliases_have_one_public_spelling(raw, expected):
    assert canonical_taxonomy_id(raw) == expected


def test_engine_finding_canonicalizes_at_the_boundary():
    finding = EngineFinding(
        check="bola",
        owasp_id="API1",
        severity=Severity.high,
        title="BOLA",
        description="",
        evidence={"route": "/accounts/{id}"},
    )
    assert finding.owasp_id == "API1:2023"


def test_taxonomy_cleanup_does_not_change_existing_fingerprints():
    evidence = {"method": "GET", "route": "/accounts/{id}"}
    assert fingerprint("bola", "API1", "BOLA", evidence) == fingerprint(
        "bola", "API1:2023", "BOLA", evidence
    )
    assert fingerprint("reflected_injection", "INJ", "lead", evidence) == fingerprint(
        "reflected_injection", "CWE-74", "lead", evidence
    )


def test_unknown_taxonomy_label_is_rejected():
    with pytest.raises(ValueError, match="unsupported finding taxonomy"):
        canonical_taxonomy_id("API8-latest")
