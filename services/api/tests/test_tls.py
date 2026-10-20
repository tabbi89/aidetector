"""TLS analyzer tests — pure `analyze_tls` against certs built in-memory.

No network: certificates are generated with `cryptography`, so the cert-hygiene
logic is exercised deterministically. The socket-handshake shell in
`TlsConfigCheck.run` is thin I/O around this and is not unit-tested here.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.domain.enums import Severity
from app.engine.checks.tls import analyze_tls


def _cert(cn, *, days_from, days_to, key_size=2048, sans=None, issuer_cn=None):
    """Build a cert. Self-signed unless issuer_cn is given (issuer != subject)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)])
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + timedelta(days=days_from))
        .not_valid_after(now + timedelta(days=days_to))
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
    return builder.sign(key, hashes.SHA256())


class _SigProxy:
    """Wrap a real cert but override its signature hash — SHA1 can't be signed."""

    def __init__(self, cert, sig_name):
        self._c = cert
        self._sig = type("H", (), {"name": sig_name})()

    def __getattr__(self, name):
        return getattr(self._c, name)

    @property
    def signature_hash_algorithm(self):
        return self._sig


def test_analyze_flags_expired_selfsigned_mismatch_and_weakkey():
    cert = _cert(
        "example.com", days_from=-40, days_to=-10,  # expired, self-signed
        key_size=1024, sans=["example.com"],
    )
    findings = analyze_tls(
        "api.target.test", cert,  # host does not match example.com
        negotiated_protocol="TLSv1",  # deprecated
        cipher_name="AES256-SHA", cipher_bits=256,
    )
    assert all(f.check == "tls_config" and f.owasp_id == "API8:2023" for f in findings)
    titles = " ".join(f.title.lower() for f in findings)
    assert "expired" in titles
    assert "self-signed" in titles
    assert "does not match" in titles
    assert "weak public key" in titles
    assert "deprecated tls" in titles
    assert any(f.severity == Severity.high for f in findings)


def test_analyze_clean_cert_has_no_findings():
    cert = _cert("good.test", days_from=-1, days_to=365, sans=["good.test"],
                 issuer_cn="Test CA")
    findings = analyze_tls(
        "good.test", cert,
        negotiated_protocol="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384", cipher_bits=256,
        supports_deprecated_tls=False,
    )
    assert findings == []


def test_analyze_wildcard_san_matches_but_flags_hygiene():
    # A wildcard legitimately matches the subdomain (no mismatch finding), but
    # the check still reports the wildcard itself as a low hygiene finding.
    cert = _cert("*.target.test", days_from=-1, days_to=365, sans=["*.target.test"],
                 issuer_cn="Test CA")
    findings = analyze_tls(
        "api.target.test", cert,
        negotiated_protocol="TLSv1.2", cipher_name="ECDHE-RSA-AES128-GCM-SHA256",
        cipher_bits=128,
    )
    assert len(findings) == 1
    assert findings[0].severity == Severity.low
    assert "wildcard" in findings[0].title.lower()
    assert "*.target.test" in findings[0].evidence["wildcards"]


def test_analyze_expiring_soon_is_low():
    cert = _cert("good.test", days_from=-1, days_to=7, sans=["good.test"],
                 issuer_cn="Test CA")
    findings = analyze_tls("good.test", cert, negotiated_protocol="TLSv1.2",
                           cipher_name="ECDHE-RSA-AES128-GCM-SHA256", cipher_bits=128)
    assert len(findings) == 1
    assert findings[0].severity == Severity.low
    assert "expires soon" in findings[0].title.lower()


def test_analyze_weak_cipher():
    cert = _cert("good.test", days_from=-1, days_to=365, sans=["good.test"],
                 issuer_cn="Test CA")
    findings = analyze_tls("good.test", cert, negotiated_protocol="TLSv1.2",
                           cipher_name="RC4-MD5", cipher_bits=40)
    assert len(findings) == 1
    assert "weak tls cipher" in findings[0].title.lower()


def test_analyze_weak_signature_hash():
    cert = _cert("good.test", days_from=-1, days_to=365, sans=["good.test"],
                 issuer_cn="Test CA")
    findings = analyze_tls("good.test", _SigProxy(cert, "sha1"),
                           negotiated_protocol="TLSv1.2",
                           cipher_name="ECDHE-RSA-AES128-GCM-SHA256", cipher_bits=128)
    assert len(findings) == 1
    assert "signature algorithm" in findings[0].title.lower()


# ---- rule decomposition ------------------------------------------------------
#
# ``analyze_tls`` is a fold over ``RULES``, so each rule can be exercised against
# only the facts it reads. These cover the seams the decomposition introduced,
# not every rule again — the end-to-end cases above already do that.


def _facts(cert, **kw):
    """A TlsFacts with sensible defaults, for testing one rule at a time."""
    from app.engine.checks.tls import TlsFacts, _cert_names

    defaults = dict(
        host="good.test",
        cert=cert,
        negotiated_protocol="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        supports_deprecated_tls=False,
        now=datetime.now(UTC),
        names=_cert_names(cert),
    )
    return TlsFacts(**{**defaults, **kw})


def test_expired_and_expiring_soon_are_mutually_exclusive():
    """The one coupling the decomposition had to preserve.

    These were the two arms of a single if/elif. As separate rules,
    ``_expiring_soon`` re-asserts "not already expired" itself — without that,
    an expired certificate would report twice.
    """
    from app.engine.checks.tls import _expired, _expiring_soon

    expired = _cert("good.test", days_from=-40, days_to=-1, sans=["good.test"])
    assert _expired(_facts(expired)) is not None
    assert _expiring_soon(_facts(expired)) is None

    soon = _cert("good.test", days_from=-40, days_to=3, sans=["good.test"])
    assert _expired(_facts(soon)) is None
    assert _expiring_soon(_facts(soon)) is not None

    healthy = _cert("good.test", days_from=-40, days_to=365, sans=["good.test"])
    assert _expired(_facts(healthy)) is None
    assert _expiring_soon(_facts(healthy)) is None


def test_an_expired_cert_yields_exactly_one_expiry_finding():
    """The same property through the public entry point."""
    cert = _cert("good.test", days_from=-40, days_to=-1, sans=["good.test"])
    findings = analyze_tls("good.test", cert, negotiated_protocol="TLSv1.3",
                           cipher_name="TLS_AES_256_GCM_SHA384", cipher_bits=256)
    expiry = [f for f in findings if "expire" in f.title.lower()]
    assert len(expiry) == 1
    assert expiry[0].severity is Severity.high


def test_every_rule_returns_none_for_a_healthy_certificate():
    """Each rule independently has nothing to say about a good cert.

    Guards the decomposition against a rule whose guard clause is inverted — it
    would still pass an end-to-end test that only counts findings.
    """
    from app.engine.checks.tls import RULES

    cert = _cert("good.test", days_from=-1, days_to=365, sans=["good.test"],
                 issuer_cn="Some CA")
    facts = _facts(cert)
    fired = [rule.__name__ for rule in RULES if rule(facts) is not None]
    assert fired == []


def test_rule_order_is_report_order():
    """Evaluation order is the order the fused function used, and is a contract.

    Findings are rendered in this order before ``sort_findings`` regrades them,
    so a reshuffle is user-visible.
    """
    from app.engine.checks.tls import RULES

    assert [r.__name__ for r in RULES] == [
        "_expired", "_expiring_soon", "_not_yet_valid", "_self_signed",
        "_hostname_mismatch", "_wildcard", "_weak_signature", "_weak_key",
        "_weak_cipher", "_deprecated_protocol",
    ]


def test_every_rule_carries_the_shared_evidence():
    """``TlsFacts.ev`` is the base every finding extends — host/protocol/cipher."""
    cert = _cert("other.test", days_from=-40, days_to=-1, key_size=1024,
                 sans=["other.test"])
    findings = analyze_tls("good.test", cert, negotiated_protocol="TLSv1",
                           cipher_name="RC4-MD5", cipher_bits=64)
    assert findings
    for f in findings:
        assert f.evidence["host"] == "good.test"
        assert f.evidence["protocol"] == "TLSv1"
        assert f.evidence["cipher"] == "RC4-MD5"
