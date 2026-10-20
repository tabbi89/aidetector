"""When a reflected payload counts as *unneutralised* — the reflection oracle.

``Attempt.reflected`` decides every finding the two reflection checks produce,
and it used to be one line: is the marker in the response body. That cannot
distinguish the two cases it most needs to:

- an endpoint that hands the payload back verbatim (a real lead), from
- an endpoint that escaped it correctly and returned the harmless remains.

The ``aidx<hex>`` marker is deliberately alphanumeric so it survives transport
intact — which means it also survives HTML escaping, JSON encoding and quote
stripping. So an endpoint doing the textbook-correct thing reported as a lead,
and a precision gate over a hardened API produced 39 findings.

These are the rules that replaced it, each with the case that motivated it.
"""
from __future__ import annotations

from app.engine.base import ProbeResult, TargetOperation
from app.engine.injection_probe import Attempt
from app.engine.spec_values import InjectionPoint


def attempt(payload: str, body: str, *, status: int = 200, marker: str = "aidxdeadbeef") -> Attempt:
    """One delivered payload and the response it drew."""
    return Attempt(
        op=TargetOperation(id="op", method="GET", path="/x"),
        point=InjectionPoint(name="q", location="query", schema={}),
        index=0,
        needle=marker,
        value=payload,
        path="/x",
        response=ProbeResult(status=status, headers={}, text=body, elapsed_ms=1.0),
    )


# ---- The baseline: no echo at all ---------------------------------------------


def test_a_marker_that_never_came_back_is_not_reflected():
    assert attempt("<b>aidxdeadbeef</b>", "nothing here").reflected is False


def test_echoed_reports_the_raw_fact_reflected_grades():
    """The two are deliberately different questions."""
    escaped = attempt("<script>aidxdeadbeef</script>", "&lt;script&gt;aidxdeadbeef&lt;/script&gt;")
    assert escaped.echoed is True      # the marker did come back
    assert escaped.reflected is False  # but the markup did not


# ---- Rule 1: structure must survive -------------------------------------------


def test_a_verbatim_echo_is_reflected():
    assert attempt("<script>aidxdeadbeef</script>", "<script>aidxdeadbeef</script>").reflected


def test_html_escaping_defeats_reflection():
    """The case that produced an XSS lead on every correctly-escaping endpoint."""
    body = "<html><body>Results for: &lt;script&gt;aidxdeadbeef&lt;/script&gt;</body></html>"
    assert attempt("<script>aidxdeadbeef</script>", body).reflected is False


def test_json_encoding_does_not_defeat_reflection():
    """JSON escapes quotes and backslashes — markup passes straight through.

    A JSON API that echoes ``<script>`` into a string is still reflecting it;
    only the transport quoting changed.
    """
    body = '{"q":"<script>aidxdeadbeef</script>"}'
    assert attempt("<script>aidxdeadbeef</script>", body).reflected


def test_a_payload_with_no_structure_is_reflected_on_a_bare_echo():
    """Some families send little more than the marker; there is nothing to strip."""
    assert attempt("aidxdeadbeef", "you searched for aidxdeadbeef").reflected


def test_case_folding_the_echo_is_not_neutralisation():
    """A target that uppercases output has still reflected the payload."""
    assert attempt("aidxdeadbeef", "you searched for AIDXDEADBEEF").reflected
    assert attempt("<b>aidxdeadbeef</b>", "<B>AIDXDEADBEEF</B>").reflected


# ---- Rule 2: structure must survive *near the marker* --------------------------


def test_the_pages_own_markup_does_not_count_as_surviving_structure():
    """Why the check is windowed rather than document-wide.

    Every HTML page contains ``<``. Searching the whole body for a surviving
    metacharacter would call every escaped reflection unneutralised — which is
    the bug this rule exists to prevent, reintroduced.
    """
    body = "<html><body><h1>Search</h1><p>Results: &lt;img&gt;aidxdeadbeef</p></body></html>"
    assert attempt("<img>aidxdeadbeef", body).reflected is False


def test_structure_adjacent_to_the_marker_does_count():
    body = "<p>Results: <img>aidxdeadbeef</p>"
    assert attempt("<img>aidxdeadbeef", body).reflected


def test_html_entities_do_not_satisfy_the_structural_test():
    """``&`` and ``;`` are excluded from the structural set for exactly this.

    Every entity is built from them, so including them would make *escaping
    itself* prove the payload survived.
    """
    body = "Results: &#x27;aidxdeadbeef&#x27; &quot;x&quot;"
    assert attempt("'aidxdeadbeef'", body).reflected is False


# ---- Rule 3: a percent-encoded payload must have decoded -----------------------


def test_an_escape_returned_verbatim_proves_it_was_not_decoded():
    """``%0d%0a`` is inert text until something turns it into a newline."""
    body = "<body>user: %0d%0aX-aidxdeadbeef:1</body>"
    assert attempt("%0d%0aX-aidxdeadbeef:1", body).reflected is False


def test_traversal_escapes_returned_verbatim_are_not_reflection():
    body = "<body>user: ..%2f..%2faidxdeadbeef</body>"
    assert attempt("..%2f..%2faidxdeadbeef", body).reflected is False


def test_a_decoded_escape_is_reflection():
    """The target *did* decode it — that is the finding the rule must keep."""
    body = "<body>user: ../../aidxdeadbeef</body>"
    assert attempt("..%2f..%2faidxdeadbeef", body).reflected


def test_a_decoded_crlf_is_reflection():
    assert attempt("%0d%0aX-aidxdeadbeef:1", "ok\r\nX-aidxdeadbeef:1").reflected


# ---- Multiple echoes ----------------------------------------------------------


def test_any_one_unneutralised_echo_is_enough():
    """A body that escapes one occurrence and not another is still vulnerable."""
    body = "safe: &lt;b&gt;aidxdeadbeef&lt;/b&gt; ... raw: <b>aidxdeadbeef</b>"
    assert attempt("<b>aidxdeadbeef</b>", body).reflected
