"""Guard the hand-maintained mirrors of the engine against drift.

``apps/web/lib/coverage.ts`` and the run-options contract are written by hand to
describe what the engine does. Nothing generates them, so they rot silently: a
check added to ``ALL_CHECKS`` without a coverage entry ships a scanner that
tests something the docs never mention, and a run flag the UI never sends is a
feature nobody can reach.

These tests are deliberately shallow — they assert *presence*, not prose. Their
job is to fail when someone adds a check, a flag or a source file and forgets
the mirror, not to police wording.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from app.domain.enums import Confidence
from app.engine.checks import ALL_CHECKS
from app.scans.run_options import RunOptions, required_passes
from tests.harness import database_required


def _repo_root() -> Path:
    """The checkout holding ``apps/web``: ``AIDETECTOR_REPO_ROOT`` (the api
    container mounts the repo read-only there), else the nearest ancestor of
    this file that has it. Falls back to the api root, where the web tree is
    absent and the fixture below decides what that means."""
    here = Path(__file__).resolve()
    override = os.getenv("AIDETECTOR_REPO_ROOT", "").strip()
    candidates = ([Path(override)] if override else []) + list(here.parents)
    for candidate in candidates:
        if (candidate / "apps" / "web" / "lib" / "coverage.ts").is_file():
            return candidate
    return here.parents[1]


REPO = _repo_root()
WEB = REPO / "apps" / "web"
COVERAGE_TS = WEB / "lib" / "coverage.ts"
API_TS = WEB / "lib" / "api.ts"
#: The client was split into a transport + feature modules; the barrel re-exports
#: them. A mirror test that reads only the barrel would see an empty surface.
API_SOURCES = [API_TS, *sorted((WEB / "lib" / "api").glob("*.ts"))]


def _api_text() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in API_SOURCES)
SCOPE_TS = WEB / "app" / "components" / "checkScope.ts"
#: Needs the scope picker derives from run flags; ``oast`` is a deployment setting.
_FLAG_NEEDS = frozenset({"mutate", "premium", "fuzz"})


def _scope_entries() -> list[tuple[str, set[str]]]:
    """(key, needs) for every check the run-scope picker offers."""
    pattern = (
        r'\{\s*key:\s*"([^"]+)",\s*label:\s*"[^"]*"'
        r"(?:,\s*needs:\s*\[([^\]]*)\])?\s*\}"
    )
    return [
        (key, set(re.findall(r'"([^"]+)"', needs)))
        for key, needs in re.findall(pattern, SCOPE_TS.read_text(encoding="utf-8"))
    ]


def test_run_scope_picker_offers_every_check_once_with_its_true_needs():
    """A check missing from the picker can't be scoped to; a wrong need misleads."""
    entries = _scope_entries()
    keys = [key for key, _ in entries]
    registered = {c.key for c in ALL_CHECKS}
    assert len(keys) == len(set(keys)), "a check appears in two scope groups"
    assert set(keys) == registered, (
        f"checkScope.ts drifted from the registry: missing {sorted(registered - set(keys))}, "
        f"stale {sorted(set(keys) - registered)}"
    )
    wrong = {
        key: (sorted(needs & _FLAG_NEEDS), sorted(required_passes(key) & _FLAG_NEEDS))
        for key, needs in entries
        if needs & _FLAG_NEEDS != required_passes(key) & _FLAG_NEEDS
    }
    assert not wrong, f"checkScope.ts needs disagree with the checks (declared, actual): {wrong}"

@pytest.fixture(autouse=True)
def _web_tree_present() -> None:
    """Without the web tree there is nothing to compare against. Locally that
    skips; under CI / TEST_REQUIRE_DB it fails, so the mirror gate cannot
    vanish from a run just because the checkout was partial."""
    if COVERAGE_TS.exists():
        return
    reason = (
        f"apps/web not found from {Path(__file__).resolve()}; set "
        "AIDETECTOR_REPO_ROOT to the repository checkout"
    )
    if database_required():
        pytest.fail(reason)
    pytest.skip(reason)


def _coverage_text() -> str:
    return COVERAGE_TS.read_text(encoding="utf-8")


def _documented_keys() -> set[str]:
    """The engine check keys coverage.ts claims to describe."""
    return set(re.findall(r'^\s*key:\s*"([^"]+)"', _coverage_text(), re.MULTILINE))


def test_every_engine_check_is_described_in_coverage_ts():
    """A check the UI never mentions is a capability users can't discover."""
    missing = sorted({c.key for c in ALL_CHECKS} - _documented_keys())
    assert not missing, (
        f"checks missing from apps/web/lib/coverage.ts: {missing}. "
        "coverage.ts is a hand-maintained mirror of the engine — add an entry "
        'carrying `key: "<check key>"`.'
    )


def test_coverage_ts_describes_no_check_that_left_the_registry():
    """A key here that no longer exists means the page documents a dead check."""
    stale = sorted(_documented_keys() - {c.key for c in ALL_CHECKS})
    assert not stale, (
        f"apps/web/lib/coverage.ts documents checks that are not registered: {stale}"
    )


def test_coverage_ts_source_paths_all_exist():
    """Every `source:` breadcrumb must point at a file that is still there."""
    text = _coverage_text()
    unresolved: list[str] = []
    for raw in re.findall(r'source:\s*"([^"]+)"', text):
        # One entry may credit several files, separated by "·" or ",".
        for part in re.split(r"[·,]", raw):
            ref = part.strip()
            if not ref:
                continue
            candidates = [
                REPO / ref,                        # e.g. "services/kali"
                REPO / "services" / "api" / "app" / ref,   # "engine/checks/x.py"
                REPO / "services" / "api" / "app" / "engine" / ref,  # "checks/x.py"
            ]
            if not any(c.exists() for c in candidates):
                unresolved.append(ref)
    assert not unresolved, f"coverage.ts references missing files: {sorted(set(unresolved))}"


def test_every_run_option_is_reachable_from_the_web_client():
    """A run flag the API client can't send is a feature no user can turn on."""
    api_text = _api_text()
    missing = [name for name in RunOptions().to_dict() if name not in api_text]
    assert not missing, (
        f"run options absent from apps/web/lib/api.ts: {missing}. "
        "Every flag on RunOptions must be settable by the UI."
    )


LEVELS_TS = WEB / "app" / "components" / "scanLevels.ts"


def _web_levels() -> dict[str, tuple[tuple[str, ...], tuple[str, ...]]]:
    """id -> (passes, aiPasses) as ``scanLevels.ts`` declares them."""
    text = LEVELS_TS.read_text(encoding="utf-8")
    levels: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {}
    for block in re.split(r'(?=\bid:\s*")', text)[1:]:
        level = re.match(r'id:\s*"([^"]+)"', block)
        passes = re.search(r"\bpasses:\s*\[([^\]]*)\]", block)
        ai = re.search(r"\baiPasses:\s*\[([^\]]*)\]", block)
        assert level and passes and ai, f"unparseable level block in scanLevels.ts: {block[:80]!r}"
        levels[level.group(1)] = (
            tuple(re.findall(r'"([^"]+)"', passes.group(1))),
            tuple(re.findall(r'"([^"]+)"', ai.group(1))),
        )
    return levels


def test_web_scan_levels_match_the_server_expansion():
    """The level picker says what a level turns on; the server decides it. They must agree."""
    from app.scans.run_levels import LEVEL_AI_PASSES, LEVEL_PASSES, LEVELS

    web = _web_levels()
    assert list(web) == list(LEVELS), "scanLevels.ts must list every level, in order"
    for level in LEVELS:
        passes, ai = web[level]
        assert set(passes) == set(LEVEL_PASSES[level]), level
        assert set(ai) == set(LEVEL_AI_PASSES[level]), level


def test_the_web_client_can_send_a_level_and_the_ai_switch():
    api_text = _api_text()
    assert re.search(r"\blevel\??:", api_text) and re.search(r"\bai\??:", api_text)


def test_run_options_round_trip_through_the_queue():
    """Options survive JSON serialisation, and unknown flags are ignored."""
    opts = RunOptions(
        mutate=True,
        confirm=True,
        plan=True,
        premium=True,
        resource_refine=True,
        resource_attempts=2,
        predefined_resource_ids={"merchant": "merchant_123"},
    )
    assert RunOptions.from_dict(opts.to_dict()) == opts
    # A newer API enqueuing a flag this worker doesn't know must not crash it.
    assert RunOptions.from_dict({"mutate": True, "flag_from_the_future": True}) == (
        RunOptions(mutate=True)
    )
    assert RunOptions.from_dict(None) == RunOptions()
    assert RunOptions().enabled == []
    assert opts.enabled == ["confirm", "mutate", "plan", "premium", "resource_refine"]


def test_run_request_carries_premium_into_the_worker_options():
    """The API request must forward premium, or the paid checks are unreachable."""
    from app.api.schemas import RunRequest

    opts = RunRequest(authorized=True, premium=True).to_options()
    assert opts.premium is True
    assert RunRequest(authorized=True).to_options().premium is False


def test_run_request_validates_and_forwards_predefined_resource_ids():
    from pydantic import ValidationError

    from app.api.schemas import RunRequest

    request = RunRequest(
        authorized=True,
        predefined_resource_ids={" merchant_id ": " existing-42 "},
    )
    assert request.to_options().predefined_resource_ids == {
        "merchant_id": "existing-42"
    }
    with pytest.raises(ValidationError):
        RunRequest(authorized=True, predefined_resource_ids={"merchant": "../escape"})


def test_predefined_resource_ids_schema_describes_what_is_accepted():
    """The published grammar must be a *subset* of what the endpoint accepts.

    It was neither: the schema advertised a bare object while a validator
    rejected almost every key, so a client generating from the schema produced
    422s against a contract promising 202. ``additionalProperties`` is the half
    that matters — ``patternProperties`` alone still permits every key that does
    not match.
    """
    from app.api.schemas import RunRequest

    field = RunRequest.model_json_schema()["properties"]["predefined_resource_ids"]
    assert field["additionalProperties"] is False
    assert field["maxProperties"] == 50
    (value_schema,) = field["patternProperties"].values()
    assert value_schema["minLength"] == 1 and value_schema["maxLength"] == 256


def test_padding_is_tolerated_but_not_advertised():
    """Trimming happens before the grammar runs, so padding stays accepted.

    That asymmetry is deliberate and is what keeps the schema a subset: anything
    the schema permits is accepted, and a little more besides.
    """
    import re

    from app.api.schemas import RunRequest

    field = RunRequest.model_json_schema()["properties"]["predefined_resource_ids"]
    (key_pattern,) = field["patternProperties"]

    assert not re.match(key_pattern, " merchant_id ")  # not described
    accepted = RunRequest(
        authorized=True, predefined_resource_ids={" merchant_id ": " existing-42 "}
    ).predefined_resource_ids
    assert accepted == {"merchant_id": "existing-42"}  # but accepted
    assert re.match(key_pattern, "merchant_id")  # and its trimmed form is described


def test_finding_confidence_vocabulary_matches_the_web_client():
    """`FindingConfidence` in api.ts is the enum, spelled in TypeScript.

    A tier the UI cannot name is a tier it renders as undefined, so the two
    move together or not at all.
    """
    api_text = _api_text()
    match = re.search(r"export type FindingConfidence =([^;]+);", api_text)
    assert match, "apps/web/lib/api.ts must declare a FindingConfidence union"
    declared = set(re.findall(r'"([^"]+)"', match.group(1)))
    assert declared == {c.value for c in Confidence}, (
        f"FindingConfidence in api.ts is {sorted(declared)}, "
        f"Confidence is {sorted(c.value for c in Confidence)}"
    )


def test_retest_knows_every_confirm_only_signal():
    """`runpentests retest` refuses to spend a run that could only come back not
    retested; it must recognise every signal the diff treats as confirm-only."""
    from app.scans.run_options import CONFIRM_SIGNALS

    retest = REPO / "cli" / "internal" / "commands" / "retest.go"
    if not retest.is_file():
        reason = "the CLI tree is not visible (set AIDETECTOR_REPO_ROOT)"
        if os.getenv("CI") or os.getenv("TEST_REQUIRE_DB"):
            pytest.fail(reason)
        pytest.skip(reason)
    block = re.search(r"confirmSignals = map\[string\]bool\{([^}]*)\}", retest.read_text())
    assert block, "confirmSignals not found in retest.go"
    assert set(re.findall(r'"([^"]+)":\s*true', block.group(1))) == set(CONFIRM_SIGNALS)
