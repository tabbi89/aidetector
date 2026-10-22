"""The dependency rule, enforced: pure decision modules must not need the ORM.

``app/domain/`` holds the vocabulary every layer agrees on, and the engine's
policy modules decide things with it. None of them has any business importing
SQLAlchemy — but for a long time all of them did, transitively, because
``Severity`` and ``Confidence`` were declared inside ``app/models/finding.py``.
Nothing failed; the import just quietly dragged the declarative ``Base`` registry
into every check.

That is the kind of regression a normal test suite cannot see, because the code
still works. So this asserts it structurally, in a subprocess with SQLAlchemy
blocked at the import hook. A module listed here that starts importing an ORM row
— or a domain module that starts importing the engine — fails at the layer it
broke, and names it.
"""
from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest

pytestmark = pytest.mark.allow_subprocess

#: Modules whose job is to decide something, not to persist it. Each must import
#: with SQLAlchemy unavailable.
PURE_MODULES = [
    "app.domain.enums",
    "app.domain.privilege",
    "app.domain.sensitive",
    "app.engine.header_policy",
    "app.engine.exposure_policy",
    "app.engine.fingerprint",
    "app.engine.remediation",
    "app.engine.signatures",
    "app.engine.payloads",
    "app.engine.payload_corpus",
    "app.engine.spec_values",
    # Shared by resource setup and every create probe; both lanes build bodies.
    "app.engine.request_bodies",
    "app.engine.evidence",
    # Free of the ORM since the credential enums moved to the domain.
    "app.engine.base",
    # The DB-free run core, so the local runner can execute checks without a DB.
    "app.engine.execution",
    # The adjunct phase core runs in the runner too: keep it ORM-free.
    "app.engine.adjunct_run",
    # The local runner executes a scan with no database: prove it never needs one.
    "app.runner.main",
    "app.runner.source_audit",
    # Schema context is read inside the runner: the reader, the adapter and the
    # upload contract must never pull the ORM in with them.
    "app.runner.schema",
    "app.db_schema.postgres",
    "app.db_schema.contracts",
    # The heavy-lane agent runs inside the DB-free runner: keep it pure too.
    "app.agent.source",
    "app.agent.sandbox",
    "app.agent.loop",
    "app.agent.memory",
]

_PROBE = textwrap.dedent(
    """
    import sys, importlib

    class _Blocker:
        '''Raise on any sqlalchemy import, wherever in the chain it happens.

        find_spec, not the find_module/load_module pair — that legacy hook was
        removed in 3.12, so a blocker written against it silently does nothing
        and every module "passes".
        '''
        def find_spec(self, name, path=None, target=None):
            if name.split(".")[0] == "sqlalchemy":
                raise ImportError(name)
            return None

    sys.meta_path.insert(0, _Blocker())
    try:
        importlib.import_module({module!r})
    except ImportError as exc:
        print(f"pulls in sqlalchemy via {{exc}}")
        raise SystemExit(1)
    raise SystemExit(0)
    """
)


@pytest.mark.parametrize("module", PURE_MODULES)
def test_pure_module_does_not_need_sqlalchemy(module: str) -> None:
    """A decision module that needs the ORM has the dependency arrow backwards."""
    result = subprocess.run(
        [sys.executable, "-c", _PROBE.format(module=module)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"{module} cannot be imported without SQLAlchemy — {result.stdout.strip()}. "
        "Pure policy must not depend on persistence: take the vocabulary it needs "
        "from app/domain/ rather than from app/models/."
    )


def test_domain_imports_nothing_from_the_app() -> None:
    """``app/domain`` is the bottom of the graph — it may depend on nothing here.

    Checked on the source text rather than by importing, so an import added
    inside a function body is caught too.
    """
    from pathlib import Path

    domain = Path(__file__).resolve().parents[1] / "app" / "domain"
    offenders: list[str] = []
    for path in sorted(domain.rglob("*.py")):
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            stripped = line.strip()
            if not stripped.startswith(("import ", "from ")):
                continue
            if "sqlalchemy" in stripped or "fastapi" in stripped:
                offenders.append(f"{path.name}:{lineno} {stripped}")
            elif stripped.startswith(("from app.", "import app.")):
                # app.domain may import from itself; nothing else.
                if not stripped.startswith(("from app.domain", "import app.domain")):
                    offenders.append(f"{path.name}:{lineno} {stripped}")
    assert not offenders, (
        "app/domain/ must not depend on the rest of the app:\n  "
        + "\n  ".join(offenders)
    )


def test_models_finding_no_longer_re_exports_the_vocabulary() -> None:
    """The re-export was a one-release migration aid; it is gone.

    Keeping it would let a new module reach ``Severity`` through the ORM again,
    which is exactly the coupling this move removed.
    """
    import app.models.finding as mf

    assert mf.__all__ == ["Finding", "sort_findings"]


@pytest.mark.parametrize("module", ["app.models.finding", "app.engine.run_record"])
def test_the_blocker_actually_blocks(module: str) -> None:
    """The guard above is only meaningful if it can fail.

    A module that genuinely needs the ORM must be reported. Without this, a
    blocker wired to a removed import hook would let every module "pass" —
    which is exactly what happened when this file was first written against
    ``find_module``/``load_module``.
    """
    result = subprocess.run(
        [sys.executable, "-c", _PROBE.format(module=module)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1, f"{module} should need SQLAlchemy but did not"
    assert "sqlalchemy" in result.stdout
