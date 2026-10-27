"""Public exports must not quietly grow private server files or secrets."""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
import yaml

from scripts.package_runner import export

API_ROOT = Path(__file__).resolve().parents[1]


def _repo_root() -> Path:
    """The checkout: ``AIDETECTOR_REPO_ROOT`` (the api container mounts it there),
    else the nearest ancestor holding the workflows. Inside the container the api
    root is ``/app``, which has no checkout above it."""
    override = os.getenv("AIDETECTOR_REPO_ROOT", "").strip()
    candidates = ([Path(override)] if override else []) + list(API_ROOT.parents)
    for candidate in candidates:
        if (candidate / ".github" / "workflows" / "distribution.yml").is_file():
            return candidate
    reason = "no repository checkout is visible (set AIDETECTOR_REPO_ROOT)"
    if os.getenv("CI") or os.getenv("TEST_REQUIRE_DB"):
        pytest.fail(reason)
    pytest.skip(reason)


@pytest.fixture
def repo_root() -> Path:
    return _repo_root()


def test_export_contains_scanner_and_no_server_or_secret_files(tmp_path):
    exported = export(API_ROOT, tmp_path / "runner")
    assert "app/runner/source_audit.py" in exported
    assert "app/engine/checks/__init__.py" in exported
    assert "app/engine/data/payloads/reflection.json" in exported
    forbidden = ("app/api/", "app/models/", "app/workers/", "app/scans/service", "app/ai_runtime/")
    assert not any(name.startswith(forbidden) for name in exported)
    assert "app/main.py" not in exported
    assert "app/core/vault.py" not in exported
    assert "app/core/db.py" not in exported
    assert set(
        p.relative_to(tmp_path / "runner").as_posix()
        for p in (tmp_path / "runner").rglob("*")
        if p.is_file()
    ) == set(exported)


def test_new_files_in_build_context_do_not_get_published(tmp_path):
    source = tmp_path / "source"
    (source / "app").mkdir(parents=True)
    (source / "app/allowed.py").write_text("# safe code")
    (source / "app/private.py").write_text("# private module")
    (source / ".env.production").write_text("DUMMY_SECRET=do-not-publish")
    (source / "runner-files.txt").write_text("app/allowed.py\n")
    assert export(source, tmp_path / "exported") == ["app/allowed.py"]
    assert not (tmp_path / "exported/app/private.py").exists()


@pytest.mark.parametrize(
    "entry", ["../secret.py", "/app/secret.py", "app/.env", "app/*.py", "app/../secret.py"]
)
def test_unsafe_manifest_entries_are_refused(tmp_path, entry):
    (tmp_path / "runner-files.txt").write_text(entry)
    with pytest.raises(ValueError):
        export(tmp_path, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_symlinked_source_is_refused_before_export(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "secret.py").write_text("# dummy private file")
    (tmp_path / "app/allowed.py").symlink_to(tmp_path / "secret.py")
    (tmp_path / "runner-files.txt").write_text("app/allowed.py\n")
    with pytest.raises(ValueError, match="symlink"):
        export(tmp_path, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_scanner_dependency_pins_match_the_api():
    def pins(name):
        return {
            line.strip()
            for line in (API_ROOT / name).read_text().splitlines()
            if line.strip() and not line.startswith("#")
        }

    assert pins("requirements-runner.txt") <= pins("requirements.txt")
    assert not any(
        p.startswith(("sqlalchemy", "alembic", "celery", "redis"))
        for p in pins("requirements-runner.txt")
    )


def test_publication_is_manual_and_never_uses_the_source_repo_for_releases(repo_root):
    workflow = yaml.load(
        (repo_root / ".github/workflows/distribution.yml").read_text(), Loader=yaml.BaseLoader
    )
    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert workflow["on"]["workflow_dispatch"]["inputs"]["publish"]["default"] == "false"
    publish = workflow["jobs"]["publish"]
    assert publish["if"] == "inputs.publish"
    assert "cli" in publish["needs"]
    command = publish["steps"][-1]["run"]
    assert '--repo "$RELEASE_REPOSITORY" --draft' in command
    assert "git archive" not in command
    # The release is authored by the organization's app, not a personal token.
    assert publish["steps"][-1]["env"]["GH_TOKEN"] == "${{ steps.app.outputs.token }}"
    assert "DISTRIBUTION_TOKEN" not in str(workflow)
    for job in ("prepare", "verify", "runner", "cli"):
        assert "DISTRIBUTION_APP_PRIVATE_KEY" not in str(workflow["jobs"][job])


def test_release_builder_rejects_unversioned_images_and_shell_inputs(repo_root):
    spec = importlib.util.spec_from_file_location(
        "cli_release", repo_root / "scripts/build_cli_release.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    digest = "ghcr.io/example/runpentests-runner@sha256:" + "a" * 64
    module.validate("v1.2.3-rc.1", digest)
    for version, image in [
        ("main", digest),
        ("v1.2.3;evil", digest),
        ("v1.2.3", "ghcr.io/example/runner:latest"),
        ("v1.2.3", digest + "\nevil"),
    ]:
        with pytest.raises(ValueError):
            module.validate(version, image)


# --- the exported tree must actually run ----------------------------------------

#: Where the published runner starts. ``__main__`` dispatches to both the scan
#: (``app.runner.main``) and the credential check (``app.runner.auth_check``).
_ENTRY_POINTS = ("app/runner/__main__.py",)

#: Imports a packaged module makes only on a server-lane branch the runner never
#: takes. Each edge is (importer, imported module) so the same target reached from
#: anywhere else still has to be in the manifest. Keep the reason with the edge.
_SERVER_ONLY_EDGES = {
    # Only when no planner was passed; the runner always passes its remote one.
    ("app/engine/execution.py", "app.ai.planner"),
    # Only when the journal carries a database session (server lane).
    ("app/engine/execution.py", "app.ai.budget"),
    ("app/engine/execution.py", "app.engine.ai_phases"),
    # The discovery second pass is reached only from engine/runner.py.
    ("app/engine/execution.py", "app.engine.discovery_probe"),
    # adjudication_key is called only by ai_phases, after a server run.
    ("app/engine/methodology.py", "app.ai.cascade"),
}


def _module_file(root: Path, module: str) -> str | None:
    path = root.joinpath(*module.split("."))
    for candidate in (path / "__init__.py", path.with_suffix(".py")):
        if candidate.is_file():
            return candidate.relative_to(root).as_posix()
    return None


def _app_imports(root: Path, name: str) -> set[str]:
    """Every ``app.*`` module ``name`` imports, at any depth in the file.

    Function-local imports count: preflight is imported inside a function, and
    the export missed it because nothing imported it at module level."""
    tree = ast.parse((root / name).read_text())
    package = name[: -len(".py")].replace("/", ".").rsplit(".", 1)[0]
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parts = package.split(".")[: len(package.split(".")) - (node.level - 1)]
                base = ".".join(parts + ([base] if base else []))
            found.add(base)
            found.update(f"{base}.{alias.name}" for alias in node.names)
    return {m for m in found if m == "app" or m.startswith("app.")}


def test_every_module_the_runner_can_import_is_exported():
    manifest = {
        line.strip()
        for line in (API_ROOT / "runner-files.txt").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }
    seen: set[str] = set()
    todo = list(_ENTRY_POINTS)
    missing: dict[str, set[str]] = {}
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        for module in _app_imports(API_ROOT, name):
            if any(
                importer == name and (module == edge or module.startswith(edge + "."))
                for importer, edge in _SERVER_ONLY_EDGES
            ):
                continue
            parts = module.split(".")
            # `from app.x import y` names y, which may be a module or an attribute.
            for depth in range(1, len(parts) + 1):
                target = _module_file(API_ROOT, ".".join(parts[:depth]))
                if target is None:
                    continue
                if target not in manifest:
                    missing.setdefault(target, set()).add(name)
                todo.append(target)
    assert not missing, (
        "runner-files.txt is missing modules the runner imports: "
        + "; ".join(f"{t} (from {', '.join(sorted(s))})" for t, s in sorted(missing.items()))
    )
    for importer, _module in _SERVER_ONLY_EDGES:
        assert importer in manifest, f"stale server-only edge: {importer} is not exported"


_EXPORTED_ENTRY = textwrap.dedent(
    """
    import json, runpy, sys

    export, mode, result_path = sys.argv[1], sys.argv[2], sys.argv[3]
    absent = set(json.loads(sys.argv[4]))
    sys.path.insert(0, export)

    class _NotInTheImage:
        # Libraries the API ships and the runner image does not: an import of
        # one fails here as it would in the release.
        def find_spec(self, name, path=None, target=None):
            if name.split(".")[0] in absent:
                raise ModuleNotFoundError(f"{name} is not in the runner image", name=name)
            return None

    sys.meta_path.insert(0, _NotInTheImage())

    import httpx
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    import app
    assert app.__file__.startswith(export), app.__file__

    from app.engine.transport import AsyncHttpClientBridge
    from app.runner import auth_check, main as runner

    async def items(request):
        if request.headers.get("authorization") == "Bearer good":
            return JSONResponse([{"id": 1, "name": "one"}])
        return JSONResponse({"detail": "no"}, status_code=401)

    target = Starlette(routes=[Route("/items", items)])

    def bridge(base, **kwargs):
        return AsyncHttpClientBridge(
            base, **{**kwargs, "transport": httpx.ASGITransport(app=target)}
        )

    runner.AsyncHttpClientBridge = bridge
    auth_check.AsyncHttpClientBridge = bridge
    runner._target_pins = lambda run, url: None

    posted = []

    def server(request):
        body = json.loads(request.content or b"{}")
        posted.append({"path": request.url.path, "body": body})
        return httpx.Response(200, json={})

    class Link(runner.ServerLink):
        def __init__(self, server_url, run_id, token, client=None):
            client = httpx.Client(base_url=server_url, transport=httpx.MockTransport(server))
            super().__init__(server_url, run_id, token, client=client)

    runner.ServerLink = Link

    sys.argv = ["app.runner"] + (["--auth-check"] if mode == "auth" else [])
    try:
        runpy.run_module("app.runner", run_name="__main__", alter_sys=True)
        code = 0
    except SystemExit as exc:
        code = exc.code
    with open(result_path, "w") as fh:
        json.dump({"code": code, "posted": posted}, fh)
    """
)

_OPERATION = {"id": "1", "method": "GET", "path": "/items", "params": []}
_CREDENTIAL = {
    "name": "good", "role": "user", "auth_type": "bearer",
    "header_name": None, "grant_type": "static",
}


def _normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _pinned(name: str) -> set[str]:
    return {
        _normalized(re.split(r"[\s\[=<>!~;]", line.strip(), maxsplit=1)[0])
        for line in (API_ROOT / name).read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }


def _not_in_runner_image() -> list[str]:
    """Import names of libraries the API pins and the runner image cannot have:
    neither in requirements-runner.txt nor pulled in by anything that is."""
    from importlib.metadata import PackageNotFoundError, packages_distributions, requires

    shipped: set[str] = set()
    todo = list(_pinned("requirements-runner.txt"))
    while todo:
        name = todo.pop()
        if name in shipped:
            continue
        shipped.add(name)
        try:
            deps = requires(name) or []
        except PackageNotFoundError:
            continue
        todo.extend(
            _normalized(re.split(r"[\s\[=<>!~;(]", dep, maxsplit=1)[0])
            for dep in deps
            if "extra ==" not in dep
        )
    api_only = _pinned("requirements.txt") - shipped
    return sorted(
        module
        for module, dists in packages_distributions().items()
        if {_normalized(d) for d in dists} <= api_only
    )


def _run_exported(tmp_path: Path, mode: str, cfg: dict) -> tuple[dict, str]:
    absent = _not_in_runner_image()
    # The guard must actually guard: the ORM is the API's and never the runner's.
    assert "sqlalchemy" in absent and "celery" in absent, absent
    export(API_ROOT, tmp_path / "runner")
    result = tmp_path / "result.json"
    proc = subprocess.run(
        # -I: no PYTHONPATH, no user site, no cwd on sys.path — only the export.
        [sys.executable, "-I", "-c", _EXPORTED_ENTRY, str(tmp_path / "runner"), mode,
         str(result), json.dumps(absent)],
        input=json.dumps(cfg), capture_output=True, text=True, timeout=120,
        cwd=tmp_path / "runner", env={"PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path)},
    )
    assert result.is_file(), proc.stderr
    return json.loads(result.read_text()), proc.stdout + proc.stderr


@pytest.mark.allow_subprocess
def test_the_exported_tree_runs_the_credential_check(tmp_path):
    cfg = {
        "check": {
            "target_base_url": "http://127.0.0.1",
            "operations": [_OPERATION],
            "credentials": [_CREDENTIAL],
            "max_requests": 10, "requests_per_second": 1000,
        },
        "secrets": {"good": "good"},
    }
    outcome, log = _run_exported(tmp_path, "auth", cfg)
    assert outcome["code"] == 0, log
    assert "ModuleNotFoundError" not in log
    assert '"reachable": true' in log


@pytest.mark.allow_subprocess
def test_the_exported_tree_runs_a_scan_through_preflight_to_upload(tmp_path):
    cfg = {
        "server": "http://server.test",
        "run": {
            "run_id": "r1", "token": "run-token-abc",
            "target_base_url": "http://127.0.0.1",
            "operations": [_OPERATION],
            "credentials": [_CREDENTIAL],
            "max_requests": 30, "requests_per_second": 1000,
            "options": {"checks": ["security_headers"]},
        },
        "secrets": {"good": {"secret": "good"}},
        "runner_version": "export-test",
    }
    outcome, log = _run_exported(tmp_path, "scan", cfg)
    assert outcome["code"] == 0, log
    completes = [p["body"] for p in outcome["posted"] if p["path"].endswith("/complete")]
    assert len(completes) == 1, log
    bundle = completes[0]
    assert bundle["gaps"]["failed_checks"] == [], log
    # Preflight ran (it is imported lazily, so only a real run proves it shipped).
    assert any(row.get("check") == "preflight" for row in bundle["trace"]), log
