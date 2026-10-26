"""Public exports must not quietly grow private server files or secrets."""

from __future__ import annotations

import importlib.util
import os
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
