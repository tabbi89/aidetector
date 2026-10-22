"""Public exports must not quietly grow private server files or secrets."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
import yaml

from scripts.package_runner import export

API_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = API_ROOT.parents[1]


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


def test_publication_is_manual_and_never_uses_the_source_repo_for_releases():
    workflow = yaml.load(
        (REPO_ROOT / ".github/workflows/distribution.yml").read_text(), Loader=yaml.BaseLoader
    )
    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert workflow["on"]["workflow_dispatch"]["inputs"]["publish"]["default"] == "false"
    publish = workflow["jobs"]["publish"]
    assert publish["if"] == "inputs.publish"
    assert "cli" in publish["needs"]
    command = publish["steps"][-1]["run"]
    assert '--repo "$RELEASE_REPOSITORY" --draft' in command
    assert "git archive" not in command
    for job in ("verify", "runner", "cli"):
        assert "DISTRIBUTION_TOKEN" not in str(workflow["jobs"][job])


def test_release_builder_rejects_unversioned_images_and_shell_inputs():
    spec = importlib.util.spec_from_file_location(
        "cli_release", REPO_ROOT / "scripts/build_cli_release.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    digest = "ghcr.io/example/aidetector-runner@sha256:" + "a" * 64
    module.validate("v1.2.3-rc.1", digest)
    for version, image in [
        ("main", digest),
        ("v1.2.3;evil", digest),
        ("v1.2.3", "ghcr.io/example/runner:latest"),
        ("v1.2.3", digest + "\nevil"),
    ]:
        with pytest.raises(ValueError):
            module.validate(version, image)
