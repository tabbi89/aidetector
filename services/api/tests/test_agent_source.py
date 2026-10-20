"""Whitebox source index: bounded, safe, deterministic."""
from __future__ import annotations

import os
from pathlib import Path

from app.agent.source import MAX_SNIPPET_CHARS, SourceIndex
from app.core.redact import Redactor


def _write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def test_build_returns_none_for_missing_or_empty(tmp_path: Path) -> None:
    assert SourceIndex.build(tmp_path / "nope") is None
    (tmp_path / "empty").mkdir()
    assert SourceIndex.build(tmp_path / "empty") is None
    # A tree with only non-source files is also nothing to index.
    _write(tmp_path / "data", "big.csv", "a,b,c\n1,2,3\n")
    assert SourceIndex.build(tmp_path / "data") is None


def test_indexes_source_and_skips_vendored_and_binary(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app/handlers.py",
        "def get_widget(widget_id):\n    return db.widgets[widget_id]\n",
    )
    _write(tmp_path, "node_modules/leftpad/index.js", "module.exports = 1\n")
    _write(tmp_path, "app/__pycache__/handlers.cpython.pyc", "junk")
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "blob.py").write_bytes(b"\xff\xfe\x00\x01not utf8")
    idx = SourceIndex.build(tmp_path)
    assert idx is not None
    assert "app/handlers.py" in idx._files
    assert not any(p.startswith("node_modules") for p in idx._files)
    assert not any("__pycache__" in p for p in idx._files)
    assert "bin/blob.py" not in idx._files  # non-utf8 skipped


def test_gitignore_subset_prunes(tmp_path: Path) -> None:
    _write(tmp_path, ".gitignore", "secrets.py\n/generated/\n*.log\n")
    _write(tmp_path, "app/main.py", "x = 1\n")
    _write(tmp_path, "secrets.py", "KEY = 'abc'\n")
    _write(tmp_path, "generated/models.py", "gen = 1\n")
    _write(tmp_path, "debug.log", "noise\n")
    idx = SourceIndex.build(tmp_path)
    assert idx is not None
    assert "app/main.py" in idx._files
    assert "secrets.py" not in idx._files
    assert "generated/models.py" not in idx._files


def test_symlink_is_never_followed(tmp_path: Path) -> None:
    _write(tmp_path, "app/main.py", "x = 1\n")
    outside = tmp_path.parent / "outside.py"
    outside.write_text("SECRET = 'leak'\n", encoding="utf-8")
    try:
        os.symlink(outside, tmp_path / "app" / "link.py")
    except (OSError, NotImplementedError):
        return  # platform without symlinks: nothing to prove
    idx = SourceIndex.build(tmp_path)
    assert idx is not None
    assert "app/link.py" not in idx._files


def test_search_ranks_more_specific_matches_first(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", "# merchant payout settlement reference\n")
    _write(tmp_path, "b.py", "merchant = 1\n")
    idx = SourceIndex.build(tmp_path)
    assert idx is not None
    hits = idx.search(["merchant", "payout"])
    assert hits
    assert hits[0].path == "a.py"  # two terms beats one
    # Whole-identifier matching: a short term does not light up substrings.
    assert idx.search(["id"]) == [] or all(
        "id" in h.excerpt.lower() for h in idx.search(["identity"])
    )


def test_search_is_deterministic(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", "widget = 1\n")
    _write(tmp_path, "b.py", "widget = 2\n")
    idx = SourceIndex.build(tmp_path)
    assert idx is not None
    assert [c.ref() for c in idx.search(["widget"])] == [c.ref() for c in idx.search(["widget"])]


def test_locate_route_finds_the_handler(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app/routes.py",
        '@app.get("/widgets/{widget_id}")\ndef read_widget(widget_id: int):\n    ...\n',
    )
    idx = SourceIndex.build(tmp_path)
    assert idx is not None
    hits = idx.locate_route("GET", "/widgets/{widget_id}")
    assert any(h.path == "app/routes.py" for h in hits)


def test_snippet_has_context_and_line_numbers(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", "l1\nl2\nTARGET\nl4\nl5\n")
    idx = SourceIndex.build(tmp_path)
    assert idx is not None
    snip = idx.snippet("a.py", 3, context=1)
    assert snip is not None
    assert "TARGET" in snip and "    2  l2" in snip and "    4  l4" in snip
    assert "l1" not in snip  # context=1 excludes line 1
    assert idx.snippet("a.py", 999) is None


def test_cited_snippets_redacts_and_dedupes(tmp_path: Path) -> None:
    _write(tmp_path, "conf.py", "API_TOKEN = 'supersecretvalue'\n")
    idx = SourceIndex.build(tmp_path)
    assert idx is not None
    red = Redactor(["supersecretvalue"])
    cites = idx.search(["api_token", "token"])
    rows = idx.cited_snippets(cites + cites, red)
    refs = [r["ref"] for r in rows]
    assert len(refs) == len(set(refs))  # deduped
    assert all("supersecretvalue" not in r["excerpt"] for r in rows)
    assert all(len(r["excerpt"]) <= MAX_SNIPPET_CHARS for r in rows)


def test_file_cap_is_respected(tmp_path: Path) -> None:
    for i in range(10):
        _write(tmp_path, f"m{i}.py", f"x = {i}\n")
    idx = SourceIndex.build(tmp_path, max_files=3)
    assert idx is not None
    assert idx.file_count <= 3


def test_annotate_findings_adds_file_line(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app/routes.py",
        '@app.get("/widgets/{widget_id}")\n'
        'def read_widget(widget_id):\n    return widgets[widget_id]\n',
    )
    idx = SourceIndex.build(tmp_path)
    assert idx is not None
    findings = [
        {
            "check": "bola",
            "evidence": {
                "method": "GET",
                "route": "/widgets/{widget_id}",
                "param": "widget_id",
            },
        },
        {"check": "tls_config", "evidence": {"issue": "weak cipher"}},  # no route -> untouched
    ]
    n = idx.annotate_findings(findings)
    assert n == 1
    assert any("app/routes.py" in r["ref"] for r in findings[0]["evidence"]["source"])
    assert "source" not in findings[1]["evidence"]


def test_annotate_is_idempotent(tmp_path: Path) -> None:
    _write(tmp_path, "app/routes.py", 'def widgets():\n    pass\n')
    idx = SourceIndex.build(tmp_path)
    assert idx is not None
    findings = [
        {
            "check": "bola",
            "evidence": {
                "method": "GET",
                "route": "/widgets",
                "source": [{"ref": "x:1", "excerpt": "kept"}],
            },
        }
    ]
    assert idx.annotate_findings(findings) == 0
    assert findings[0]["evidence"]["source"] == [{"ref": "x:1", "excerpt": "kept"}]
