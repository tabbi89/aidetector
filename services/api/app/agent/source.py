"""Whitebox source index — the project's own code, read for evidence.

The CLI heavy lane runs inside the project and mounts it **read-only** into the
runner (``--source DIR`` → ``-v DIR:/src:ro``). This module turns that tree into
a bounded, searchable index the agent uses to (a) confirm a finding against the
code, (b) explain it with a ``file:line`` citation, and (c) steer which checks
and parameters to probe.

Three rules keep it safe and keep the archive small, mirroring the request
trace's discipline:

- **Source is evidence, never instructions.** The index never executes anything;
  it only reads text. The agent loop wraps every snippet it forwards to the model
  in the same untrusted-data guard ``ai_runtime/plan_agent.py`` already uses, and
  a citation that leaves the machine is redacted first.
- **It is bounded.** A built-in skip list plus a pragmatic ``.gitignore`` subset
  prune vendored and generated trees; only an allowlist of text extensions is
  read; per-file bytes, total files and total bytes are all capped. A huge or
  binary repo degrades to a partial index, never an unbounded read.
- **It is DB-free.** Like the rest of ``app.engine.execution`` / ``app.runner``
  it imports no SQLAlchemy, so ``tests/test_layering.py`` can pin it pure.

Only ``file:line`` citations and short redacted snippets are ever uploaded —
never whole files, the same way a finding records field *names*, not values.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from app.core.redact import Redactor

#: Text extensions worth indexing. A deliberately curated list — the point is
#: application source, not every text file on disk. No extension-less match, so
#: a lockfile or a 50 MB CSV is skipped even if it is "text".
_SOURCE_SUFFIXES = frozenset(
    {
        ".py",
        ".pyi",
        ".go",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".rb",
        ".php",
        ".java",
        ".kt",
        ".cs",
        ".rs",
        ".c",
        ".h",
        ".cc",
        ".cpp",
        ".hpp",
        ".scala",
        ".ex",
        ".exs",
        ".sql",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".tf",
        ".sh",
    }
)

#: Directories never worth walking into, whatever ``.gitignore`` says. Vendored
#: and generated trees dominate a repo's byte count and carry no app logic.
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        ".next",
        "target",
        "vendor",
        ".terraform",
        "coverage",
        ".cache",
        ".idea",
        ".vscode",
    }
)

#: Default caps. A run's whole source budget is bounded so the index can never
#: become the thing that blows the archive or the wall-clock.
MAX_FILE_BYTES = 256 * 1024
MAX_FILES = 4000
MAX_TOTAL_BYTES = 48 * 1024 * 1024
#: Lines of context either side of a match in a snippet.
SNIPPET_CONTEXT = 3
#: A snippet never grows past this many characters once redacted.
MAX_SNIPPET_CHARS = 1200


@dataclass(frozen=True)
class Citation:
    """One ``file:line`` pointer with the matched line and a little context.

    ``path`` is always repo-relative and POSIX-shaped, so a citation uploaded
    from a Windows CLI machine reads the same as one from Linux.
    """

    path: str
    line: int
    excerpt: str

    def ref(self) -> str:
        return f"{self.path}:{self.line}"


class _GitignoreSubset:
    """A pragmatic ``.gitignore`` matcher — not git's full algorithm.

    Supports the cases that actually prune a scan tree: blank/comment lines, a
    trailing-slash directory match, a leading-slash anchor, and ``*`` globs
    matched against both the basename and the repo-relative path. It errs toward
    *keeping* a file (indexing one extra generated file is harmless; skipping a
    real source file hides evidence), and negation (``!``) is treated as "keep".
    """

    def __init__(self, patterns: list[str]):
        self._dir_patterns: list[str] = []
        self._patterns: list[str] = []
        for raw in patterns:
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            anchored = line.startswith("/")
            line = line.lstrip("/")
            if line.endswith("/"):
                self._dir_patterns.append(line.rstrip("/"))
                continue
            # Record whether it was anchored by keeping the raw glob; matching
            # tries both the basename and the full relative path.
            self._patterns.append(line)
            if not anchored and "/" not in line:
                self._dir_patterns.append(line)

    def ignored(self, rel: PurePosixPath, *, is_dir: bool) -> bool:
        name = rel.name
        rel_str = str(rel)
        if is_dir:
            for pat in self._dir_patterns:
                if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(rel_str, pat):
                    return True
            return False
        for pat in self._patterns:
            if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(rel_str, pat):
                return True
        for pat in self._dir_patterns:
            # A file inside an ignored directory segment.
            if pat in rel.parts[:-1]:
                return True
        return False


def _tokenize(text: str) -> list[str]:
    """Identifier-ish tokens from a route, param or title, lowercased."""
    return [t for t in re.split(r"[^A-Za-z0-9_]+", text.lower()) if len(t) >= 3]


class SourceIndex:
    """An in-memory index of a project's source, built once per run.

    ``build`` returns ``None`` when there is nothing usable to index (no root,
    an empty tree), which the agent reads as "no whitebox context" and carries
    on — source analysis is an enhancement, never a requirement.
    """

    def __init__(self, root: Path, files: dict[str, list[str]]):
        self.root = root
        #: repo-relative POSIX path -> its lines (no trailing newlines).
        self._files = files
        self.total_bytes = sum(sum(len(line) + 1 for line in lines) for lines in files.values())

    # -- construction --------------------------------------------------------
    @classmethod
    def build(
        cls,
        root: str | Path,
        *,
        max_file_bytes: int = MAX_FILE_BYTES,
        max_files: int = MAX_FILES,
        max_total_bytes: int = MAX_TOTAL_BYTES,
    ) -> SourceIndex | None:
        base = Path(root)
        if not base.is_dir():
            return None
        ignore = cls._load_gitignore(base)
        files: dict[str, list[str]] = {}
        total = 0
        for path in cls._walk(base, ignore):
            if len(files) >= max_files or total >= max_total_bytes:
                break
            if path.suffix.lower() not in _SOURCE_SUFFIXES:
                continue
            try:
                if path.stat().st_size > max_file_bytes:
                    continue
                raw = path.read_text(encoding="utf-8", errors="strict")
            except (OSError, UnicodeDecodeError):
                # Unreadable or not real UTF-8 text: skip rather than guess.
                continue
            rel = PurePosixPath(path.relative_to(base).as_posix())
            lines = raw.split("\n")
            files[str(rel)] = lines
            total += len(raw)
        if not files:
            return None
        return cls(base, files)

    @staticmethod
    def _load_gitignore(base: Path) -> _GitignoreSubset:
        patterns: list[str] = []
        gi = base / ".gitignore"
        try:
            if gi.is_file() and gi.stat().st_size < 256 * 1024:
                patterns = gi.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            patterns = []
        return _GitignoreSubset(patterns)

    @staticmethod
    def _walk(base: Path, ignore: _GitignoreSubset):
        """Depth-first file walk that prunes skip/ignored directories and
        refuses to follow symlinks out of the tree."""
        stack: list[Path] = [base]
        while stack:
            current = stack.pop()
            try:
                entries = sorted(current.iterdir())
            except OSError:
                continue
            for entry in entries:
                try:
                    rel = PurePosixPath(entry.relative_to(base).as_posix())
                except ValueError:
                    continue
                if entry.is_symlink():
                    # Never follow a symlink: a mounted repo could point one out
                    # of the tree (at /etc/shadow, say). Index only real files.
                    continue
                if entry.is_dir():
                    if entry.name in _SKIP_DIRS or ignore.ignored(rel, is_dir=True):
                        continue
                    stack.append(entry)
                elif entry.is_file() and not ignore.ignored(rel, is_dir=False):
                    yield entry

    # -- queries -------------------------------------------------------------
    @property
    def file_count(self) -> int:
        return len(self._files)

    def search(self, terms: list[str], *, limit: int = 8) -> list[Citation]:
        """Lines mentioning any of ``terms``, best (most terms) first.

        A grep over the index, not a semantic search — cheap, deterministic and
        good enough to put the agent near the handler that serves a route or
        reads a parameter. ``terms`` are matched case-insensitively as whole-ish
        identifiers so ``id`` does not light up every ``valid`` and ``hidden``.
        """
        wanted = [t for t in {t.lower() for t in terms} if len(t) >= 3]
        if not wanted:
            return []
        word = re.compile(r"(?:^|[^A-Za-z0-9_])(" + "|".join(map(re.escape, wanted)) + r")", re.I)
        scored: list[tuple[int, int, Citation]] = []
        for rel, lines in self._files.items():
            for i, line in enumerate(lines):
                if len(line) > 4000:
                    continue
                hits = {m.group(1).lower() for m in word.finditer(line)}
                if not hits:
                    continue
                scored.append(
                    (len(hits), -len(line), Citation(rel, i + 1, line.strip()[:300]))
                )
        # Most distinct terms first; shorter lines (more specific) next; then a
        # stable path/line order so the same repo yields the same citations.
        scored.sort(key=lambda s: (-s[0], -s[1], s[2].path, s[2].line))
        return [c for _, _, c in scored[:limit]]

    def locate_route(self, method: str, path: str, *, limit: int = 6) -> list[Citation]:
        """Citations near the code that most likely serves ``METHOD path``.

        Routes are declared a hundred different ways across frameworks, so this
        looks for the path's own segments (and the literal path) rather than any
        one framework's decorator syntax. The method is a weak signal on its own
        and is only added to the term set.
        """
        segments = [s for s in path.split("/") if s and not s.startswith("{")]
        terms = _tokenize(path) + segments
        if method:
            terms.append(method.lower())
        return self.search(terms, limit=limit)

    def snippet(self, path: str, line: int, *, context: int = SNIPPET_CONTEXT) -> str | None:
        """A few lines of context around ``path:line`` — or None if unknown.

        Line-numbered so a reader (human or model) can cite within it. Never
        redacted here: redaction happens at the boundary, in
        :meth:`cited_snippets`, because an in-process caller confirming a finding
        against the code needs the real text.
        """
        lines = self._files.get(path)
        if lines is None or line < 1 or line > len(lines):
            return None
        lo = max(0, line - 1 - context)
        hi = min(len(lines), line + context)
        out = []
        for i in range(lo, hi):
            out.append(f"{i + 1:5d}  {lines[i]}")
        return "\n".join(out)[:MAX_SNIPPET_CHARS]

    def annotate_findings(
        self,
        findings: list[dict],
        *,
        redactor: Redactor | None = None,
        per_finding: int = 3,
    ) -> int:
        """Attach ``evidence['source']`` file:line citations to each finding.

        Whitebox's "explain it with a file:line" without the agent loop: for
        every finding that names a route or path (and optionally a parameter or
        field), point at the code that most likely serves it. ``source`` is not
        a fingerprint identity key (see ``engine/fingerprint.py``), so this adds
        explanation without changing which finding is which. Returns how many
        findings were annotated. Idempotent — a finding that already carries
        ``source`` is left alone.
        """
        red = redactor or Redactor()
        annotated = 0
        for finding in findings:
            evidence = finding.get("evidence")
            if not isinstance(evidence, dict) or evidence.get("source"):
                continue
            method = str(evidence.get("method") or "")
            route = str(evidence.get("route") or evidence.get("path") or "")
            if not route:
                continue
            cites = self.locate_route(method, route, limit=per_finding)
            extra = str(evidence.get("param") or evidence.get("field") or "")
            if extra:
                cites = (self.search([extra], limit=per_finding) + cites)[: per_finding * 2]
            rows = self.cited_snippets(cites, red)[:per_finding]
            if rows:
                evidence["source"] = rows
                annotated += 1
        return annotated

    def cited_snippets(
        self, citations: list[Citation], redactor: Redactor | None = None
    ) -> list[dict[str, str]]:
        """Redacted ``{ref, excerpt}`` rows ready to upload or hand to the model.

        This is the only path source takes toward anything that leaves the
        machine or reaches the model, so redaction lives here: a secret checked
        into the repo (an ``.env`` example, a test fixture) is masked before it
        travels, exactly as a response body is.
        """
        red = redactor or Redactor()
        rows: list[dict[str, str]] = []
        seen: set[str] = set()
        for c in citations:
            ref = c.ref()
            if ref in seen:
                continue
            seen.add(ref)
            snip = self.snippet(c.path, c.line) or c.excerpt
            rows.append({"ref": ref, "excerpt": red.text(snip)[:MAX_SNIPPET_CHARS]})
        return rows
