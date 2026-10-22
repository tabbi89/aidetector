"""Export only reviewed runner files, never the API tree or build context.

The manifest is intentionally a list of files, without glob expansion: adding
server code or a secret beside a scanner module cannot put it in a public layer.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path, PurePosixPath


def export(source: Path, destination: Path) -> list[str]:
    source = source.resolve()
    names = [
        line.strip()
        for line in (source / "runner-files.txt").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    if len(names) != len(set(names)):
        raise ValueError("duplicate runner manifest entry")
    for name in names:
        relative = PurePosixPath(name)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or str(relative) != name
            or not name.startswith("app/")
            or not (name.endswith(".py") or name == "app/engine/data/payloads/reflection.json")
        ):
            raise ValueError(f"invalid runner manifest entry: {name}")
        path = source
        for part in relative.parts:
            path = path / part
            if path.is_symlink():
                raise ValueError(f"runner source must not be a symlink: {name}")
        if not path.is_file():
            raise ValueError(f"missing runner source: {name}")
    # Validate the entire manifest before writing any output.
    for name in names:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, target)
    return names


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must be a new directory")
    export(args.source, args.output)
