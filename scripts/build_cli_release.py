"""Build public CLI archives with an immutable runner image compiled into them."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

PLATFORMS = (
    ("darwin", "arm64"),
    ("darwin", "amd64"),
    ("linux", "amd64"),
    ("linux", "arm64"),
    ("windows", "amd64"),
    ("windows", "arm64"),
)
VERSION = re.compile(
    r"v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?\Z"
)
IMAGE = re.compile(
    r"ghcr\.io/[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_./-]*@sha256:[0-9a-f]{64}\Z"
)


def validate(version: str, image: str) -> None:
    if not VERSION.fullmatch(version):
        raise ValueError(
            "version must be vMAJOR.MINOR.PATCH, optionally with a prerelease suffix"
        )
    if not IMAGE.fullmatch(image):
        raise ValueError(
            "runner image must be a fully qualified ghcr.io image pinned by sha256 digest"
        )


def third_party_notices(root: Path) -> str:
    text = subprocess.check_output(
        ["go", "mod", "download", "-json", "all"], cwd=root / "cli", text=True
    )
    decoder = json.JSONDecoder()
    goroot = subprocess.check_output(["go", "env", "GOROOT"], text=True).strip()
    notices = ["Go standard library", (Path(goroot) / "LICENSE").read_text()]
    while text.strip():
        module, end = decoder.raw_decode(text.lstrip())
        text = text.lstrip()[end:]
        if module.get("Main"):
            continue
        directory = Path(module["Dir"])
        files = [
            path
            for path in directory.iterdir()
            if path.is_file()
            and path.name.upper().startswith(("LICENSE", "COPYING", "NOTICE"))
        ]
        if not files:
            raise ValueError(f"missing redistribution notice for {module['Path']}")
        notices.append(module["Path"] + " " + module.get("Version", ""))
        notices.extend(path.read_text() for path in sorted(files))
    return "\n\n".join(notices) + "\n"


def build(version: str, image: str, output: Path) -> None:
    validate(version, image)
    if output.exists():
        raise ValueError("release output must be a new directory")
    root = Path(__file__).resolve().parents[1]
    output.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="runpentests-release-") as scratch:
        notices = Path(scratch) / "THIRD_PARTY_NOTICES.txt"
        notices.write_text(third_party_notices(root))
        for system, arch in PLATFORMS:
            filename = "runpentests.exe" if system == "windows" else "runpentests"
            binary = Path(scratch) / filename
            env = {**os.environ, "CGO_ENABLED": "0", "GOOS": system, "GOARCH": arch}
            subprocess.run(
                [
                    "go",
                    "build",
                    "-trimpath",
                    "-buildvcs=false",
                    "-ldflags",
                    f"-s -w -X runpentests/cli/internal/commands.Version={version} "
                    f"-X runpentests/cli/internal/commands.RunnerImage={image}",
                    "-o",
                    str(binary),
                    "./cmd/runpentests",
                ],
                cwd=root / "cli",
                env=env,
                check=True,
            )
            base = output / f"runpentests-{version}-{system}-{arch}"
            if system == "windows":
                with zipfile.ZipFile(
                    str(base) + ".zip", "w", zipfile.ZIP_DEFLATED
                ) as archive:
                    archive.write(binary, filename)
                    archive.write(notices, notices.name)
            else:
                with tarfile.open(str(base) + ".tar.gz", "w:gz") as archive:
                    archive.add(binary, arcname=filename)
                    archive.add(notices, arcname=notices.name)
            binary.unlink()
    (output / "runner.json").write_text(
        json.dumps(
            {
                "version": version,
                "image": image,
                "platforms": ["linux/amd64", "linux/arm64"],
                "mcp": {"command": "runpentests", "args": ["mcp"]},
            },
            indent=2,
        )
        + "\n"
    )
    checksums = [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}"
        for path in sorted(output.iterdir())
        if path.is_file()
    ]
    (output / "SHA256SUMS").write_text("\n".join(checksums) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build(args.version, args.image, args.output.resolve())
