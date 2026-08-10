#!/usr/bin/env python3
"""Write deterministic SHA-256 evidence for release artifacts."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import os
import sys
from pathlib import Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_checksums(directory: Path, output: Path, names: list[str]) -> int:
    directory = directory.expanduser().resolve()
    output = output.expanduser().resolve()
    if not names:
        raise ValueError("at least one artifact file is required")
    if len(set(names)) != len(names):
        raise ValueError("artifact file names must be unique")
    files: list[Path] = []
    for name in sorted(names):
        if Path(name).name != name or name in {".", ".."}:
            raise ValueError("artifact files must be direct child names")
        path = directory / name
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"artifact file is missing or unsafe: {name}")
        if path.resolve() == output:
            raise ValueError("checksum output cannot be an input artifact")
        files.append(path)
    content = "".join(f"{_sha256(path)}  {path.name}\n" for path in files)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    try:
        with temporary.open("x", encoding="ascii", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()
    return len(files)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--file", action="append", required=True, dest="files")
    args = parser.parse_args(argv)
    try:
        count = write_checksums(args.directory, args.output, args.files)
    except (OSError, ValueError) as exc:
        print(f"checksum generation failed: {exc}", file=sys.stderr)
        return 2
    print(f"wrote checksums for {count} artifact(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
