#!/usr/bin/env python3
"""Fail closed on high-confidence secret shapes in candidate files."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("github-token", re.compile(rb"ghp_[A-Za-z0-9]{36}")),
    ("github-fine-grained-token", re.compile(rb"github_pat_[A-Za-z0-9_]{40,}")),
    ("aws-access-key", re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}")),
    ("slack-token", re.compile(rb"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("openai-token", re.compile(rb"sk-[A-Za-z0-9_-]{20,}")),
    (
        "private-key",
        re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    (
        "credential-bearing-url",
        re.compile(rb"https?://[^\s/@:]+:[^\s/@]+@[^\s/]+", re.IGNORECASE),
    ),
)


def _candidate_paths(root: Path) -> tuple[Path, ...]:
    result = subprocess.run(
        ["git", "ls-files", "-co", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    names = result.stdout.decode("utf-8", errors="strict").split("\0")
    return tuple(root / name for name in names if name)


def _contents(path: Path) -> bytes:
    if path.is_symlink():
        return os.readlink(path).encode("utf-8", errors="surrogateescape")
    return path.read_bytes()


def scan(root: Path) -> tuple[int, list[tuple[str, int, str]]]:
    findings: list[tuple[str, int, str]] = []
    paths = _candidate_paths(root)
    for path in paths:
        content = _contents(path)
        relative = path.relative_to(root).as_posix()
        for kind, pattern in _PATTERNS:
            for match in pattern.finditer(content):
                line = content.count(b"\n", 0, match.start()) + 1
                findings.append((relative, line, kind))
    return len(paths), findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    root = args.root.expanduser().resolve()
    try:
        count, findings = scan(root)
    except (OSError, subprocess.CalledProcessError, UnicodeError) as exc:
        print(f"secret scan could not complete: {type(exc).__name__}", file=sys.stderr)
        return 2
    if findings:
        for path, line, kind in findings:
            print(f"{path}:{line}: {kind}", file=sys.stderr)
        print(f"secret scan rejected {len(findings)} high-confidence finding(s)", file=sys.stderr)
        return 1
    print(f"secret scan passed: scanned {count} candidate files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
