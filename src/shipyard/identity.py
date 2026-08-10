from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
import subprocess
import sys
from pathlib import Path

from . import __version__
from .runtime import resolve_executable, sanitized_environment

_DISTRIBUTION = "gary-shipyard"


def package_version() -> str:
    try:
        return importlib.metadata.version(_DISTRIBUTION)
    except importlib.metadata.PackageNotFoundError:
        return __version__


def distribution_fingerprint() -> str:
    try:
        files = importlib.metadata.files(_DISTRIBUTION) or []
    except importlib.metadata.PackageNotFoundError:
        files = []
    records = sorted(
        f"{entry}:{entry.hash}:{entry.size}"
        for entry in files
        if str(entry).startswith("shipyard/")
    )
    if not records:
        root = Path(__file__).resolve().parent
        records = [
            f"{path.relative_to(root)}:{hashlib.sha256(path.read_bytes()).hexdigest()}"
            for path in sorted(root.rglob("*.py"))
        ]
    return hashlib.sha256("\n".join(records).encode()).hexdigest()


def source_sha() -> str | None:
    root = Path(__file__).resolve().parents[2]
    if not (root / ".git").exists():
        return None
    try:
        git = resolve_executable("git", root)
        completed = subprocess.run(  # noqa: S603
            (str(git), "rev-parse", "HEAD"),
            cwd=root,
            env=sanitized_environment(),
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = completed.stdout.strip()
    return value if len(value) == 40 else None


def runtime_identity() -> dict[str, object]:
    return {
        "package_version": package_version(),
        "source_sha": source_sha(),
        "distribution_sha256": distribution_fingerprint(),
        "python": platform.python_version(),
        "python_executable": str(Path(sys.executable).resolve()),
        "platform": platform.platform(),
    }


def runtime_identity_json() -> str:
    return json.dumps(runtime_identity(), separators=(",", ":"), sort_keys=True)
