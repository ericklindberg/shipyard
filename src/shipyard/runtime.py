from __future__ import annotations

import os
import stat
from pathlib import Path


class RuntimeIdentityError(OSError):
    pass


_ENV_ALLOWLIST = {
    "CI",
    "COLORTERM",
    "FORCE_COLOR",
    "HOME",
    "LANG",
    "LC_ALL",
    "NO_COLOR",
    "SOURCE_DATE_EPOCH",
    "SSH_AUTH_SOCK",
    "TERM",
    "TMPDIR",
    "TZ",
    "USER",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
}


def trusted_path_directories() -> tuple[Path, ...]:
    """Return the operator-controlled executable roots used by Shipyard.

    The ambient PATH is deliberately ignored. Additional roots require the
    explicit SHIPYARD_TRUSTED_PATH setting and must be absolute directories.
    """
    home = Path.home()
    configured = os.environ.get("SHIPYARD_TRUSTED_PATH", "")
    raw = [
        *(part for part in configured.split(os.pathsep) if part),
        str(home / ".local" / "bin"),
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
    ]
    result: list[Path] = []
    for value in raw:
        path = Path(value).expanduser()
        if not path.is_absolute():
            raise RuntimeIdentityError("SHIPYARD_TRUSTED_PATH entries must be absolute")
        resolved = path.resolve()
        if resolved not in result and resolved.is_dir():
            result.append(resolved)
    return tuple(result)


def resolve_executable(executable: str, cwd: Path) -> Path:
    """Resolve an executable without consulting attacker-controlled ambient PATH."""
    if "/" in executable:
        candidate = Path(executable).expanduser()
        if not candidate.is_absolute():
            candidate = cwd / candidate
        candidates = (candidate,)
    else:
        candidates = tuple(directory / executable for directory in trusted_path_directories())

    unsafe_candidate: Path | None = None
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
            metadata = resolved.stat()
        except OSError:
            continue
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            continue
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            unsafe_candidate = unsafe_candidate or resolved
            continue
        return resolved
    if unsafe_candidate is not None:
        raise RuntimeIdentityError(
            f"executable is group/world writable: {unsafe_candidate}"
        )
    raise FileNotFoundError(f"trusted executable not found: {executable}")


def sanitized_environment() -> dict[str, str]:
    """Create a deterministic subprocess environment without credential leakage."""
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in _ENV_ALLOWLIST and "\x00" not in value
    }
    environment["PATH"] = os.pathsep.join(str(path) for path in trusted_path_directories())
    environment.setdefault("LANG", "C.UTF-8")
    environment.setdefault("LC_ALL", "C.UTF-8")
    return environment
