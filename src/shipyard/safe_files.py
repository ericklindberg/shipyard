from __future__ import annotations

import os
import stat
from pathlib import Path, PurePosixPath


class SafeFileError(RuntimeError):
    pass


def relative_parts(value: str) -> tuple[str, ...]:
    path = PurePosixPath(value)
    parts = path.parts
    if (
        not value
        or path.is_absolute()
        or not parts
        or any(part in {"", ".", ".."} for part in parts)
        or "\\" in value
    ):
        raise SafeFileError("path must be a canonical repository-relative POSIX path")
    return parts


def open_relative_regular(root: Path, relative: str) -> int:
    """Open a regular file beneath root without following any path-component symlink."""
    parts = relative_parts(relative)
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptors: list[int] = []
    try:
        current = os.open(root, directory_flags)
        descriptors.append(current)
        root_metadata = os.fstat(current)
        if not stat.S_ISDIR(root_metadata.st_mode):
            raise SafeFileError("repository root is not a directory")
        for component in parts[:-1]:
            current = os.open(component, directory_flags, dir_fd=current)
            descriptors.append(current)
            if not stat.S_ISDIR(os.fstat(current).st_mode):
                raise SafeFileError("artifact parent is not a directory")
        descriptor = os.open(parts[-1], file_flags, dir_fd=current)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise SafeFileError("artifact is not a regular file")
        return descriptor
    except (OSError, ValueError) as exc:
        raise SafeFileError("file cannot be opened without following symlinks") from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def copy_private_regular(source: Path, destination: Path) -> None:
    if not source.is_absolute():
        raise SafeFileError("private source path must be absolute")
    try:
        relative = source.relative_to(Path("/")).as_posix()
        source_descriptor = open_relative_regular(Path("/"), relative)
    except (SafeFileError, ValueError) as exc:
        raise SafeFileError("private source file is unsafe") from exc
    destination_descriptor: int | None = None
    completed = False
    try:
        metadata = os.fstat(source_descriptor)
        if (
            (hasattr(os, "geteuid") and metadata.st_uid != os.geteuid())
            or not bool(stat.S_IMODE(metadata.st_mode) & stat.S_IRUSR)
            or bool(stat.S_IMODE(metadata.st_mode) & 0o177)
        ):
            raise SafeFileError("private source file ownership or mode is unsafe")
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        while chunk := os.read(source_descriptor, 64 * 1024):
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written <= 0:
                    raise OSError("private file copy made no progress")
                view = view[written:]
        os.fsync(destination_descriptor)
        os.fchmod(destination_descriptor, 0o400)
        completed = True
    except OSError as exc:
        raise SafeFileError("private file copy failed") from exc
    finally:
        os.close(source_descriptor)
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        if not completed:
            destination.unlink(missing_ok=True)
