from __future__ import annotations

import os
import stat
from contextlib import suppress
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


def _open_absolute_parent(destination: Path) -> tuple[int, str]:
    if not destination.is_absolute() or destination.name in {"", ".", ".."}:
        raise SafeFileError("private destination path must be absolute")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    current: int | None = None
    try:
        current = os.open(Path("/"), directory_flags)
        parent_parts = destination.parent.relative_to(Path("/")).parts
        for component in parent_parts:
            if component in {"", ".", ".."} or "\x00" in component:
                raise SafeFileError("private destination path is unsafe")
            child = os.open(component, directory_flags, dir_fd=current)
            os.close(current)
            current = child
            if not stat.S_ISDIR(os.fstat(current).st_mode):
                raise SafeFileError("private destination parent is not a directory")
        return current, destination.name
    except (OSError, ValueError, SafeFileError) as exc:
        if current is not None:
            os.close(current)
        raise SafeFileError("private destination path is unsafe") from exc


def copy_private_regular(source: Path, destination: Path) -> None:
    if not source.is_absolute():
        raise SafeFileError("private source path must be absolute")
    try:
        relative = source.relative_to(Path("/")).as_posix()
        source_descriptor = open_relative_regular(Path("/"), relative)
    except (SafeFileError, ValueError) as exc:
        raise SafeFileError("private source file is unsafe") from exc
    destination_descriptor: int | None = None
    destination_parent_descriptor: int | None = None
    destination_name = destination.name
    completed = False
    try:
        metadata = os.fstat(source_descriptor)
        if (
            (hasattr(os, "geteuid") and metadata.st_uid != os.geteuid())
            or not bool(stat.S_IMODE(metadata.st_mode) & stat.S_IRUSR)
            or bool(stat.S_IMODE(metadata.st_mode) & 0o177)
        ):
            raise SafeFileError("private source file ownership or mode is unsafe")
        destination_parent_descriptor, destination_name = _open_absolute_parent(destination)
        destination_descriptor = os.open(
            destination_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=destination_parent_descriptor,
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
        if not completed and destination_parent_descriptor is not None:
            with suppress(FileNotFoundError):
                os.unlink(destination_name, dir_fd=destination_parent_descriptor)
        if destination_parent_descriptor is not None:
            os.close(destination_parent_descriptor)
