from __future__ import annotations

import argparse
import copy
import gzip
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

_SHA = re.compile(r"^[0-9a-f]{40}$")
_MAX_MEMBERS = 10_000
_MAX_MEMBER_BYTES = 128 * 1024 * 1024


class ReleaseBuildError(RuntimeError):
    pass


@contextmanager
def embedded_source_marker(root: Path, sha: str, epoch: int) -> Iterator[None]:
    package = root / "src" / "shipyard"
    marker = package / "_build_source.py"
    if package.is_symlink() or not package.is_dir() or os.path.lexists(marker):
        raise ReleaseBuildError("release source marker path is unsafe or already exists")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    payload = (
        '"""Canonical release source identity; generated during artifact build."""\n\n'
        f'SOURCE_SHA = "{sha}"\n'
        f"SOURCE_DATE_EPOCH = {epoch}\n"
    ).encode()
    try:
        descriptor = os.open(marker, flags, 0o644)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
        except Exception:
            marker.unlink(missing_ok=True)
            raise
        yield
    finally:
        try:
            marker.unlink()
        except FileNotFoundError:
            raise ReleaseBuildError("release source marker disappeared during build") from None
        except OSError as exc:
            raise ReleaseBuildError("cannot remove release source marker") from exc


def _git(root: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(  # noqa: S603
            ["git", *arguments],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReleaseBuildError("cannot inspect exact Git source") from exc
    return result.stdout.strip()


def source_identity(root: Path) -> tuple[str, int]:
    if root.is_symlink() or not (root / ".git").exists():
        raise ReleaseBuildError("release source must be a non-symlink Git worktree")
    sha = _git(root, "rev-parse", "HEAD")
    if _SHA.fullmatch(sha) is None:
        raise ReleaseBuildError("release source SHA is invalid")
    if _git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ReleaseBuildError("release source worktree must be clean")
    value = _git(root, "show", "-s", "--format=%ct", sha)
    if not value.isdigit():
        raise ReleaseBuildError("release source timestamp is invalid")
    epoch = int(value)
    if epoch <= 0 or epoch > 0xFFFFFFFF:
        raise ReleaseBuildError("release source timestamp is outside gzip limits")
    return sha, epoch


def _safe_member(member: tarfile.TarInfo) -> None:
    path = PurePosixPath(member.name)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ReleaseBuildError("source archive contains an unsafe member path")
    if member.size < 0 or member.size > _MAX_MEMBER_BYTES:
        raise ReleaseBuildError("source archive member exceeds the size limit")
    if not (member.isfile() or member.isdir()):
        raise ReleaseBuildError("source archive contains an unsupported member type")


def normalize_sdist(source: Path, destination: Path, epoch: int) -> None:
    if source.is_symlink() or not source.is_file():
        raise ReleaseBuildError("source archive must be a regular non-symlink file")
    seen: set[str] = set()
    with tempfile.SpooledTemporaryFile(max_size=64 * 1024 * 1024) as normalized_tar:
        try:
            with tarfile.open(source, mode="r:gz") as archive, tarfile.open(
                fileobj=normalized_tar,
                mode="w",
                format=tarfile.PAX_FORMAT,
            ) as output:
                members = sorted(archive.getmembers(), key=lambda item: item.name)
                if not members or len(members) > _MAX_MEMBERS:
                    raise ReleaseBuildError("source archive member count is invalid")
                for member in members:
                    _safe_member(member)
                    if member.name in seen:
                        raise ReleaseBuildError("source archive contains a duplicate member")
                    seen.add(member.name)
                    record = copy.copy(member)
                    record.uid = 0
                    record.gid = 0
                    record.uname = ""
                    record.gname = ""
                    record.mtime = epoch
                    record.pax_headers = {}
                    payload = archive.extractfile(member) if member.isfile() else None
                    output.addfile(record, payload)
        except (OSError, tarfile.TarError) as exc:
            raise ReleaseBuildError("cannot normalize source archive") from exc
        normalized_tar.seek(0)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.tmp")
        try:
            with temporary.open("wb") as raw:
                with gzip.GzipFile(
                    filename="",
                    mode="wb",
                    compresslevel=9,
                    fileobj=raw,
                    mtime=epoch,
                ) as compressed:
                    shutil.copyfileobj(normalized_tar, compressed, length=1024 * 1024)
                raw.flush()
                os.fsync(raw.fileno())
            header = temporary.read_bytes()[:10]
            if len(header) < 10 or header[:3] != b"\x1f\x8b\x08" or header[9] != 255:
                raise ReleaseBuildError("normalized source archive has an invalid gzip header")
            os.chmod(temporary, 0o644)
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)


def build(root: Path, destination: Path) -> dict[str, str | int]:
    root = root.expanduser().resolve(strict=True)
    destination = destination.expanduser()
    if not destination.is_absolute():
        destination = root / destination
    destination = Path(os.path.abspath(destination))
    sha, epoch = source_identity(root)
    if os.path.lexists(destination):
        if destination.is_symlink() or not destination.is_dir():
            raise ReleaseBuildError("artifact destination must be a non-symlink directory")
        if any(destination.iterdir()):
            raise ReleaseBuildError("artifact destination must be empty")
    else:
        destination.mkdir(parents=True, mode=0o755)
    uv = shutil.which("uv")
    if uv is None:
        raise ReleaseBuildError("uv is required to build release artifacts")
    environment = os.environ.copy()
    environment["SOURCE_DATE_EPOCH"] = str(epoch)
    with tempfile.TemporaryDirectory(prefix="shipyard-release-build-") as temporary_name:
        temporary = Path(temporary_name)
        try:
            with embedded_source_marker(root, sha, epoch):
                subprocess.run(  # noqa: S603
                    [uv, "build", "--project", str(root), "--out-dir", str(temporary)],
                    cwd=root,
                    env=environment,
                    check=True,
                    stdin=subprocess.DEVNULL,
                    timeout=300,
                )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ReleaseBuildError("release artifact build failed") from exc
        wheels = sorted(temporary.glob("*.whl"))
        sdists = sorted(temporary.glob("*.tar.gz"))
        if len(wheels) != 1 or len(sdists) != 1:
            raise ReleaseBuildError("release build must produce exactly one wheel and one sdist")
        wheel_destination = destination / wheels[0].name
        sdist_destination = destination / sdists[0].name
        published: list[Path] = []
        try:
            with tempfile.TemporaryDirectory(
                prefix=".shipyard-release-stage-", dir=destination
            ) as staging_name:
                staging = Path(staging_name)
                staged_wheel = staging / wheels[0].name
                staged_sdist = staging / sdists[0].name
                shutil.copyfile(wheels[0], staged_wheel)
                os.chmod(staged_wheel, 0o644)
                normalize_sdist(sdists[0], staged_sdist, epoch)
                for path in (staged_wheel, staged_sdist):
                    with path.open("rb") as artifact:
                        os.fsync(artifact.fileno())
                for staged, final in (
                    (staged_wheel, wheel_destination),
                    (staged_sdist, sdist_destination),
                ):
                    os.replace(staged, final)
                    published.append(final)
        except Exception:
            for path in published:
                path.unlink(missing_ok=True)
            raise
    return {
        "source_sha": sha,
        "source_date_epoch": epoch,
        "wheel": wheel_destination.name,
        "sdist": sdist_destination.name,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build reproducible exact-SHA Shipyard artifacts")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--directory", type=Path, default=Path("dist"))
    args = parser.parse_args(argv)
    try:
        result = build(args.root, args.directory)
    except ReleaseBuildError as exc:
        print(f"release build failed: {exc}", file=sys.stderr)
        return 2
    for name, value in result.items():
        print(f"{name}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
