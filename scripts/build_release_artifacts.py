from __future__ import annotations

import argparse
import copy
import gzip
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

_SHA = re.compile(r"^[0-9a-f]{40}$")
_MAX_MEMBERS = 10_000
_MAX_MEMBER_BYTES = 128 * 1024 * 1024
_END_OF_CENTRAL_DIRECTORY = b"PK\x05\x06"
_CENTRAL_DIRECTORY_ENTRY = b"PK\x01\x02"
_LOCAL_FILE_HEADER = b"PK\x03\x04"


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
                    record.mode = (
                        0o755
                        if record.isdir() or (record.isfile() and record.mode & 0o111)
                        else 0o644
                    )
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


def normalize_wheel(source: Path, destination: Path) -> None:
    """Canonicalize ZIP host/mode metadata without recompressing wheel members."""
    if source.is_symlink() or not source.is_file():
        raise ReleaseBuildError("wheel must be a regular non-symlink file")
    try:
        payload = bytearray(source.read_bytes())
    except OSError as exc:
        raise ReleaseBuildError("cannot read wheel") from exc
    search_start = max(0, len(payload) - (65_535 + 22))
    end = payload.rfind(_END_OF_CENTRAL_DIRECTORY, search_start)
    if end < 0 or end + 22 > len(payload):
        raise ReleaseBuildError("wheel has no valid end-of-central-directory record")
    disk, central_disk, disk_entries, total_entries = struct.unpack_from(
        "<HHHH", payload, end + 4
    )
    central_size, central_offset = struct.unpack_from("<II", payload, end + 12)
    comment_length = struct.unpack_from("<H", payload, end + 20)[0]
    if total_entries == 0xFFFF or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
        raise ReleaseBuildError("wheel must use the documented non-ZIP64 ZIP32 format")
    if (
        disk != 0
        or central_disk != 0
        or disk_entries != total_entries
        or total_entries == 0
        or total_entries > _MAX_MEMBERS
        or end + 22 + comment_length != len(payload)
        or central_offset + central_size != end
    ):
        raise ReleaseBuildError("wheel central directory is unsupported or malformed")
    position = central_offset
    seen: set[bytes] = set()
    local_records: list[tuple[int, int]] = []
    for _index in range(total_entries):
        if position + 46 > end or payload[position : position + 4] != _CENTRAL_DIRECTORY_ENTRY:
            raise ReleaseBuildError("wheel central directory entry is malformed")
        name_length, extra_length, member_comment_length = struct.unpack_from(
            "<HHH", payload, position + 28
        )
        next_position = position + 46 + name_length + extra_length + member_comment_length
        if name_length == 0 or next_position > end:
            raise ReleaseBuildError("wheel central directory entry is malformed")
        name = bytes(payload[position + 46 : position + 46 + name_length])
        try:
            path = PurePosixPath(name.decode("utf-8", errors="strict"))
        except UnicodeDecodeError as exc:
            raise ReleaseBuildError("wheel member name is not valid UTF-8") from exc
        if (
            name in seen
            or path.is_absolute()
            or not path.parts
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ReleaseBuildError("wheel contains an unsafe or duplicate member path")
        seen.add(name)
        made_by = struct.unpack_from("<H", payload, position + 4)[0]
        if made_by >> 8 != 3:
            raise ReleaseBuildError("wheel members must use Unix member metadata")
        flags, compression = struct.unpack_from("<HH", payload, position + 8)
        crc, compressed_size, uncompressed_size = struct.unpack_from(
            "<III", payload, position + 16
        )
        if flags not in {0, 0x0800}:
            raise ReleaseBuildError("wheel general-purpose flags are unsupported")
        if compression not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
            raise ReleaseBuildError("wheel compression method is unsupported")
        if compressed_size == 0xFFFFFFFF or uncompressed_size == 0xFFFFFFFF:
            raise ReleaseBuildError("wheel must use the documented non-ZIP64 ZIP32 format")
        local_offset = struct.unpack_from("<I", payload, position + 42)[0]
        if local_offset == 0xFFFFFFFF:
            raise ReleaseBuildError("wheel must use the documented non-ZIP64 ZIP32 format")
        if flags & 0x08:
            raise ReleaseBuildError("wheel data descriptors are unsupported")
        local_header_missing = (
            local_offset + 30 > central_offset
            or payload[local_offset : local_offset + 4] != _LOCAL_FILE_HEADER
        )
        if local_header_missing:
            raise ReleaseBuildError("wheel local header offset is invalid")
        local_flags, local_compression = struct.unpack_from("<HH", payload, local_offset + 6)
        local_crc, local_compressed_size, local_uncompressed_size = struct.unpack_from(
            "<III", payload, local_offset + 14
        )
        local_name_length, local_extra_length = struct.unpack_from(
            "<HH", payload, local_offset + 26
        )
        local_data_offset = local_offset + 30 + local_name_length + local_extra_length
        local_record_end = local_data_offset + compressed_size
        if local_record_end > central_offset:
            raise ReleaseBuildError("wheel local member data overlaps the central directory")
        local_records.append((local_offset, local_record_end))
        local_name = bytes(
            payload[local_offset + 30 : local_offset + 30 + local_name_length]
        )
        if local_name != name:
            raise ReleaseBuildError("wheel local and central member names differ")
        if local_flags != flags:
            raise ReleaseBuildError("wheel local and central flags differ")
        if local_compression != compression:
            raise ReleaseBuildError("wheel local and central compression method differs")
        if (local_crc, local_compressed_size, local_uncompressed_size) != (
            crc,
            compressed_size,
            uncompressed_size,
        ):
            raise ReleaseBuildError("wheel local and central CRC or size differs")
        original_attributes = struct.unpack_from("<I", payload, position + 38)[0]
        unix_mode = original_attributes >> 16
        original_type = stat.S_IFMT(unix_mode)
        original_mode = stat.S_IMODE(unix_mode)
        is_directory = name.endswith(b"/")
        if original_type not in {stat.S_IFREG, stat.S_IFDIR}:
            raise ReleaseBuildError("wheel supports only regular files and directories")
        if is_directory != (original_type == stat.S_IFDIR):
            raise ReleaseBuildError("wheel member type does not match its path")
        struct.pack_into("<H", payload, position + 4, (3 << 8) | (made_by & 0xFF))
        canonical_permissions = 0o755 if is_directory or original_mode & 0o111 else 0o644
        canonical_type = stat.S_IFDIR if is_directory else stat.S_IFREG
        external_attributes = ((canonical_type | canonical_permissions) << 16) | (
            0x10 if is_directory else 0
        )
        struct.pack_into("<I", payload, position + 38, external_attributes)
        position = next_position
    if position != end:
        raise ReleaseBuildError("wheel central directory size is inconsistent")
    ordered_records = sorted(local_records)
    if (
        ordered_records[0][0] != 0
        or ordered_records[-1][1] != central_offset
        or any(
            previous_end != next_start
            for (_, previous_end), (next_start, _) in zip(
                ordered_records, ordered_records[1:], strict=False
            )
        )
    ):
        raise ReleaseBuildError("wheel local records must be contiguous and non-overlapping")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    try:
        with temporary.open("xb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o644)
        try:
            with zipfile.ZipFile(temporary) as archive:
                if archive.testzip() is not None:
                    raise ReleaseBuildError("normalized wheel member CRC is invalid")
        except (zipfile.BadZipFile, NotImplementedError, RuntimeError) as exc:
            raise ReleaseBuildError("normalized wheel is invalid") from exc
        os.replace(temporary, destination)
    except (OSError, UnicodeError, struct.error) as exc:
        raise ReleaseBuildError("cannot normalize wheel metadata") from exc
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
                normalize_wheel(wheels[0], staged_wheel)
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
