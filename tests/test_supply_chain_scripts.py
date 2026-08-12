from __future__ import annotations

import importlib.util
import os
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import time
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

from shipyard import __version__

ROOT = Path(__file__).parents[1]
SCANNER = ROOT / "scripts/scan_tracked_secrets.py"
CHECKSUMS = ROOT / "scripts/write_checksums.py"
RELEASE_ARTIFACTS = ROOT / "scripts/resolve_release_artifacts.py"
RELEASE_BUILDER = ROOT / "scripts/build_release_artifacts.py"
CANDIDATE_TAG_VERIFIER = ROOT / "scripts/verify_candidate_tag.py"

_SPEC = importlib.util.spec_from_file_location("shipyard_release_builder", RELEASE_BUILDER)
assert _SPEC is not None and _SPEC.loader is not None
_BUILDER = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_BUILDER)
ReleaseBuildError = _BUILDER.ReleaseBuildError
build_release_artifacts = _BUILDER.build
normalize_sdist = _BUILDER.normalize_sdist


def _git(path: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=path, check=True, capture_output=True, text=True)


def test_secret_scanner_covers_tracked_and_untracked_without_printing_values(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / "safe.txt").write_text("ordinary text\n", encoding="utf-8")
    _git(tmp_path, "add", "safe.txt")

    clean = subprocess.run(
        [sys.executable, str(SCANNER), "--root", str(tmp_path)],
        text=True,
        capture_output=True,
    )
    assert clean.returncode == 0, clean.stderr
    assert "scanned 1 candidate files" in clean.stdout

    marker = "ghp_" + "A" * 36
    (tmp_path / "untracked.txt").write_text(f"token={marker}\n", encoding="utf-8")
    flagged = subprocess.run(
        [sys.executable, str(SCANNER), "--root", str(tmp_path)],
        text=True,
        capture_output=True,
    )
    assert flagged.returncode == 1
    assert "untracked.txt" in flagged.stderr
    assert "github-token" in flagged.stderr
    assert marker not in flagged.stdout + flagged.stderr


def test_checksum_writer_is_deterministic_and_excludes_its_output(tmp_path):
    (tmp_path / "b.whl").write_bytes(b"wheel")
    (tmp_path / "a.tar.gz").write_bytes(b"sdist")
    (tmp_path / "unrelated.txt").write_text("not a release artifact", encoding="utf-8")
    output = tmp_path / "SHA256SUMS"
    command = [
        sys.executable,
        str(CHECKSUMS),
        "--directory",
        str(tmp_path),
        "--output",
        str(output),
        "--file",
        "a.tar.gz",
        "--file",
        "b.whl",
    ]

    first = subprocess.run(command, text=True, capture_output=True)
    assert first.returncode == 0, first.stderr
    first_bytes = output.read_bytes()

    second = subprocess.run(command, text=True, capture_output=True)
    assert second.returncode == 0, second.stderr
    assert output.read_bytes() == first_bytes
    lines = first_bytes.decode().splitlines()
    assert [line.split("  ", 1)[1] for line in lines] == ["a.tar.gz", "b.whl"]


def test_release_artifact_resolver_uses_canonical_version_and_exact_build_outputs(tmp_path):
    wheel = f"shipyard_release-{__version__}-py3-none-any.whl"
    sdist = f"shipyard_release-{__version__}.tar.gz"
    (tmp_path / wheel).write_bytes(b"wheel")
    (tmp_path / sdist).write_bytes(b"sdist")

    result = subprocess.run(
        [sys.executable, str(RELEASE_ARTIFACTS), "--directory", str(tmp_path)],
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        f"SHIPYARD_VERSION={__version__}",
        f"SHIPYARD_WHEEL={wheel}",
        f"SHIPYARD_SDIST={sdist}",
        f"SHIPYARD_RUNTIME_SBOM=shipyard-{__version__}-runtime.cdx.json",
        f"SHIPYARD_BUILD_SBOM=shipyard-{__version__}-build.cdx.json",
    ]


def test_release_artifact_resolver_rejects_ambiguous_build_outputs(tmp_path):
    (tmp_path / f"shipyard_release-{__version__}-py3-none-any.whl").write_bytes(b"wheel")
    (tmp_path / f"shipyard_release-{__version__}-1-py3-none-any.whl").write_bytes(
        b"duplicate"
    )
    (tmp_path / f"shipyard_release-{__version__}.tar.gz").write_bytes(b"sdist")

    result = subprocess.run(
        [sys.executable, str(RELEASE_ARTIFACTS), "--directory", str(tmp_path)],
        text=True,
        capture_output=True,
    )

    assert result.returncode == 2
    assert "expected exactly one wheel" in result.stderr


def _archive(path: Path, *, link: bool = False) -> None:
    with tarfile.open(path, "w:gz") as archive:
        root = tarfile.TarInfo("shipyard_release-0.6.0")
        root.type = tarfile.DIRTYPE
        root.mode = 0o775
        root.mtime = int(time.time())
        archive.addfile(root)
        member = tarfile.TarInfo("shipyard_release-0.6.0/file.txt")
        member.mtime = int(time.time())
        if link:
            member.type = tarfile.SYMTYPE
            member.linkname = "../outside"
            archive.addfile(member)
        else:
            payload = b"release"
            member.size = len(payload)
            member.mode = 0o664
            archive.addfile(member, BytesIO(payload))


def test_sdist_normalizer_is_deterministic_and_strips_dynamic_metadata(tmp_path):
    source = tmp_path / "source.tar.gz"
    _archive(source)
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"

    normalize_sdist(source, first, 1_700_000_000)
    normalize_sdist(source, second, 1_700_000_000)

    assert first.read_bytes() == second.read_bytes()
    assert int.from_bytes(first.read_bytes()[4:8], "little") == 1_700_000_000
    with tarfile.open(first, "r:gz") as archive:
        members = archive.getmembers()
        assert {member.mtime for member in members} == {1_700_000_000}
        assert {member.uid for member in members} == {0}
        assert {member.gid for member in members} == {0}
        assert {member.mode for member in members if member.isdir()} == {0o755}
        assert {member.mode for member in members if member.isfile()} == {0o644}


def _wheel(
    path: Path,
    mode: int,
    *,
    name: str = "shipyard/example.py",
    file_type: int = stat.S_IFREG,
    create_system: int = 3,
) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        member = zipfile.ZipInfo(name, (2026, 8, 12, 12, 0, 0))
        member.create_system = create_system
        member.compress_type = zipfile.ZIP_DEFLATED
        member.external_attr = (file_type | mode) << 16
        archive.writestr(member, b"VALUE = 1\n")


def test_wheel_normalizer_canonicalizes_modes_without_recompressing_payload(tmp_path):
    group_writable = tmp_path / "group-writable.whl"
    canonical = tmp_path / "canonical.whl"
    _wheel(group_writable, 0o664)
    _wheel(canonical, 0o644)
    first = tmp_path / "first.whl"
    second = tmp_path / "second.whl"

    _BUILDER.normalize_wheel(group_writable, first)
    _BUILDER.normalize_wheel(canonical, second)

    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first) as archive:
        info = archive.getinfo("shipyard/example.py")
        assert archive.read(info) == b"VALUE = 1\n"
        assert info.create_system == 3
        assert stat.S_IMODE(info.external_attr >> 16) == 0o644


def test_wheel_normalizer_preserves_executable_members(tmp_path):
    source = tmp_path / "source.whl"
    destination = tmp_path / "destination.whl"
    _wheel(source, 0o775, name="shipyard/tool")

    _BUILDER.normalize_wheel(source, destination)

    with zipfile.ZipFile(destination) as archive:
        info = archive.getinfo("shipyard/tool")
        assert stat.S_IMODE(info.external_attr >> 16) == 0o755


def test_wheel_normalizer_rejects_malformed_archives(tmp_path):
    source = tmp_path / "malformed.whl"
    source.write_bytes(b"not a zip archive")

    with pytest.raises(ReleaseBuildError, match="end-of-central-directory"):
        _BUILDER.normalize_wheel(source, tmp_path / "destination.whl")


def test_wheel_normalizer_rejects_traversal_member_names(tmp_path):
    source = tmp_path / "traversal.whl"
    _wheel(source, 0o644, name="../outside.py")

    with pytest.raises(ReleaseBuildError, match="unsafe or duplicate"):
        _BUILDER.normalize_wheel(source, tmp_path / "destination.whl")


def test_wheel_normalizer_rejects_invalid_utf8_member_names(tmp_path):
    source = tmp_path / "invalid-name.whl"
    _wheel(source, 0o644)
    payload = bytearray(source.read_bytes())
    central = payload.index(b"PK\x01\x02")
    name_length = struct.unpack_from("<H", payload, central + 28)[0]
    assert name_length > 0
    payload[central + 46] = 0xFF
    source.write_bytes(payload)

    with pytest.raises(ReleaseBuildError, match="UTF-8"):
        _BUILDER.normalize_wheel(source, tmp_path / "destination.whl")


@pytest.mark.parametrize("file_type", [stat.S_IFLNK, stat.S_IFIFO])
def test_wheel_normalizer_rejects_special_file_entries(tmp_path, file_type):
    source = tmp_path / "special.whl"
    _wheel(source, 0o777, file_type=file_type)

    with pytest.raises(ReleaseBuildError, match="regular files and directories"):
        _BUILDER.normalize_wheel(source, tmp_path / "destination.whl")


def test_wheel_normalizer_rejects_dos_only_member_metadata(tmp_path):
    source = tmp_path / "dos.whl"
    _wheel(source, 0o644, create_system=0)

    with pytest.raises(ReleaseBuildError, match="Unix member metadata"):
        _BUILDER.normalize_wheel(source, tmp_path / "destination.whl")


def test_wheel_normalizer_rejects_directory_type_mismatch(tmp_path):
    source = tmp_path / "mismatch.whl"
    _wheel(source, 0o755, name="shipyard/data/", file_type=stat.S_IFREG)

    with pytest.raises(ReleaseBuildError, match="member type does not match its path"):
        _BUILDER.normalize_wheel(source, tmp_path / "destination.whl")


@pytest.mark.parametrize(
    ("field_offset", "value", "message"),
    [(8, 0, "compression method"), (14, 0, "CRC or size")],
)
def test_wheel_normalizer_rejects_local_header_metadata_mismatch(
    tmp_path, field_offset, value, message
):
    source = tmp_path / "mismatch.whl"
    _wheel(source, 0o644)
    payload = bytearray(source.read_bytes())
    local = payload.index(b"PK\x03\x04")
    if field_offset == 8:
        struct.pack_into("<H", payload, local + field_offset, value)
    else:
        struct.pack_into("<I", payload, local + field_offset, value)
    source.write_bytes(payload)

    with pytest.raises(ReleaseBuildError, match=message):
        _BUILDER.normalize_wheel(source, tmp_path / "destination.whl")


def test_wheel_normalizer_rejects_local_header_name_mismatch(tmp_path):
    source = tmp_path / "name-mismatch.whl"
    _wheel(source, 0o644)
    payload = bytearray(source.read_bytes())
    local = payload.index(b"PK\x03\x04")
    payload[local + 30] = ord("X")
    source.write_bytes(payload)

    with pytest.raises(ReleaseBuildError, match="member name"):
        _BUILDER.normalize_wheel(source, tmp_path / "destination.whl")


def test_wheel_normalizer_rejects_out_of_bounds_local_header(tmp_path):
    source = tmp_path / "bad-offset.whl"
    _wheel(source, 0o644)
    payload = bytearray(source.read_bytes())
    central = payload.index(b"PK\x01\x02")
    struct.pack_into("<I", payload, central + 42, central)
    source.write_bytes(payload)

    with pytest.raises(ReleaseBuildError, match="local header offset"):
        _BUILDER.normalize_wheel(source, tmp_path / "destination.whl")


def test_wheel_normalizer_rejects_zip64_with_explicit_contract(tmp_path):
    source = tmp_path / "zip64.whl"
    _wheel(source, 0o644)
    payload = bytearray(source.read_bytes())
    end = payload.rindex(b"PK\x05\x06")
    struct.pack_into("<H", payload, end + 10, 0xFFFF)
    source.write_bytes(payload)

    with pytest.raises(ReleaseBuildError, match="non-ZIP64"):
        _BUILDER.normalize_wheel(source, tmp_path / "destination.whl")


@pytest.mark.parametrize(
    ("flags", "compression", "message"),
    [(1, zipfile.ZIP_DEFLATED, "general-purpose flags"), (0, 99, "compression method")],
)
def test_wheel_normalizer_rejects_unsupported_zip_features(
    tmp_path, flags, compression, message
):
    source = tmp_path / "unsupported.whl"
    _wheel(source, 0o644)
    payload = bytearray(source.read_bytes())
    local = payload.index(b"PK\x03\x04")
    central = payload.index(b"PK\x01\x02")
    struct.pack_into("<H", payload, local + 6, flags)
    struct.pack_into("<H", payload, central + 8, flags)
    struct.pack_into("<H", payload, local + 8, compression)
    struct.pack_into("<H", payload, central + 10, compression)
    source.write_bytes(payload)

    with pytest.raises(ReleaseBuildError, match=message):
        _BUILDER.normalize_wheel(source, tmp_path / "destination.whl")


def test_wheel_normalizer_rejects_unreferenced_prefix_bytes(tmp_path):
    source = tmp_path / "prefixed.whl"
    _wheel(source, 0o644)
    payload = bytearray(b"X" + source.read_bytes())
    central = payload.index(b"PK\x01\x02")
    end = payload.rindex(b"PK\x05\x06")
    struct.pack_into("<I", payload, central + 42, 1)
    struct.pack_into("<I", payload, end + 16, central)
    source.write_bytes(payload)

    with pytest.raises(ReleaseBuildError, match="contiguous and non-overlapping"):
        _BUILDER.normalize_wheel(source, tmp_path / "destination.whl")


def _candidate_repository(tmp_path: Path) -> tuple[Path, str, str]:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "Test")
    _git(repository, "config", "user.email", "test@example.invalid")
    (repository / "README.md").write_text("candidate\n", encoding="utf-8")
    _git(repository, "add", "README.md")
    _git(repository, "commit", "-qm", "candidate")
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return repository, sha, f"shipyard-candidate-{sha}"


def _verify_candidate_tag(repository: Path, sha: str, tag: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(CANDIDATE_TAG_VERIFIER),
            "--repository",
            str(repository),
            "--expected-sha",
            sha,
            "--github-ref",
            f"refs/tags/{tag}",
            "--github-sha",
            sha,
        ],
        text=True,
        capture_output=True,
    )


def test_candidate_tag_verifier_accepts_direct_annotated_tag(tmp_path):
    repository, sha, tag = _candidate_repository(tmp_path)
    _git(repository, "tag", "-a", tag, "-m", "candidate")

    result = _verify_candidate_tag(repository, sha, tag)

    assert result.returncode == 0, result.stderr
    assert f"candidate_sha={sha}" in result.stdout
    assert f"candidate_tag={tag}" in result.stdout
    assert "candidate_tag_object=" in result.stdout


def test_candidate_tag_verifier_rejects_lightweight_tag(tmp_path):
    repository, sha, tag = _candidate_repository(tmp_path)
    _git(repository, "tag", tag)

    result = _verify_candidate_tag(repository, sha, tag)

    assert result.returncode == 2
    assert "annotated tag object" in result.stderr


def test_candidate_tag_verifier_rejects_nested_annotated_tag(tmp_path):
    repository, sha, tag = _candidate_repository(tmp_path)
    inner = f"inner-{sha}"
    _git(repository, "tag", "-a", inner, "-m", "inner")
    _git(repository, "tag", "-a", tag, inner, "-m", "candidate")

    result = _verify_candidate_tag(repository, sha, tag)

    assert result.returncode == 2
    assert "directly reference the expected commit" in result.stderr


def test_sdist_normalizer_rejects_archive_links(tmp_path):
    source = tmp_path / "source.tar.gz"
    _archive(source, link=True)

    with pytest.raises(ReleaseBuildError, match="unsupported member type"):
        normalize_sdist(source, tmp_path / "normalized.tar.gz", 1_700_000_000)


def test_release_builder_produces_byte_identical_outputs_from_clean_commit(tmp_path):
    source = tmp_path / "source"
    subprocess.run(["git", "clone", "-q", str(ROOT), str(source)], check=True)
    first = tmp_path / "first"
    second = tmp_path / "second"

    tracked = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=source,
        check=True,
        capture_output=True,
    ).stdout.split(b"\0")
    tracked_paths = [source / item.decode() for item in tracked if item]

    def set_group_write(enabled: bool) -> None:
        directories: set[Path] = set()
        for path in tracked_paths:
            parent = path.parent
            while parent != source:
                directories.add(parent)
                parent = parent.parent
        for path in [*tracked_paths, *directories]:
            mode = stat.S_IMODE(path.stat().st_mode)
            updated = mode | stat.S_IWGRP if enabled else mode & ~stat.S_IWGRP
            os.chmod(path, updated)
        status = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=source,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        assert status == ""

    for destination, group_writable in ((first, True), (second, False)):
        set_group_write(group_writable)
        result = subprocess.run(
            [
                sys.executable,
                str(RELEASE_BUILDER),
                "--root",
                str(source),
                "--directory",
                str(destination),
            ],
            text=True,
            capture_output=True,
        )
        assert result.returncode == 0, result.stderr

    assert sorted(path.name for path in first.iterdir()) == sorted(
        path.name for path in second.iterdir()
    )
    for artifact in first.iterdir():
        assert artifact.read_bytes() == (second / artifact.name).read_bytes()

    with zipfile.ZipFile(next(first.glob("*.whl"))) as archive:
        assert {
            stat.S_IMODE(info.external_attr >> 16)
            for info in archive.infolist()
            if not info.is_dir()
        } == {0o644}
    with tarfile.open(next(first.glob("*.tar.gz")), "r:gz") as archive:
        members = archive.getmembers()
        assert {member.mode for member in members if member.isdir()} == {0o755}
        assert {member.mode for member in members if member.isfile()} == {0o644}


def test_release_builder_rejects_dirty_source(tmp_path):
    source = tmp_path / "source"
    subprocess.run(["git", "clone", "-q", str(ROOT), str(source)], check=True)
    (source / "dirty.txt").write_text("dirty\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(RELEASE_BUILDER), "--root", str(source)],
        text=True,
        capture_output=True,
    )

    assert result.returncode == 2
    assert "worktree must be clean" in result.stderr


def test_release_builder_rolls_back_every_output_when_normalization_fails(
    tmp_path, monkeypatch
):
    source = tmp_path / "source"
    subprocess.run(["git", "clone", "-q", str(ROOT), str(source)], check=True)
    destination = tmp_path / "dist"

    def fail_normalization(*_args, **_kwargs):
        raise ReleaseBuildError("injected normalization failure")

    monkeypatch.setattr(_BUILDER, "normalize_sdist", fail_normalization)
    with pytest.raises(ReleaseBuildError, match="injected normalization failure"):
        build_release_artifacts(source, destination)

    assert destination.is_dir()
    assert list(destination.iterdir()) == []


def test_release_builder_embeds_exact_source_identity_and_cleans_worktree(tmp_path) -> None:
    repo = tmp_path / "repository"
    shutil.copytree(ROOT, repo, ignore=shutil.ignore_patterns(".git", ".venv", "dist"))
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repo, check=True)
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    destination = tmp_path / "dist"

    result = build_release_artifacts(repo, destination)

    assert result["source_sha"] == sha
    assert not (repo / "src" / "shipyard" / "_build_source.py").exists()
    assert subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout == ""
    wheel = next(destination.glob("*.whl"))
    with zipfile.ZipFile(wheel) as archive:
        marker = archive.read("shipyard/_build_source.py").decode("utf-8")
    assert f'SOURCE_SHA = "{sha}"' in marker
