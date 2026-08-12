from __future__ import annotations

import importlib.util
import shutil
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
        root.mode = 0o755
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
            member.mode = 0o644
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
        assert {member.mtime for member in archive.getmembers()} == {1_700_000_000}
        assert {member.uid for member in archive.getmembers()} == {0}
        assert {member.gid for member in archive.getmembers()} == {0}


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

    for destination in (first, second):
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
