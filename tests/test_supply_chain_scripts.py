from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCANNER = ROOT / "scripts/scan_tracked_secrets.py"
CHECKSUMS = ROOT / "scripts/write_checksums.py"
RELEASE_ARTIFACTS = ROOT / "scripts/resolve_release_artifacts.py"


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
    (tmp_path / "gary_shipyard-0.3.0-py3-none-any.whl").write_bytes(b"wheel")
    (tmp_path / "gary_shipyard-0.3.0.tar.gz").write_bytes(b"sdist")

    result = subprocess.run(
        [sys.executable, str(RELEASE_ARTIFACTS), "--directory", str(tmp_path)],
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "SHIPYARD_VERSION=0.3.0",
        "SHIPYARD_WHEEL=gary_shipyard-0.3.0-py3-none-any.whl",
        "SHIPYARD_SDIST=gary_shipyard-0.3.0.tar.gz",
        "SHIPYARD_RUNTIME_SBOM=shipyard-0.3.0-runtime.cdx.json",
        "SHIPYARD_BUILD_SBOM=shipyard-0.3.0-build.cdx.json",
    ]


def test_release_artifact_resolver_rejects_ambiguous_build_outputs(tmp_path):
    (tmp_path / "gary_shipyard-0.3.0-py3-none-any.whl").write_bytes(b"wheel")
    (tmp_path / "gary_shipyard-0.3.0-1-py3-none-any.whl").write_bytes(b"duplicate")
    (tmp_path / "gary_shipyard-0.3.0.tar.gz").write_bytes(b"sdist")

    result = subprocess.run(
        [sys.executable, str(RELEASE_ARTIFACTS), "--directory", str(tmp_path)],
        text=True,
        capture_output=True,
    )

    assert result.returncode == 2
    assert "expected exactly one wheel" in result.stderr
