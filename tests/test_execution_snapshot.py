from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from shipyard.execution_snapshot import (
    ExecutionSnapshotError,
    _copy_approved_artifact,
    _copy_buzz_auth_config,
    _rebind_buzz_auth_config,
    execution_snapshot_run,
    freeze_execution_snapshot,
)
from shipyard.models import ReleaseRun
from shipyard.safe_files import SafeFileError, copy_private_regular


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ("git", *args),
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_buzz_snapshot_copies_only_safe_credential_references(
    git_repo: Path, tmp_path: Path
) -> None:
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    _git(snapshot, "init", "-q")
    keyfile = tmp_path / "buzz.key"
    keyfile.write_text("nsec-secret-must-not-be-copied", encoding="utf-8")
    keyfile.chmod(0o600)
    host = "buzz.example.com"
    _git(git_repo, "config", f"credential.https://{host}.helper", "nostr")
    _git(git_repo, "config", f"credential.https://{host}.useHttpPath", "true")
    _git(git_repo, "config", "nostr.keyfile", str(keyfile))

    _copy_buzz_auth_config(
        git_repo,
        snapshot,
        f"https://{host}/git/owner/repository.git",
    )

    helper_values = subprocess.run(
        ("git", "config", "--get-all", f"credential.https://{host}.helper"),
        cwd=snapshot,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    assert helper_values == ["", "nostr"]
    assert (
        _git(snapshot, "config", "--get", f"credential.https://{host}.useHttpPath")
        == "true"
    )
    private_copy = snapshot / ".git" / "shipyard-credentials" / "nostr.key"
    assert _git(snapshot, "config", "--get", "nostr.keyfile") == str(private_copy)
    assert private_copy.read_text(encoding="utf-8") == "nsec-secret-must-not-be-copied"
    assert private_copy.stat().st_mode & 0o777 == 0o400
    keyfile.write_text("replaced-after-copy", encoding="utf-8")
    assert private_copy.read_text(encoding="utf-8") == "nsec-secret-must-not-be-copied"
    assert _git(snapshot, "config", "--local", "--get-all", "credential.helper") == ""
    assert "nsec-secret" not in (snapshot / ".git" / "config").read_text(encoding="utf-8")


def test_buzz_snapshot_rebinds_private_key_after_atomic_relocation(
    git_repo: Path, tmp_path: Path
) -> None:
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    _git(temporary, "init", "-q")
    keyfile = tmp_path / "private.key"
    keyfile.write_text("private", encoding="utf-8")
    keyfile.chmod(0o600)
    _git(git_repo, "config", "nostr.keyfile", str(keyfile))
    _git(git_repo, "config", "credential.https://buzz.example.com.helper", "nostr")
    _git(git_repo, "config", "credential.https://buzz.example.com.useHttpPath", "true")

    _copy_buzz_auth_config(git_repo, temporary, "https://buzz.example.com/repo.git")
    final = tmp_path / "final"
    os.replace(temporary, final)
    _rebind_buzz_auth_config(final)

    configured = Path(_git(final, "config", "--get", "nostr.keyfile"))
    assert configured == final / ".git" / "shipyard-credentials" / "nostr.key"
    assert configured.is_file()


def test_buzz_snapshot_rejects_arbitrary_credential_helper_command(
    git_repo: Path, tmp_path: Path
) -> None:
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    _git(snapshot, "init", "-q")
    host = "buzz.example.com"
    _git(git_repo, "config", f"credential.https://{host}.helper", "!steal-secrets")
    _git(git_repo, "config", f"credential.https://{host}.useHttpPath", "true")

    with pytest.raises(ExecutionSnapshotError, match="host-scoped nostr helper"):
        _copy_buzz_auth_config(
            git_repo,
            snapshot,
            f"https://{host}/git/owner/repository.git",
        )


def test_artifact_copy_is_anchored_when_parent_path_is_swapped(
    tmp_path: Path, monkeypatch
) -> None:
    source = tmp_path / "source"
    parent = source / "safe"
    parent.mkdir(parents=True)
    approved = b"approved-artifact"
    (parent / "release.bin").write_bytes(approved)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "release.bin").write_bytes(b"tampered-external-artifact")
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    original_open = os.open
    swapped = False

    def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if not swapped and str(path).endswith("release.bin"):
            swapped = True
            parent.rename(source / "approved-parent")
            parent.symlink_to(outside, target_is_directory=True)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", swapping_open)
    _copy_approved_artifact(
        source,
        snapshot,
        {
            "path": "safe/release.bin",
            "size": len(approved),
            "sha256": hashlib.sha256(approved).hexdigest(),
        },
    )

    assert (snapshot / "safe" / "release.bin").read_bytes() == approved


def test_artifact_copy_rejects_symlinked_destination_parent(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "safe").mkdir(parents=True)
    approved = b"approved-artifact"
    (source / "safe" / "release.bin").write_bytes(approved)
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    redirected = snapshot / "redirected"
    redirected.mkdir()
    (snapshot / "safe").symlink_to(redirected, target_is_directory=True)

    with pytest.raises(ExecutionSnapshotError, match="destination path is unsafe"):
        _copy_approved_artifact(
            source,
            snapshot,
            {
                "path": "safe/release.bin",
                "size": len(approved),
                "sha256": hashlib.sha256(approved).hexdigest(),
            },
        )

    assert not (redirected / "release.bin").exists()


def test_private_copy_rejects_symlinked_destination_parent(tmp_path: Path) -> None:
    source = tmp_path / "private.key"
    source.write_text("private", encoding="utf-8")
    source.chmod(0o600)
    outside = tmp_path / "outside"
    outside.mkdir()
    destination_parent = tmp_path / "credentials"
    destination_parent.symlink_to(outside, target_is_directory=True)

    with pytest.raises(SafeFileError, match="private destination path is unsafe"):
        copy_private_regular(source, destination_parent / "nostr.key")

    assert not (outside / "nostr.key").exists()


def test_freeze_rejects_symlink_descendants(tmp_path: Path) -> None:
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    (snapshot / "regular").write_text("safe", encoding="utf-8")
    (snapshot / "link").symlink_to(snapshot / "regular")

    with pytest.raises(ExecutionSnapshotError, match="contains a symlink"):
        freeze_execution_snapshot(snapshot)


def test_recovery_rejects_dangling_snapshot_symlink(tmp_path: Path) -> None:
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir()
    (snapshots / "run-1").symlink_to(tmp_path / "missing", target_is_directory=True)

    with pytest.raises(ExecutionSnapshotError, match="path is unsafe"):
        execution_snapshot_run(
            tmp_path, cast(ReleaseRun, SimpleNamespace(run_id="run-1"))
        )
