from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from shipyard.execution_snapshot import (
    ExecutionSnapshotError,
    _copy_buzz_auth_config,
)


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

    assert _git(snapshot, "config", "--get", f"credential.https://{host}.helper") == "nostr"
    assert (
        _git(snapshot, "config", "--get", f"credential.https://{host}.useHttpPath")
        == "true"
    )
    assert _git(snapshot, "config", "--get", "nostr.keyfile") == str(keyfile.resolve())
    assert "nsec-secret" not in (snapshot / ".git" / "config").read_text(encoding="utf-8")


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
