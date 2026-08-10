from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from shipyard.connections import ConnectionStore

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts/validate_provider_sandbox.py"


def _git(path: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=path, check=True, capture_output=True, text=True
    ).stdout.strip()


def test_sandbox_harness_checks_then_mutates_only_with_exact_confirmations(git_repo, tmp_path):
    bare = tmp_path / "sandbox.git"
    subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True)
    _git(git_repo, "remote", "add", "sandbox", str(bare))
    _git(git_repo, "push", "sandbox", "HEAD:refs/heads/sandbox")

    config_dir = tmp_path / "config"
    profile = ConnectionStore(config_dir).add(
        "sandbox-git",
        "github",
        {"remote": "sandbox", "ref": "refs/heads/sandbox"},
    )
    state_dir = tmp_path / "state"

    checked = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "sandbox-git",
            "--repo",
            str(git_repo),
            "--config-dir",
            str(config_dir),
            "--state-dir",
            str(state_dir),
            "--confirm-destination",
            profile.destination,
        ],
        text=True,
        capture_output=True,
    )
    assert checked.returncode == 0, checked.stderr
    check_payload = json.loads(checked.stdout)
    assert check_payload["schema_version"] == 1
    assert check_payload["check"]["status"] == "verified"
    assert check_payload["mutation_executed"] is False

    (git_repo / "sandbox.txt").write_text("candidate\n", encoding="utf-8")
    _git(git_repo, "add", "sandbox.txt")
    _git(git_repo, "commit", "-m", "sandbox candidate")
    candidate_sha = _git(git_repo, "rev-parse", "HEAD")

    wrong = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "sandbox-git",
            "--repo",
            str(git_repo),
            "--config-dir",
            str(config_dir),
            "--state-dir",
            str(state_dir),
            "--confirm-destination",
            "wrong-destination",
            "--execute-mutation",
            "--confirm-sha",
            candidate_sha,
            "--approval-actor",
            "pytest",
            "--approval-reason",
            "sandbox contract",
        ],
        text=True,
        capture_output=True,
    )
    assert wrong.returncode == 2
    assert _git(bare, "rev-parse", "refs/heads/sandbox") != candidate_sha

    executed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "sandbox-git",
            "--repo",
            str(git_repo),
            "--config-dir",
            str(config_dir),
            "--state-dir",
            str(state_dir),
            "--confirm-destination",
            profile.destination,
            "--execute-mutation",
            "--confirm-sha",
            candidate_sha,
            "--approval-actor",
            "pytest",
            "--approval-reason",
            "sandbox contract",
        ],
        text=True,
        capture_output=True,
    )
    assert executed.returncode == 0, executed.stderr
    payload = json.loads(executed.stdout)
    assert payload["candidate_sha"] == candidate_sha
    assert payload["mutation_executed"] is True
    assert payload["run_status"] == "succeeded"
    assert _git(bare, "rev-parse", "refs/heads/sandbox") == candidate_sha
