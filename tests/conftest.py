from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def enable_legacy_external_only_for_v1_regression_tests(monkeypatch):
    monkeypatch.setenv("SHIPYARD_ENABLE_LEGACY_EXTERNAL", "1")


@pytest.fixture(autouse=True)
def isolate_global_target_locks_per_test(monkeypatch, tmp_path: Path):
    # Production locks must be shared across state directories. Test processes need
    # distinct roots so concurrent local/CI suites cannot fence each other.
    monkeypatch.setenv("SHIPYARD_GLOBAL_LOCK_DIR", str(tmp_path / "global-target-locks"))


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Shipyard Tests"], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "shipyard-tests@localhost"], cwd=repo, check=True
    )
    (repo / "README.md").write_text("test repository\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "initial"], cwd=repo, check=True)
    return repo
