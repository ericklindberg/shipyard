from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def enable_legacy_external_only_for_v1_regression_tests(monkeypatch):
    monkeypatch.setenv("SHIPYARD_ENABLE_LEGACY_EXTERNAL", "1")


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
