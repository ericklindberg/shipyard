from __future__ import annotations

import subprocess

from shipyard.gitops import snapshot_repository


def test_snapshot_records_exact_sha_branch_and_cleanliness(git_repo):
    expected_sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=git_repo, text=True
    ).strip()

    snapshot = snapshot_repository(git_repo)

    assert snapshot.sha == expected_sha
    assert snapshot.branch == "main"
    assert snapshot.dirty is False
    assert snapshot.remote_url is None
    assert snapshot.upstream_sha is None


def test_snapshot_detects_and_fingerprints_dirty_files(git_repo):
    (git_repo / "README.md").write_text("changed\n", encoding="utf-8")
    (git_repo / "untracked.txt").write_text("dirty\n", encoding="utf-8")

    first = snapshot_repository(git_repo)

    assert first.dirty is True
    assert first.changed_paths == ("README.md", "untracked.txt")
    assert first.worktree_digest is not None

    (git_repo / "README.md").write_text("changed again\n", encoding="utf-8")
    second = snapshot_repository(git_repo)
    assert second.worktree_digest != first.worktree_digest
