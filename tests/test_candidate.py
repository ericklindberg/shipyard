from __future__ import annotations

import json
from pathlib import Path

import pytest

from shipyard.candidate import CandidateError, build_candidate
from shipyard.gitops import snapshot_repository
from shipyard.ledger import Ledger
from shipyard.playbook import load_playbook


def _playbook(path: Path, artifact: Path) -> Path:
    path.write_text(
        f'''schema_version = 1
name = "candidate"
target = "production"
provider = "github"
destination = "owner/repo:refs/heads/main"

[[artifacts]]
path = {json.dumps(artifact.name)}

[[steps]]
id = "push"
name = "Push"
effect = "external"
command = ["git", "push", "origin", "{{sha}}:refs/heads/main"]
''',
        encoding="utf-8",
    )
    return path


def test_candidate_binds_source_plan_destination_artifact_and_runtime(git_repo, tmp_path):
    artifact = git_repo / "release.bin"
    artifact.write_bytes(b"release-one")
    playbook = load_playbook(_playbook(tmp_path / "shipyard.toml", artifact))
    run = Ledger(tmp_path / "state").create_run(snapshot_repository(git_repo), playbook)

    first = build_candidate(run)
    second = build_candidate(run)

    assert first.digest == second.digest
    assert first.payload["source"]["sha"] == run.source_sha
    assert first.payload["destination"] == {
        "provider": "github",
        "identity": "owner/repo:refs/heads/main",
    }
    assert first.payload["artifacts"][0]["sha256"]
    assert first.payload["runtime"]["package_version"]
    assert first.payload["executables"][0]["sha256"]

    artifact.write_bytes(b"release-two")
    changed = build_candidate(run)
    assert changed.digest != first.digest


def test_candidate_rejects_missing_or_escaping_artifacts(git_repo, tmp_path):
    playbook_path = tmp_path / "shipyard.toml"
    missing = git_repo / "missing.bin"
    playbook = load_playbook(_playbook(playbook_path, missing))
    run = Ledger(tmp_path / "state").create_run(snapshot_repository(git_repo), playbook)

    with pytest.raises(CandidateError, match="required artifact is missing"):
        build_candidate(run)

    playbook_path.write_text(
        '''schema_version = 1
name = "candidate"
target = "production"
provider = "github"
destination = "owner/repo:refs/heads/main"

[[artifacts]]
path = "../escape.bin"

[[steps]]
id = "push"
name = "Push"
effect = "external"
command = ["git", "push", "origin", "{sha}:refs/heads/main"]
''',
        encoding="utf-8",
    )
    escaped = load_playbook(playbook_path)
    escaped_run = Ledger(tmp_path / "other-state").create_run(
        snapshot_repository(git_repo), escaped
    )
    with pytest.raises(CandidateError, match="escapes repository"):
        build_candidate(escaped_run)
