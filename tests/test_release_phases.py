from __future__ import annotations

from pathlib import Path

import pytest

from shipyard.playbook import load_playbook
from shipyard.release_phases import ReleasePhaseError, render_release_phase
from shipyard.release_project import load_release_project

SHA = "a" * 40


def _project(path: Path):
    path.write_text(
        '''schema_version = 1
name = "phase-test"
source_remote = "https://github.com/example/example.git"

[git]
github_remote = "origin"
buzz_remote = "buzz"
main_ref = "refs/heads/main"

[github]
owner = "example"
repo = "example"
repository_id = "1234"
required_workflow_ids = ["101"]
token_env = "GITHUB_ACTIONS_TOKEN"
''',
        encoding="utf-8",
    )
    path.chmod(0o644)
    return load_release_project(path)


@pytest.mark.parametrize(
    ("phase", "provider", "ref", "annotated"),
    [
        (
            "github-candidate",
            "github",
            f"refs/tags/shipyard-candidate-{SHA}",
            True,
        ),
        (
            "buzz-candidate",
            "buzz-git",
            f"refs/tags/shipyard-candidate-{SHA}",
            False,
        ),
        ("buzz-main", "buzz-git", "refs/heads/main", False),
        ("github-main", "github", "refs/heads/main", False),
    ],
)
def test_release_phase_playbooks_parse_with_correct_provider_tag_semantics(
    tmp_path, phase, provider, ref, annotated
) -> None:
    project = _project(tmp_path / "shipyard.release.toml")
    output = tmp_path / f"{phase}.toml"
    output.write_text(
        render_release_phase(
            project,
            source_sha=SHA,
            phase=phase,
            repo_path=str(tmp_path),
        ),
        encoding="utf-8",
    )

    playbook = load_playbook(output)

    assert playbook.provider == provider
    assert playbook.steps[0].config["ref"] == ref
    assert (playbook.steps[0].config.get("tag_kind") == "annotated") is annotated


def test_release_phase_rejects_buzz_phase_without_buzz_remote(tmp_path) -> None:
    path = tmp_path / "shipyard.release.toml"
    path.write_text(
        '''schema_version = 1
name = "no-buzz"
source_remote = "https://github.com/example/example.git"

[git]
github_remote = "origin"
main_ref = "refs/heads/main"

[github]
owner = "example"
repo = "example"
repository_id = "1234"
required_workflow_ids = ["101"]
token_env = "GITHUB_ACTIONS_TOKEN"
''',
        encoding="utf-8",
    )
    path.chmod(0o644)
    project = load_release_project(path)

    with pytest.raises(ReleasePhaseError, match="Buzz remote"):
        render_release_phase(
            project,
            source_sha=SHA,
            phase="buzz-main",
            repo_path=str(tmp_path),
        )
