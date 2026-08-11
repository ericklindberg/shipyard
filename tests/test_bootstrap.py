from pathlib import Path

import pytest

from shipyard.bootstrap import BootstrapInputError, plan_github_bootstrap
from shipyard.playbook import load_playbook


def _plan():
    return plan_github_bootstrap(
        "acme",
        "widget",
        "a" * 40,
        repository_id="1234",
        workflow_id="5678",
    )


def test_bootstrap_plan_is_deterministic_and_safe(tmp_path: Path):
    bundle = _plan()

    assert set(bundle.files) == {
        ".github/workflows/shipyard.yml",
        "SHIPYARD_BOOTSTRAP.md",
        "shipyard.toml",
    }
    workflow = bundle.files[".github/workflows/shipyard.yml"]
    assert "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" in workflow
    assert "actions/checkout@v" not in workflow
    assert "persist-credentials: false" in workflow
    assert "inputs.source_sha" in workflow
    assert "performs no provider mutation" in workflow
    assert "secret-token" not in "".join(bundle.files.values())
    assert bundle == _plan()

    playbook_path = tmp_path / "shipyard.toml"
    playbook_path.write_text(bundle.files["shipyard.toml"], encoding="utf-8")
    playbook = load_playbook(playbook_path)
    assert playbook.steps[0].action == "github.workflow"
    assert playbook.steps[0].config["ref"] == (
        "refs/tags/shipyard-candidate-{source_sha}"
    )


@pytest.mark.parametrize(
    "owner,repo",
    [
        ("acme/x", "repo"),
        ("acme", "bad/repo"),
        ("", "repo"),
        ("acme", "repo.git"),
    ],
)
def test_bootstrap_rejects_noncanonical_names(owner, repo):
    with pytest.raises(BootstrapInputError):
        plan_github_bootstrap(
            owner,
            repo,
            "a" * 40,
            repository_id="1",
            workflow_id="2",
        )


@pytest.mark.parametrize(
    "source_sha", ["main", "refs/heads/main", "https://github.com/a/b", "a" * 39]
)
def test_bootstrap_requires_immutable_source_sha(source_sha):
    with pytest.raises(BootstrapInputError):
        plan_github_bootstrap(
            "acme",
            "repo",
            source_sha,
            repository_id="1",
            workflow_id="2",
        )


@pytest.mark.parametrize(
    "repository_id,workflow_id",
    [("0", "2"), ("1", "02"), ("owner", "2"), ("1", "https://example.test")],
)
def test_bootstrap_requires_numeric_provider_identities(repository_id, workflow_id):
    with pytest.raises(BootstrapInputError):
        plan_github_bootstrap(
            "acme",
            "repo",
            "a" * 40,
            repository_id=repository_id,
            workflow_id=workflow_id,
        )
