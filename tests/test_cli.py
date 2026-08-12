from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest

from shipyard import cli
from shipyard.adapters.base import AdapterStatus, ProviderReadback
from shipyard.gitops import GitError, RepositorySnapshot
from shipyard.observations import ObservationStore, ReleaseObservation
from shipyard.quickstart import run_quickstart
from shipyard.release_inspection import ProviderInspection, ReleaseInspection
from shipyard.release_project import load_release_project


def json_data(text: str):
    envelope = json.loads(text)
    assert envelope["api_version"] == "shipyard.cli/v1"
    assert envelope["ok"] is True
    assert isinstance(envelope["status"], str)
    return envelope["data"]


def test_release_project_source_identity_matches_https_and_ssh_transports(tmp_path):
    snapshot = RepositorySnapshot(
        path=tmp_path,
        sha="a" * 40,
        branch=None,
        dirty=False,
        changed_paths=(),
        remote_url="git@github.com:example/example.git",
        upstream_sha=None,
        worktree_digest=None,
    )

    cli._verify_release_project_source(
        "https://github.com/example/example.git", snapshot
    )


def test_release_project_source_identity_rejects_different_repository(tmp_path):
    snapshot = RepositorySnapshot(
        path=tmp_path,
        sha="a" * 40,
        branch=None,
        dirty=False,
        changed_paths=(),
        remote_url="git@github.com:example/other.git",
        upstream_sha=None,
        worktree_digest=None,
    )

    with pytest.raises(GitError, match="source_remote does not match"):
        cli._verify_release_project_source(
            "https://github.com/example/example.git", snapshot
        )


def run_cli(args, *, cwd: Path):
    env = os.environ.copy()
    src = Path(__file__).parents[1] / "src"
    env["PYTHONPATH"] = f"{src}{os.pathsep}{env.get('PYTHONPATH', '')}"
    return subprocess.run(
        [sys.executable, "-m", "shipyard", *args],
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
    )


def test_inspect_json_is_machine_readable(git_repo):
    result = run_cli(["inspect", str(git_repo), "--json"], cwd=git_repo)

    assert result.returncode == 0, result.stderr
    payload = json_data(result.stdout)
    assert payload["branch"] == "main"
    assert len(payload["sha"]) == 40
    assert payload["dirty"] is False


def test_plan_reports_external_boundary_without_running_it(git_repo, tmp_path):
    playbook = tmp_path / "shipyard.toml"
    playbook.write_text(
        '''schema_version = 1
name = "cli-test"
target = "test"

[[steps]]
id = "external"
name = "External"
effect = "external"
command = ["git", "push", "origin", "{sha}:refs/heads/main"]
''',
        encoding="utf-8",
    )

    result = run_cli(
        ["plan", str(git_repo), "--playbook", str(playbook), "--json"], cwd=git_repo
    )

    assert result.returncode == 0, result.stderr
    payload = json_data(result.stdout)
    assert payload["source"]["sha"]
    assert payload["steps"][0]["effect"] == "external"
    assert payload["steps"][0]["requires_confirmation"] is True


def test_uncertain_external_outcome_has_distinct_exit_code(git_repo, tmp_path):
    playbook = tmp_path / "uncertain.toml"
    playbook.write_text(
        '''schema_version = 1
name = "uncertain"
target = "production"

[[steps]]
id = "publish"
name = "Publish"
effect = "external"
command = ["python3", "-c", "raise SystemExit(7)"]
''',
        encoding="utf-8",
    )
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=git_repo,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()

    prepared = run_cli(
        [
            "run",
            str(git_repo),
            "--playbook",
            str(playbook),
            "--state-dir",
            str(tmp_path / "state"),
            "--json",
        ],
        cwd=git_repo,
    )
    assert prepared.returncode == 3, prepared.stderr
    prepared_payload = json_data(prepared.stdout)
    assert prepared_payload["status"] == "awaiting_authorization"
    assert prepared_payload["candidate_digest"]

    result = run_cli(
        [
            "resume",
            prepared_payload["run_id"],
            "--state-dir",
            str(tmp_path / "state"),
            "--execute-external",
            "--confirm-sha",
            sha,
            "--approve-candidate",
            prepared_payload["candidate_digest"],
            "--approval-actor",
            "pytest",
            "--approval-reason",
            "exercise uncertain outcome",
            "--json",
        ],
        cwd=git_repo,
    )

    assert result.returncode == 4, result.stderr
    payload = json_data(result.stdout)
    assert payload["status"] == "uncertain"

    status = run_cli(
        [
            "status",
            payload["run_id"],
            "--state-dir",
            str(tmp_path / "state"),
            "--json",
        ],
        cwd=git_repo,
    )
    assert status.returncode == 4, status.stderr
    assert json_data(status.stdout)["status"] == "uncertain"

    resumed = run_cli(
        [
            "resume",
            payload["run_id"],
            "--state-dir",
            str(tmp_path / "state"),
            "--execute-external",
            "--confirm-sha",
            sha,
            "--json",
        ],
        cwd=git_repo,
    )
    assert resumed.returncode == 4
    assert "outcome is unknown" in resumed.stderr


def test_quickstart_cli_runs_real_local_release_and_evidence(tmp_path):
    destination = tmp_path / "quickstart"

    result = run_cli(["quickstart", str(destination), "--json"], cwd=tmp_path)

    assert result.returncode == 0, result.stderr
    payload = json_data(result.stdout)
    assert payload["status"] == "succeeded"
    assert payload["source_sha"] == payload["remote_sha"]
    assert payload["evidence_verified"] is True
    assert Path(payload["evidence_path"]).is_file()


def test_evidence_report_cli_verifies_then_writes_static_report(tmp_path):
    destination = tmp_path / "quickstart"
    quickstart = run_cli(["quickstart", str(destination), "--json"], cwd=tmp_path)
    bundle = json_data(quickstart.stdout)["evidence_path"]
    report_path = tmp_path / "report.html"

    result = run_cli(
        [
            "evidence",
            "report",
            bundle,
            "--format",
            "html",
            "--output",
            str(report_path),
            "--json",
        ],
        cwd=tmp_path,
    )

    assert result.returncode == 0, result.stderr
    payload = json_data(result.stdout)
    assert payload["valid"] is True
    assert payload["format"] == "html"
    assert report_path.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert stat.S_IMODE(report_path.stat().st_mode) == 0o600


def test_github_bootstrap_cli_writes_real_workflow_and_playbook(tmp_path):
    output = tmp_path / "bootstrap"

    result = run_cli(
        [
            "bootstrap",
            "github-actions",
            "acme",
            "widget",
            "a" * 40,
            "--repository-id",
            "1234",
            "--workflow-id",
            "5678",
            "--output-dir",
            str(output),
            "--json",
        ],
        cwd=tmp_path,
    )

    assert result.returncode == 0, result.stderr
    payload = json_data(result.stdout)
    assert len(payload["created"]) == 3
    assert (output / "shipyard.toml").is_file()
    workflow = (output / ".github/workflows/shipyard.yml").read_text(
        encoding="utf-8"
    )
    assert "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" in workflow


def _release_project(path: Path) -> Path:
    path.write_text(
        '''schema_version = 1
name = "cli-release"
source_remote = "https://github.com/example/example.git"

[apple]
workflow_id = "workflow-1"
source_remote = "https://github.com/example/example.git"
source_git_remote = "origin"
bundle_id = "com.example.app"
beta_group_name = "Testing"
expected_marketing_version = "1.1"
token_env = "APPLE_ASC_TOKEN"

[[gates]]
name = "physical-device"
required_for = ["external", "production"]
''',
        encoding="utf-8",
    )
    path.chmod(0o644)
    return path


def test_release_init_cli_creates_parseable_secret_free_project(tmp_path):
    output = tmp_path / "shipyard.release.toml"

    result = run_cli(
        ["release", "init", "--output", str(output), "--json"], cwd=tmp_path
    )

    assert result.returncode == 0, result.stderr
    payload = json_data(result.stdout)
    assert payload["secrets_stored"] is False
    assert output.is_file()
    assert load_release_project(output).apple is not None
    assert "PRIVATE KEY" not in output.read_text(encoding="utf-8")


def test_release_project_namespace_init_validate_show_is_offline_and_redacted(tmp_path):
    output = tmp_path / "shipyard.release.toml"

    initialized = run_cli(
        ["release", "project", "init", str(output), "--json"], cwd=tmp_path
    )
    validated = run_cli(
        ["release", "project", "validate", str(output), "--json"], cwd=tmp_path
    )
    shown = run_cli(
        ["release", "project", "show", str(output), "--json"], cwd=tmp_path
    )

    assert initialized.returncode == 0, initialized.stderr
    assert validated.returncode == 0, validated.stderr
    assert shown.returncode == 0, shown.stderr
    for result in (validated, shown):
        payload = json_data(result.stdout)
        assert payload["valid"] is True
        assert payload["offline"] is True
        assert payload["provider_mutations"] == 0
        assert "PRIVATE KEY" not in result.stdout


def test_release_project_init_derives_checkout_identity_and_renders_first_playbook(
    git_repo, tmp_path
):
    subprocess.run(
        ["git", "remote", "add", "origin", "git@github.com:acme/widget.git"],
        cwd=git_repo,
        check=True,
    )
    project_path = tmp_path / "release.toml"
    initialized = run_cli(
        [
            "release",
            "project",
            "init",
            str(project_path),
            "--repo",
            str(git_repo),
            "--json",
        ],
        cwd=git_repo,
    )
    assert initialized.returncode == 0, initialized.stderr
    initialized_payload = json_data(initialized.stdout)
    assert initialized_payload["derived_from_repository"] is True
    project = load_release_project(project_path)
    assert project.source_remote == "https://github.com/acme/widget.git"
    assert project.github is not None
    assert (project.github.owner, project.github.repo) == ("acme", "widget")

    output = tmp_path / "github-candidate.toml"
    rendered = run_cli(
        [
            "release",
            "playbook",
            "--project",
            str(project_path),
            "--source-sha",
            subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=git_repo,
                text=True,
                capture_output=True,
                check=True,
            ).stdout.strip(),
            "--phase",
            "github-candidate",
            "--repo",
            str(git_repo),
            "--output",
            str(output),
            "--json",
        ],
        cwd=git_repo,
    )
    assert rendered.returncode == 0, rendered.stderr
    assert json_data(rendered.stdout)["phase"] == "github-candidate"
    assert output.is_file()


def test_release_observation_namespace_lists_and_shows_without_network(tmp_path):
    project_path = _release_project(tmp_path / "shipyard.release.toml")
    project = load_release_project(project_path)
    state = tmp_path / "state"
    observation = ReleaseObservation.create(
        "github",
        project.digest,
        "a" * 40,
        ProviderReadback(
            "succeeded",
            "github-checks",
            "a" * 40,
            {"read_only": True},
        ),
        observed_at="2026-08-12T12:00:00Z",
    )
    path = ObservationStore(state).save(observation)

    listed = run_cli(
        [
            "release",
            "observation",
            "list",
            "--project",
            str(project_path),
            "--state-dir",
            str(state),
            "--json",
        ],
        cwd=tmp_path,
    )
    shown = run_cli(
        [
            "release",
            "observation",
            "show",
            str(path),
            "--state-dir",
            str(state),
            "--json",
        ],
        cwd=tmp_path,
    )

    assert listed.returncode == 0, listed.stderr
    listed_payload = json_data(listed.stdout)
    assert listed_payload["count"] == 1
    assert listed_payload["observations"][0]["observation_sha256"] == observation.digest
    assert listed_payload["provider_mutations"] == 0
    assert shown.returncode == 0, shown.stderr
    shown_payload = json_data(shown.stdout)
    assert shown_payload["observation"]["observation_sha256"] == observation.digest
    assert shown_payload["provider_mutations"] == 0


def test_release_playbook_cli_uses_verified_observation_not_raw_ids(tmp_path, monkeypatch):
    project_path = _release_project(tmp_path / "shipyard.release.toml")
    project = load_release_project(project_path)
    state = tmp_path / "state"
    source_sha = "a" * 40
    observation = ReleaseObservation.create(
        "apple",
        project.digest,
        source_sha,
        ProviderReadback(
            "succeeded",
            "run-609",
            source_sha,
            {
                "workflow_id": "workflow-1",
                "repository_id": "repository-1",
                "repository_identity": "github.com/example/example",
                "git_reference_id": "reference-1",
                "git_reference_name": f"refs/tags/shipyard-candidate-{source_sha}",
                "app_id": "app-1",
                "bundle_id": "com.example.app",
                "run_id": "run-609",
                "run_number": "609",
                "build_id": "build-609",
                "build_number": "609",
                "processing_state": "VALID",
                "expired": False,
                "pre_release_version_id": "version-1",
                "marketing_version": "1.1",
                "beta_group_id": "group-testing",
                "beta_group_name": "Testing",
                "beta_group_internal": True,
                "relationship_present": False,
                "internal_build_state": "READY_FOR_BETA_TESTING",
                "external_build_state": "READY_FOR_BETA_SUBMISSION",
            },
        ),
        observed_at="2026-08-12T12:00:00Z",
    )
    observation_path = ObservationStore(state).save(observation)
    monkeypatch.setenv("APPLE_ASC_TOKEN", "secret-token")
    output = tmp_path / "testflight.toml"

    result = run_cli(
        [
            "release",
            "playbook",
            "--project",
            str(project_path),
            "--source-sha",
            source_sha,
            "--apple-observation",
            str(observation_path),
            "--state-dir",
            str(state),
            "--output",
            str(output),
            "--json",
        ],
        cwd=tmp_path,
    )

    assert result.returncode == 0, result.stderr
    payload = json_data(result.stdout)
    assert payload["provider_mutations"] == 0
    assert payload["requires_candidate_approval"] is True
    content = output.read_text(encoding="utf-8")
    assert 'build_id = "build-609"' in content
    assert "secret-token" not in content


def test_release_dossier_cli_exports_and_offline_verifies(tmp_path):
    quickstart = run_quickstart(tmp_path / "quickstart")
    project_path = _release_project(tmp_path / "shipyard.release.toml")
    output = tmp_path / "dossier.tar"

    exported = run_cli(
        [
            "release",
            "dossier",
            "export",
            "--project",
            str(project_path),
            "--source-sha",
            quickstart.source_sha,
            "--scope",
            "internal",
            "--run",
            f"candidate={quickstart.evidence_path}",
            "--output",
            str(output),
            "--json",
        ],
        cwd=tmp_path,
    )
    verified = run_cli(
        ["release", "dossier", "verify", str(output), "--json"], cwd=tmp_path
    )

    assert exported.returncode == 0, exported.stderr
    assert json_data(exported.stdout)["valid"] is True
    assert verified.returncode == 0, verified.stderr
    assert json_data(verified.stdout)["runs_verified"] == 1


def test_invalid_dossier_json_sets_ok_false_and_preserves_report(tmp_path):
    quickstart = run_quickstart(tmp_path / "quickstart")

    result = run_cli(
        [
            "release",
            "dossier",
            "verify",
            str(quickstart.evidence_path),
            "--json",
        ],
        cwd=tmp_path,
    )

    assert result.returncode == 1
    assert result.stderr == ""
    envelope = json.loads(result.stdout)
    assert envelope["api_version"] == "shipyard.cli/v1"
    assert envelope["ok"] is False
    assert envelope["status"] == "invalid"
    assert envelope["data"]["valid"] is False
    assert envelope["data"]["errors"]


def test_wait_cli_uses_readback_once_without_resolve(monkeypatch, tmp_path, capsys):
    statuses = iter(["pending", "succeeded"])

    class FakeExecutor:
        def __init__(self, ledger):
            self.ledger = ledger

        def readback_once(self, run_id):
            return ProviderReadback(
                cast(AdapterStatus, next(statuses)), "op-1", "a" * 40, {}
            )

        def resolve(self, run_id):
            raise AssertionError("wait must not resolve or continue execution")

    monkeypatch.setattr(cli, "Ledger", lambda _: object())
    monkeypatch.setattr(cli, "ReleaseExecutor", FakeExecutor)

    code = cli.main(
        [
            "wait",
            "run-1",
            "--state-dir",
            str(tmp_path / "state"),
            "--timeout",
            "1",
            "--interval",
            "0.01",
            "--json",
        ]
    )

    assert code == 0
    payload = json_data(capsys.readouterr().out)
    assert payload["state"] == "succeeded"
    assert payload["polls"] == 2


def test_release_wait_polls_shared_inspection_without_persisting(
    monkeypatch, git_repo, tmp_path, capsys
):
    project_path = _release_project(tmp_path / "shipyard.release.toml")
    subprocess.run(
        ["git", "remote", "add", "origin", "https://github.com/example/example.git"],
        cwd=git_repo,
        check=True,
    )
    statuses = iter(["pending", "succeeded"])

    def fake_inspect(project, source_sha, **kwargs):
        status = cast(AdapterStatus, next(statuses))
        return ReleaseInspection(
            source_sha,
            (
                ProviderInspection(
                    "github",
                    ProviderReadback(status, "github-checks", source_sha, {"read_only": True}),
                ),
            ),
        )

    class ForbiddenStore:
        def __init__(self, *args, **kwargs):
            raise AssertionError("release wait must not create an observation store")

    monkeypatch.setattr(cli, "inspect_release", fake_inspect)
    monkeypatch.setattr(cli, "ObservationStore", ForbiddenStore)

    code = cli.main(
        [
            "release",
            "wait",
            str(git_repo),
            "--project",
            str(project_path),
            "--provider",
            "github",
            "--allow-network",
            "--timeout",
            "1",
            "--interval",
            "0.01",
            "--json",
        ]
    )

    assert code == 0
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["status"] == "succeeded"
    payload = envelope["data"]
    assert payload["persisted"] is False
    assert payload["provider_mutations"] == 0
    assert payload["polls"] == 2


def test_invalid_json_invocation_emits_one_structured_document(tmp_path):
    result = run_cli(
        ["release", "playbook", "--json"],
        cwd=tmp_path,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    envelope = json.loads(result.stderr)
    assert envelope["api_version"] == "shipyard.cli/v1"
    assert envelope["ok"] is False
    assert envelope["status"] == "invalid"
    assert envelope["data"] is None
    assert envelope["error"]["code"] == "INVALID_ARGUMENT"
    assert envelope["error"]["retryable"] is False
    assert envelope["error"]["mutation"] == "none"


def test_signed_approval_cli_round_trip_binds_current_ledger_candidate(
    git_repo, tmp_path
):
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    subprocess.run(
        ["git", "remote", "add", "origin", str(remote)], cwd=git_repo, check=True
    )
    playbook = tmp_path / "approval.toml"
    playbook.write_text(
        '''schema_version = 2
name = "signed-approval"
target = "sandbox"
provider = "github"
destination = "sandbox:refs/heads/release"

[[steps]]
id = "publish"
name = "Publish"
effect = "external"
action = "git.ref"

[steps.config]
remote = "origin"
ref = "refs/heads/release"
''',
        encoding="utf-8",
    )
    state = tmp_path / "state"
    prepared = run_cli(
        [
            "run",
            str(git_repo),
            "--playbook",
            str(playbook),
            "--state-dir",
            str(state),
            "--json",
        ],
        cwd=git_repo,
    )
    prepared_payload = json_data(prepared.stdout)
    review = tmp_path / "review.json"
    signed = tmp_path / "signed.json"
    key = tmp_path / "approval-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    public_key = key.with_suffix(".pub").read_text(encoding="utf-8").strip()
    allowed = tmp_path / "allowed-signers"
    allowed.write_text(f"alice@example.com {public_key}\n", encoding="utf-8")

    exported = run_cli(
        [
            "approval",
            "export",
            prepared_payload["run_id"],
            "--state-dir",
            str(state),
            "--output",
            str(review),
            "--json",
        ],
        cwd=git_repo,
    )
    assert exported.returncode == 0, exported.stderr
    signed_result = run_cli(
        [
            "approval",
            "sign",
            str(review),
            "--key",
            str(key),
            "--actor",
            "alice@example.com",
            "--reason",
            "reviewed exact candidate",
            "--approved-at",
            "2026-08-11T00:00:00Z",
            "--output",
            str(signed),
            "--json",
        ],
        cwd=git_repo,
    )
    assert signed_result.returncode == 0, signed_result.stderr
    verified = run_cli(
        [
            "approval",
            "verify",
            str(review),
            str(signed),
            "--allowed-signers",
            str(allowed),
            "--json",
        ],
        cwd=git_repo,
    )
    assert verified.returncode == 0, verified.stderr
    imported = run_cli(
        [
            "approval",
            "import",
            prepared_payload["run_id"],
            "--state-dir",
            str(state),
            "--review",
            str(review),
            "--signed",
            str(signed),
            "--allowed-signers",
            str(allowed),
            "--json",
        ],
        cwd=git_repo,
    )
    assert imported.returncode == 0, imported.stderr

    status = run_cli(
        [
            "status",
            prepared_payload["run_id"],
            "--state-dir",
            str(state),
            "--json",
        ],
        cwd=git_repo,
    )
    approval = json_data(status.stdout)["approval"]
    assert approval["actor"] == "alice@example.com"
    assert approval["approved_at"] == "2026-08-11T00:00:00Z"
