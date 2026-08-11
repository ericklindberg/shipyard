from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import cast

from shipyard import cli
from shipyard.adapters.base import AdapterStatus, ProviderReadback


def json_data(text: str):
    envelope = json.loads(text)
    assert envelope["api_version"] == "shipyard.cli/v1"
    assert envelope["ok"] is True
    return envelope["data"]


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
