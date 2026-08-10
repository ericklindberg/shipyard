from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


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
