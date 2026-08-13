from __future__ import annotations

import json
import stat
import threading
import urllib.error
import urllib.request

import pytest

from shipyard.cli import main
from shipyard.connections import ConnectionStore
from shipyard.gitops import snapshot_repository
from shipyard.ledger import Ledger
from shipyard.playbook import load_playbook
from shipyard.web import create_server


def test_init_generates_valid_typed_provider_playbooks(tmp_path):
    for provider in ("github", "github-actions", "buzz", "render", "heroku", "vercel"):
        destination = tmp_path / f"{provider}.toml"
        assert main(["init", provider, "--output", str(destination), "--json"]) == 0
        playbook = load_playbook(destination)
        assert playbook.schema_version == 2
        assert playbook.provider == provider
        assert playbook.steps[0].action is not None


def test_app_review_init_writes_parseable_conservative_manifest(tmp_path, capsys):
    destination = tmp_path / "review.json"
    assert main(["app-review", "init", "--output", str(destination), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["data"]["created"] == str(destination)
    assert payload["data"]["secrets_stored"] is False
    assert payload["data"]["network_access"] is False
    assert payload["data"]["provider_mutations"] == 0
    assert payload["data"]["next_steps"] == [
        f"edit non-secret submission facts in {destination}",
        f"shipyard app-review preflight {destination} --json",
    ]
    manifest = json.loads(destination.read_text())
    assert manifest["schema_version"] == "shipyard.app-review-preflight/v1"
    assert set(manifest) == {
        "schema_version",
        "app",
        "submission",
        "review_access",
        "privacy",
        "commerce",
        "authentication",
        "compliance",
    }
    assert manifest["privacy"]["privacy_policy_url"] == ""
    assert manifest["privacy"]["support_url"] == ""
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert main(["app-review", "preflight", str(destination), "--json"]) == 1
    findings = json.loads(capsys.readouterr().out)["data"]
    assert findings["status"] == "blocked"
    assert {item["id"] for item in findings["findings"]} >= {
        "submission-metadata",
        "current-screenshots",
        "privacy-policy-url",
        "support-url",
    }


def test_app_review_init_refuses_overwrite_and_symlink_without_force(tmp_path, capsys):
    destination = tmp_path / "review.json"
    destination.write_text("preserve-me", encoding="utf-8")

    assert main(["app-review", "init", "--output", str(destination), "--json"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "refusing to overwrite" in captured.err
    assert destination.read_text(encoding="utf-8") == "preserve-me"

    victim = tmp_path / "victim.json"
    victim.write_text("preserve-victim", encoding="utf-8")
    linked = tmp_path / "linked.json"
    linked.symlink_to(victim)
    assert (
        main(["app-review", "init", "--output", str(linked), "--force", "--json"])
        == 2
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "refusing symlink output" in captured.err
    assert victim.read_text(encoding="utf-8") == "preserve-victim"

    assert (
        main(["app-review", "init", "--output", str(destination), "--force", "--json"])
        == 0
    )
    assert json.loads(destination.read_text(encoding="utf-8"))["schema_version"] == (
        "shipyard.app-review-preflight/v1"
    )


def test_agent_facing_list_doctor_adapters_and_version_are_json(
    git_repo, tmp_path, capsys
):
    state = tmp_path / "state"
    commands = [
        ["list", "--state-dir", str(state), "--json"],
        ["doctor", str(git_repo), "--state-dir", str(state), "--json"],
        ["adapters", "--json"],
        ["version", "--json"],
    ]
    payloads = []
    for command in commands:
        assert main(command) == 0
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["api_version"] == "shipyard.cli/v1"
        assert envelope["ok"] is True
        payloads.append(envelope["data"])
    assert payloads[0] == {"runs": []}
    assert payloads[1]["ready"] is True
    assert "git.ref" in payloads[2]["actions"]
    assert len(payloads[3]["distribution_sha256"]) == 64


def test_json_errors_use_the_versioned_envelope(tmp_path, capsys):
    assert (
        main(
            [
                "connection",
                "show",
                "missing",
                "--config-dir",
                str(tmp_path / "config"),
                "--json",
            ]
        )
        == 2
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    envelope = json.loads(captured.err)
    assert envelope["api_version"] == "shipyard.cli/v1"
    assert envelope["ok"] is False
    assert envelope["status"] == "invalid"
    assert envelope["data"] is None
    assert envelope["error"]["code"] == "INVALID_REQUEST"
    assert envelope["error"]["message"] == "connection profile not found: missing"
    assert envelope["error"]["retryable"] is False
    assert envelope["error"]["mutation"] == "none"


def test_doctor_reports_missing_credentials_without_reading_values(
    git_repo, tmp_path, monkeypatch, capsys
):
    playbook = tmp_path / "render.toml"
    assert main(["init", "render", "--output", str(playbook), "--json"]) == 0
    capsys.readouterr()
    monkeypatch.delenv("RENDER_API_KEY", raising=False)

    assert (
        main(
            [
                "doctor",
                str(git_repo),
                "--state-dir",
                str(tmp_path / "state"),
                "--playbook",
                str(playbook),
                "--json",
            ]
        )
        == 1
    )
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["api_version"] == "shipyard.cli/v1"
    assert envelope["ok"] is True
    payload = envelope["data"]
    playbook_check = next(check for check in payload["checks"] if check["name"] == "playbook")
    assert playbook_check["detail"]["missing_credential_env"] == ["RENDER_API_KEY"]


def test_web_app_is_loopback_read_only_and_exposes_verified_run_data(
    git_repo, tmp_path, monkeypatch
):
    state = tmp_path / "state"
    config = tmp_path / "config"
    monkeypatch.setenv("RENDER_API_KEY", "web-secret-must-not-leak")
    ConnectionStore(config).add(
        "render-production",
        "render",
        {"service_id": "srv-example", "token_env": "RENDER_API_KEY"},
    )
    ledger = Ledger(state)
    playbook_path = tmp_path / "local.toml"
    playbook_path.write_text(
        '''schema_version = 1
name = "local"
target = "local"

[[steps]]
id = "verify"
name = "Verify"
effect = "verify"
command = ["git", "status", "--short"]
''',
        encoding="utf-8",
    )
    ledger.create_run(snapshot_repository(git_repo), load_playbook(playbook_path))
    server = create_server(state, port=0, config_dir=config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        with urllib.request.urlopen(f"{base}/api/health", timeout=5) as response:
            health = json.load(response)
            assert response.headers["Cache-Control"] == "no-store"
        with urllib.request.urlopen(f"{base}/api/runs", timeout=5) as response:
            runs = json.load(response)
        with urllib.request.urlopen(f"{base}/api/connections", timeout=5) as response:
            connections = json.load(response)
        assert health["status"] == "ok"
        assert len(runs["runs"]) == 1
        assert connections["connections"][0]["name"] == "render-production"
        assert connections["connections"][0]["credential_env"][0]["present"] is True
        assert "web-secret-must-not-leak" not in json.dumps(connections)
        hostile = urllib.request.Request(
            f"{base}/api/connections", headers={"Host": "attacker.example"}
        )
        with pytest.raises(urllib.error.HTTPError) as rejected:
            urllib.request.urlopen(hostile, timeout=5)
        assert rejected.value.code == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    with pytest.raises(ValueError, match="loopback"):
        create_server(state, host="0.0.0.0", port=0)
