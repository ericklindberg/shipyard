from __future__ import annotations

import json
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
    for provider in ("github", "buzz", "render", "heroku", "vercel"):
        destination = tmp_path / f"{provider}.toml"
        assert main(["init", provider, "--output", str(destination), "--json"]) == 0
        playbook = load_playbook(destination)
        assert playbook.schema_version == 2
        assert playbook.provider == provider
        assert playbook.steps[0].action is not None


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
    assert envelope == {
        "api_version": "shipyard.cli/v1",
        "ok": False,
        "error": {"message": "connection profile not found: missing"},
    }


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
