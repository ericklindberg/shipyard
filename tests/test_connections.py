from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from shipyard.adapters.base import ConnectionCheck
from shipyard.cli import main
from shipyard.connections import (
    ConnectionError,
    ConnectionProfile,
    ConnectionStore,
    render_playbook,
    verify_connection,
)
from shipyard.playbook import load_playbook

SHA = "a" * 40


def json_data(text: str):
    envelope = json.loads(text)
    assert envelope["api_version"] == "shipyard.cli/v1"
    assert envelope["ok"] is True
    return envelope["data"]


def test_connection_store_is_user_scoped_private_and_never_serializes_secret_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RENDER_API_KEY", "live-secret-must-not-be-stored")
    store = ConnectionStore(tmp_path / "config")

    profile = store.add(
        "render-production",
        "render",
        {
            "service_id": "srv-example",
            "token_env": "RENDER_API_KEY",
        },
    )

    assert profile.provider == "render"
    assert profile.action == "render.deploy"
    assert profile.destination == "render:srv-example"
    assert (store.config_dir.stat().st_mode & 0o777) == 0o700
    assert (store.path.stat().st_mode & 0o777) == 0o600
    serialized = store.path.read_text(encoding="utf-8")
    assert "RENDER_API_KEY" in serialized
    assert "live-secret-must-not-be-stored" not in serialized
    assert store.get("render-production") == profile


def test_connection_store_rejects_duplicate_unknown_and_literal_credentials(tmp_path: Path) -> None:
    store = ConnectionStore(tmp_path / "config")
    store.add(
        "render-production",
        "render",
        {"service_id": "srv-example", "token_env": "RENDER_API_KEY"},
    )

    with pytest.raises(ConnectionError, match="already exists"):
        store.add(
            "render-production",
            "render",
            {"service_id": "srv-other", "token_env": "RENDER_API_KEY"},
        )
    with pytest.raises(ConnectionError, match="unsupported option"):
        store.add(
            "render-other",
            "render",
            {
                "service_id": "srv-example",
                "token_env": "RENDER_API_KEY",
                "api_base": "https://internal.invalid",
            },
        )
    with pytest.raises(ConnectionError, match="literal credentials"):
        store.add(
            "render-secret",
            "render",
            {"service_id": "srv-example", "token": "do-not-store-me"},
        )
    with pytest.raises(ConnectionError, match="must use a RENDER_"):
        store.add(
            "render-confused-secret",
            "render",
            {"service_id": "srv-example", "token_env": "AWS_SECRET_ACCESS_KEY"},
        )
    with pytest.raises(ConnectionError, match="provider identifier"):
        store.add(
            "render-path-injection",
            "render",
            {"service_id": "../admin", "token_env": "RENDER_API_KEY"},
        )


def test_connection_store_rejects_symlinked_storage(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir(mode=0o700)
    target = tmp_path / "target.json"
    target.write_text('{"schema_version": 1, "profiles": {}}', encoding="utf-8")
    (config_dir / "connections.json").symlink_to(target)

    with pytest.raises(ConnectionError, match="symlink"):
        ConnectionStore(config_dir).list()


def test_connection_store_rejects_unsafe_permissions_and_newer_schema(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir(mode=0o700)
    path = config_dir / "connections.json"
    path.write_text('{"schema_version": 1, "profiles": {}}', encoding="utf-8")
    path.chmod(0o644)

    with pytest.raises(ConnectionError, match="permissions.*0600"):
        ConnectionStore(config_dir).list()

    path.chmod(0o600)
    path.write_text('{"schema_version": 99, "profiles": {}}', encoding="utf-8")
    with pytest.raises(ConnectionError, match="profile schema"):
        ConnectionStore(config_dir).list()


def test_connection_store_detects_config_directory_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_dir = tmp_path / "config"
    store = ConnectionStore(config_dir)
    original_ensure = store._ensure_dir

    def replace_after_validation():
        metadata = original_ensure()
        config_dir.rename(tmp_path / "original-config")
        config_dir.mkdir(mode=0o700)
        return metadata

    monkeypatch.setattr(store, "_ensure_dir", replace_after_validation)
    with pytest.raises(ConnectionError, match="changed during access"):
        store.list()


def test_connection_store_rejects_malformed_profile_names(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir(mode=0o700)
    path = config_dir / "connections.json"
    path.write_text(
        '{"schema_version": 1, "profiles": {"Bad Name": {}}}', encoding="utf-8"
    )
    path.chmod(0o600)

    with pytest.raises(ConnectionError, match="invalid profile name"):
        ConnectionStore(config_dir).list()


def test_all_supported_provider_profiles_validate_and_expose_only_secret_presence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ConnectionStore(tmp_path / "config")
    monkeypatch.delenv("GITHUB_ACTIONS_TOKEN", raising=False)
    profiles = [
        store.add(
            "github-production",
            "github",
            {"remote": "origin", "ref": "refs/heads/main"},
        ),
        store.add(
            "github-actions-production",
            "github-actions",
            {
                "owner": "owner",
                "repo": "mobile-app",
                "repository_id": "1234",
                "workflow_id": "5678",
                "workflow_file": "release.yml",
                "ref": f"refs/tags/shipyard-candidate-{SHA}",
                "token_env": "GITHUB_ACTIONS_TOKEN",
            },
        ),
        store.add(
            "buzz-git-production",
            "buzz-git",
            {"remote": "buzz", "ref": "refs/heads/main"},
        ),
        store.add(
            "buzz-production",
            "buzz",
            {"workflow_id": "workflow-example"},
        ),
        store.add(
            "render-production",
            "render",
            {"service_id": "srv-example", "token_env": "RENDER_API_KEY"},
        ),
        store.add(
            "heroku-production",
            "heroku",
            {
                "app": "example-app",
                "token_env": "HEROKU_API_KEY",
                "source_blob_url_env": "HEROKU_SOURCE_BLOB_URL",
            },
        ),
        store.add(
            "vercel-production",
            "vercel",
            {
                "project": "example-site",
                "repo_id": "1234",
                "team_id": "team-example",
                "token_env": "VERCEL_TOKEN",
            },
        ),
    ]
    monkeypatch.setenv("VERCEL_TOKEN", "hidden")

    public = {profile.name: profile.public_payload() for profile in profiles}

    assert public["github-production"]["credential_env"] == []
    assert public["github-actions-production"]["credential_env"] == [
        {
            "name": "GITHUB_ACTIONS_TOKEN",
            "present": False,
            "purpose": "runtime",
            "required": True,
        }
    ]
    assert public["buzz-git-production"]["action"] == "git.ref"
    assert public["buzz-git-production"]["credential_env"] == []
    assert public["buzz-production"]["credential_env"] == [
        {
            "name": "BUZZ_AUTH_TAG",
            "present": False,
            "purpose": "runtime",
            "required": False,
        },
        {
            "name": "BUZZ_PRIVATE_KEY",
            "present": False,
            "purpose": "runtime",
            "required": True,
        },
        {
            "name": "BUZZ_RELAY_URL",
            "present": False,
            "purpose": "runtime",
            "required": False,
        },
    ]
    assert public["vercel-production"]["credential_env"] == [
        {
            "name": "VERCEL_TOKEN",
            "present": True,
            "purpose": "runtime",
            "required": True,
        }
    ]
    assert "hidden" not in json.dumps(public)


@pytest.mark.parametrize(
    ("provider", "options", "expected_action"),
    [
        ("github", {"remote": "origin", "ref": "refs/heads/main"}, "git.ref"),
        (
            "github-actions",
            {
                "owner": "owner",
                "repo": "mobile-app",
                "repository_id": "1234",
                "workflow_id": "5678",
                "workflow_file": "release.yml",
                "ref": f"refs/tags/shipyard-candidate-{SHA}",
                "token_env": "GITHUB_ACTIONS_TOKEN",
            },
            "github.workflow",
        ),
        ("buzz", {"workflow_id": "workflow-example"}, "buzz.workflow"),
        (
            "render",
            {"service_id": "srv-example", "token_env": "RENDER_API_KEY"},
            "render.deploy",
        ),
        (
            "heroku",
            {
                "app": "example-app",
                "token_env": "HEROKU_API_KEY",
                "source_blob_url_env": "HEROKU_SOURCE_BLOB_URL",
            },
            "heroku.build",
        ),
        (
            "vercel",
            {
                "project": "example-site",
                "repo_id": "1234",
                "token_env": "VERCEL_TOKEN",
            },
            "vercel.deploy",
        ),
    ],
)
def test_connection_profile_renders_a_standalone_candidate_bound_schema_v2_playbook(
    tmp_path: Path,
    provider: str,
    options: dict[str, object],
    expected_action: str,
) -> None:
    profile = ConnectionProfile.create("production", provider, options)
    rendered = render_playbook(profile, target="production")
    output = tmp_path / f"{provider}.toml"
    output.write_text(rendered, encoding="utf-8")

    playbook = load_playbook(output)

    assert playbook.schema_version == 2
    assert playbook.provider == provider
    assert playbook.destination == profile.destination
    assert playbook.steps[0].action == expected_action
    assert f'connection_profile = "{profile.name}"' in rendered
    assert f'connection_digest = "{profile.digest}"' in rendered
    assert not any(
        value and value in rendered
        for name in profile.credential_env_names()
        if (value := os.environ.get(name))
    )


def test_connection_profile_rejects_invalid_names_refs_and_environment_references() -> None:
    with pytest.raises(ConnectionError, match="connection name"):
        ConnectionProfile.create("Production Team", "render", {})
    with pytest.raises(ConnectionError, match="canonical"):
        ConnectionProfile.create(
            "github-production", "github", {"remote": "origin", "ref": "main"}
        )
    with pytest.raises(ConnectionError, match="embedded credentials"):
        ConnectionProfile.create(
            "github-secret",
            "github",
            {
                "remote": "https://user:" + "password@example.invalid/repository.git",
                "ref": "refs/heads/main",
            },
        )
    with pytest.raises(ConnectionError, match="single-line"):
        ConnectionProfile.create(
            "buzz-production", "buzz", {"workflow_id": "workflow\nother"}
        )
    with pytest.raises(ConnectionError, match="environment variable"):
        ConnectionProfile.create(
            "render-production",
            "render",
            {"service_id": "srv-example", "token_env": "not valid"},
        )
    with pytest.raises(ConnectionError, match="provider identifier"):
        ConnectionProfile.create(
            "github-actions-production",
            "github-actions",
            {
                "owner": "owner",
                "repo": "mobile-app",
                "repository_id": "1234",
                "workflow_id": "5678",
                "workflow_file": "../release.yml",
                "ref": f"refs/tags/shipyard-candidate-{SHA}",
                "token_env": "GITHUB_ACTIONS_TOKEN",
            },
        )
    with pytest.raises(ConnectionError, match="immutable candidate tag"):
        ConnectionProfile.create(
            "github-actions-production",
            "github-actions",
            {
                "owner": "owner",
                "repo": "mobile-app",
                "repository_id": "1234",
                "workflow_id": "5678",
                "workflow_file": "release.yml",
                "ref": "refs/heads/release",
                "token_env": "GITHUB_ACTIONS_TOKEN",
            },
        )
    with pytest.raises(ConnectionError, match="must use a GITHUB_"):
        ConnectionProfile.create(
            "github-actions-production",
            "github-actions",
            {
                "owner": "owner",
                "repo": "mobile-app",
                "repository_id": "1234",
                "workflow_id": "5678",
                "workflow_file": "release.yml",
                "ref": f"refs/tags/shipyard-candidate-{SHA}",
                "token_env": "AWS_SECRET_ACCESS_KEY",
            },
        )


class _CheckAdapter:
    action = "render.deploy"

    def __init__(self) -> None:
        self.calls = 0

    def check(self, context):
        self.calls += 1
        return ConnectionCheck(
            "verified", context.provider, self.action, "srv-example", {"read_only": True}
        )


class _CheckRegistry:
    def __init__(self, adapter: _CheckAdapter) -> None:
        self.adapter = adapter

    def get(self, action: str):
        assert action == self.adapter.action
        return self.adapter


def test_connection_verification_is_offline_by_default_and_requires_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = ConnectionProfile.create(
        "render-production",
        "render",
        {"service_id": "srv-example", "token_env": "RENDER_API_KEY"},
    )
    adapter = _CheckAdapter()
    registry = _CheckRegistry(adapter)
    monkeypatch.delenv("RENDER_API_KEY", raising=False)

    blocked = verify_connection(profile, tmp_path, allow_network=False, registry=registry)
    assert blocked["status"] == "blocked"
    assert blocked["missing_credential_env"] == ["RENDER_API_KEY"]
    assert blocked["network_checked"] is False
    assert adapter.calls == 0

    monkeypatch.setenv("RENDER_API_KEY", "never-print-this")
    configured = verify_connection(profile, tmp_path, allow_network=False, registry=registry)
    assert configured["status"] == "configured"
    assert configured["network_checked"] is False
    assert adapter.calls == 0
    assert "never-print-this" not in json.dumps(configured)

    verified = verify_connection(profile, tmp_path, allow_network=True, registry=registry)
    assert verified["status"] == "verified"
    assert verified["network_checked"] is True
    assert verified["mutation_performed"] is False
    assert adapter.calls == 1


def test_connection_cli_adds_github_actions_profile_and_generates_playbook(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_dir = tmp_path / "config"
    output = tmp_path / "github-actions.toml"
    monkeypatch.setenv("GITHUB_ACTIONS_TOKEN", "cli-secret")

    assert (
        main(
            [
                "connection",
                "add",
                "apple-release",
                "--provider",
                "github-actions",
                "--owner",
                "owner",
                "--repo-name",
                "mobile-app",
                "--repository-id",
                "1234",
                "--workflow-id",
                "5678",
                "--workflow-file",
                "release.yml",
                "--ref",
                f"refs/tags/shipyard-candidate-{SHA}",
                "--token-env",
                "GITHUB_ACTIONS_TOKEN",
                "--config-dir",
                str(config_dir),
                "--json",
            ]
        )
        == 0
    )
    added = json_data(capsys.readouterr().out)
    assert added["connection"]["action"] == "github.workflow"
    assert added["connection"]["destination"] == (
        f"github-actions:1234:5678:refs/tags/shipyard-candidate-{SHA}"
    )
    assert "cli-secret" not in json.dumps(added)

    assert (
        main(
            [
                "connection",
                "playbook",
                "apple-release",
                "--output",
                str(output),
                "--config-dir",
                str(config_dir),
                "--json",
            ]
        )
        == 0
    )
    capsys.readouterr()
    playbook = load_playbook(output)
    assert playbook.steps[0].action == "github.workflow"
    assert playbook.steps[0].config["repository_id"] == "1234"
    assert playbook.steps[0].config["workflow_id"] == "5678"


def test_connection_cli_add_list_show_check_playbook_and_remove(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_dir = tmp_path / "config"
    monkeypatch.setenv("RENDER_API_KEY", "cli-secret")

    assert (
        main(
            [
                "connection",
                "add",
                "render-production",
                "--provider",
                "render",
                "--service-id",
                "srv-example",
                "--config-dir",
                str(config_dir),
                "--json",
            ]
        )
        == 0
    )
    added = json_data(capsys.readouterr().out)
    assert added["connection"]["name"] == "render-production"
    assert added["connection"]["credential_env"][0]["present"] is True
    assert "cli-secret" not in json.dumps(added)

    assert main(["connection", "list", "--config-dir", str(config_dir), "--json"]) == 0
    listed = json_data(capsys.readouterr().out)
    assert [row["name"] for row in listed["connections"]] == ["render-production"]

    assert (
        main(
            [
                "connection",
                "check",
                "render-production",
                "--repo",
                str(tmp_path),
                "--config-dir",
                str(config_dir),
                "--json",
            ]
        )
        == 0
    )
    checked = json_data(capsys.readouterr().out)
    assert checked["status"] == "configured"
    assert checked["network_checked"] is False

    playbook_path = tmp_path / "shipyard.toml"
    assert (
        main(
            [
                "connection",
                "playbook",
                "render-production",
                "--output",
                str(playbook_path),
                "--config-dir",
                str(config_dir),
                "--json",
            ]
        )
        == 0
    )
    generated = json_data(capsys.readouterr().out)
    assert generated["created"] == str(playbook_path.resolve())
    assert playbook_path.stat().st_mode & 0o777 == 0o600
    assert load_playbook(playbook_path).steps[0].config["service_id"] == "srv-example"

    victim = tmp_path / "victim.toml"
    victim.write_text("preserve-me", encoding="utf-8")
    linked_output = tmp_path / "linked.toml"
    linked_output.symlink_to(victim)
    assert (
        main(
            [
                "connection",
                "playbook",
                "render-production",
                "--output",
                str(linked_output),
                "--force",
                "--config-dir",
                str(config_dir),
            ]
        )
        == 2
    )
    assert "refusing symlink output" in capsys.readouterr().err
    assert victim.read_text(encoding="utf-8") == "preserve-me"

    assert (
        main(
            [
                "connection",
                "remove",
                "render-production",
                "--config-dir",
                str(config_dir),
                "--json",
            ]
        )
        == 0
    )
    removed = json_data(capsys.readouterr().out)
    assert removed == {"removed": "render-production"}
    assert ConnectionStore(config_dir).list() == ()
