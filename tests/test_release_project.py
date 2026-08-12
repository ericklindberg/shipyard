from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from shipyard.adapters.base import ProviderReadback
from shipyard.observations import (
    ObservationError,
    ObservationStore,
    ReleaseObservation,
)
from shipyard.release_project import (
    ReleaseProjectError,
    load_release_project,
    render_project_template,
)

SHA = "a" * 40


def _project(path: Path) -> Path:
    path.write_text(
        '''schema_version = 1
name = "example-ios-release"
source_remote = "https://github.com/example/example.git"

[github]
owner = "example"
repo = "example"
repository_id = "1234"
required_workflow_ids = ["101", "102"]
token_env = "GITHUB_ACTIONS_TOKEN"

[apple]
workflow_id = "workflow-1"
source_remote = "https://github.com/example/example.git"
source_git_remote = "origin"
bundle_id = "com.example.app"
beta_group_name = "Testing"
expected_marketing_version = "1.1"
issuer_id_env = "APPLE_ISSUER_ID"
key_id_env = "APPLE_KEY_ID"
private_key_path_env = "APPLE_PRIVATE_KEY_PATH"

[[gates]]
name = "physical-device"
required_for = ["external", "production"]
''',
        encoding="utf-8",
    )
    path.chmod(0o644)
    return path


def test_release_project_loads_stable_nonsecret_coordinates(tmp_path) -> None:
    project = load_release_project(_project(tmp_path / "shipyard.release.toml"))

    assert project.name == "example-ios-release"
    assert project.github is not None
    assert project.github.required_workflow_ids == ("101", "102")
    assert project.apple is not None
    assert project.apple.source_remote == "https://github.com/example/example.git"
    assert project.apple.source_git_remote == "origin"
    assert project.apple.beta_group_name == "Testing"
    assert project.apple.credential_config == {
        "issuer_id_env": "APPLE_ISSUER_ID",
        "key_id_env": "APPLE_KEY_ID",
        "private_key_path_env": "APPLE_PRIVATE_KEY_PATH",
    }
    assert project.gate_names() == ("physical-device",)
    assert project.digest
    assert "PRIVATE KEY" not in json.dumps(project.public_payload())
    with pytest.raises(TypeError):
        project.apple.credential_config["token_env"] = "APPLE_OTHER_TOKEN"  # type: ignore[index]
    assert project.required_gate_names("internal") == ()
    assert project.required_gate_names("external") == ("physical-device",)


def test_release_project_rejects_literal_credential_option(tmp_path) -> None:
    path = _project(tmp_path / "shipyard.release.toml")
    content = path.read_text(encoding="utf-8").replace(
        'private_key_path_env = "APPLE_PRIVATE_KEY_PATH"',
        'private_key_path_env = "APPLE_PRIVATE_KEY_PATH"\nprivate_key = "secret"',
    )
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ReleaseProjectError, match="unsupported apple option: private_key"):
        load_release_project(path)


def test_release_project_template_round_trips(tmp_path) -> None:
    path = tmp_path / "shipyard.release.toml"
    path.write_text(render_project_template(), encoding="utf-8")
    path.chmod(0o644)

    project = load_release_project(path)

    assert project.github is not None
    assert project.apple is not None
    assert "physical-device" in project.gate_names()


def test_apple_release_project_requires_external_physical_device_policy(tmp_path) -> None:
    path = _project(tmp_path / "shipyard.release.toml")
    content = path.read_text(encoding="utf-8").replace(
        '\n[[gates]]\nname = "physical-device"\nrequired_for = ["external", "production"]\n',
        "\n",
    )
    path.write_text(content, encoding="utf-8")
    path.chmod(0o644)

    with pytest.raises(ReleaseProjectError, match="physical-device"):
        load_release_project(path)


def test_observation_store_persists_immutable_private_exact_sha_record(tmp_path) -> None:
    observation = ReleaseObservation.create(
        "github",
        "b" * 64,
        SHA,
        ProviderReadback(
            "succeeded",
            "github-checks:" + SHA,
            SHA,
            {"required": 2, "succeeded": 2, "read_only": True},
        ),
        observed_at="2026-08-12T12:00:00Z",
    )
    store = ObservationStore(tmp_path / "state")

    first = store.save(observation)
    second = store.save(observation)
    loaded = store.load(first)

    assert first == second
    assert loaded.payload() == observation.payload()
    assert stat.S_IMODE(first.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "state" / "observations").stat().st_mode) == 0o700
    assert first.name == observation.digest + ".json"


def test_observation_store_detects_content_tamper(tmp_path) -> None:
    observation = ReleaseObservation.create(
        "apple",
        "b" * 64,
        SHA,
        ProviderReadback("pending", "run-609", SHA, {"read_only": True}),
        observed_at="2026-08-12T12:00:00Z",
    )
    store = ObservationStore(tmp_path / "state")
    path = store.save(observation)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["status"] = "succeeded"
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(ObservationError, match="digest"):
        store.load(path)


def test_observation_rejects_provider_sha_mismatch() -> None:
    with pytest.raises(ObservationError, match="does not match"):
        ReleaseObservation.create(
            "github",
            "b" * 64,
            SHA,
            ProviderReadback("succeeded", "checks", "c" * 40, {}),
        )


def test_observation_store_rejects_path_outside_state_root(tmp_path) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    outside.chmod(0o600)

    with pytest.raises(ObservationError, match="outside state root"):
        ObservationStore(tmp_path / "state").load(outside)


def test_observation_list_is_bounded_filtered_and_does_not_create_missing_state(
    tmp_path,
) -> None:
    state = tmp_path / "state"
    store = ObservationStore(state)

    assert store.list() == ()
    assert not state.exists()

    older = ReleaseObservation.create(
        "github",
        "b" * 64,
        SHA,
        ProviderReadback("pending", "github-checks", SHA, {"read_only": True}),
        observed_at="2026-08-12T12:00:00Z",
    )
    newer = ReleaseObservation.create(
        "apple",
        "b" * 64,
        SHA,
        ProviderReadback("succeeded", "run-609", SHA, {"read_only": True}),
        observed_at="2026-08-12T12:01:00Z",
    )
    store.save(older)
    store.save(newer)

    assert [item.provider for item in store.list()] == ["apple", "github"]
    assert store.list(provider="github") == (store.load(older.path or store.save(older)),)
    assert store.list(project_digest="c" * 64) == ()


def test_observation_list_rejects_unsafe_nested_state_entry(tmp_path) -> None:
    store = ObservationStore(tmp_path / "state")
    root = store._ensure_root()
    (root / "unexpected").write_text("unsafe", encoding="utf-8")

    with pytest.raises(ObservationError, match="invalid project entry"):
        store.list()


def test_observation_store_rejects_nested_project_symlink_without_outside_write(
    tmp_path,
) -> None:
    observation = ReleaseObservation.create(
        "github",
        "b" * 64,
        SHA,
        ProviderReadback("pending", "github-checks", SHA, {"read_only": True}),
        observed_at="2026-08-12T12:00:00Z",
    )
    store = ObservationStore(tmp_path / "state")
    root = store._ensure_root()
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    (root / observation.project_digest).symlink_to(outside, target_is_directory=True)

    with pytest.raises(ObservationError, match="persist release observation"):
        store.save(observation)
    with pytest.raises(ObservationError, match="unsafe project entry"):
        store.list()

    assert list(outside.iterdir()) == []
