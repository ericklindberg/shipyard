from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from shipyard import playbook as playbook_module
from shipyard.playbook import PlaybookError, load_playbook


def write_playbook(path: Path, steps: str, *, allow_dirty: bool = False) -> None:
    path.write_text(
        f'''schema_version = 1
name = "test-release"
target = "local"
allow_dirty = {str(allow_dirty).lower()}

{steps}
''',
        encoding="utf-8",
    )


def test_external_command_classifier_remains_a_bounded_orchestrator():
    source = inspect.getsource(playbook_module._is_external_command)
    function = ast.parse(source).body[0]

    assert isinstance(function, ast.FunctionDef)
    assert function.end_lineno is not None
    assert function.end_lineno <= 40


def test_playbook_loader_remains_a_bounded_orchestrator():
    source = inspect.getsource(playbook_module.load_playbook)
    function = ast.parse(source).body[0]

    assert isinstance(function, ast.FunctionDef)
    assert function.end_lineno is not None
    assert function.end_lineno <= 40


def test_typed_git_ref_rejects_credential_bearing_or_direct_remote_urls(tmp_path):
    path = tmp_path / "shipyard.toml"
    path.write_text(
        '''schema_version = 2
name = "unsafe-git"
target = "production"
provider = "github"
destination = "production"

[[steps]]
id = "push"
name = "Push"
effect = "external"
action = "git.ref"

[steps.config]
remote = "https://CREDENTIALSexample.invalid/repository.git"
ref = "refs/heads/main"
'''.replace("CREDENTIALS", "user:secret@"),
        encoding="utf-8",
    )

    with pytest.raises(PlaybookError, match="named Git remote"):
        load_playbook(path)


def test_typed_http_action_rejects_cross_provider_credential_reference(tmp_path):
    path = tmp_path / "shipyard.toml"
    path.write_text(
        '''schema_version = 2
name = "unsafe-render"
target = "production"
provider = "render"
destination = "render:srv-example"

[[steps]]
id = "deploy"
name = "Deploy"
effect = "external"
action = "render.deploy"

[steps.config]
service_id = "srv-example"
token_env = "AWS_SECRET_ACCESS_KEY"
''',
        encoding="utf-8",
    )

    with pytest.raises(PlaybookError, match="must use a RENDER_"):
        load_playbook(path)


@pytest.mark.parametrize(
    ("action", "config"),
    [
        (
            "xcodecloud.build",
            '''workflow_id = "workflow-1"
git_reference_id = "gitref-1"
git_reference_name = "refs/tags/shipyard-candidate-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
source_remote = "origin"
token_env = "APPLE_ASC_TOKEN"
clean = true''',
        ),
        (
            "appstoreconnect.testflight",
            '''app_id = "app-1"
build_id = "build-1"
beta_group_id = "group-1"
pre_release_version_id = "version-1"
xcode_cloud_run_id = "run-1"
bundle_id = "com.example.app"
marketing_version = "2.1"
build_number = "42"
token_env = "APPLE_ASC_TOKEN"''',
        ),
    ],
)
def test_typed_apple_actions_are_public_playbook_actions(tmp_path, action, config):
    path = tmp_path / "shipyard.toml"
    path.write_text(
        f'''schema_version = 2
name = "apple-release"
target = "testflight"
provider = "apple"
destination = "apple-destination"

[[steps]]
id = "apple"
name = "Apple adoption"
effect = "external"
action = "{action}"

[steps.config]
{config}
''',
        encoding="utf-8",
    )

    assert load_playbook(path).steps[0].action == action


def test_typed_apple_action_rejects_cross_provider_credential_reference(tmp_path):
    path = tmp_path / "shipyard.toml"
    path.write_text(
        '''schema_version = 2
name = "unsafe-apple"
target = "testflight"
provider = "apple"
destination = "workflow-1:gitref-1"

[[steps]]
id = "build"
name = "Build"
effect = "external"
action = "xcodecloud.build"

[steps.config]
workflow_id = "workflow-1"
git_reference_id = "gitref-1"
git_reference_name = "refs/tags/shipyard-candidate-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
source_remote = "origin"
token_env = "GITHUB_TOKEN"
''',
        encoding="utf-8",
    )

    with pytest.raises(PlaybookError, match="must use a APPLE_"):
        load_playbook(path)


def test_xcode_cloud_action_requires_pre_mutation_source_binding_config(tmp_path):
    path = tmp_path / "xcode-missing-source.toml"
    path.write_text(
        '''schema_version = 2
name = "xcode-missing-source"
target = "production"
provider = "apple"
destination = "workflow-1:gitref-1"

[[steps]]
id = "build"
name = "Build"
effect = "external"
action = "xcodecloud.build"

[steps.config]
workflow_id = "workflow-1"
git_reference_id = "gitref-1"
token_env = "APPLE_ASC_TOKEN"
''',
        encoding="utf-8",
    )

    with pytest.raises(PlaybookError, match="git_reference_name.*source_remote"):
        load_playbook(path)


def test_playbook_approval_quorum_defaults_to_one_and_accepts_bounded_integer(tmp_path):
    default_path = tmp_path / "default.toml"
    write_playbook(
        default_path,
        '''[[steps]]
id = "tests"
name = "Tests"
effect = "verify"
command = ["python3", "--version"]
''',
    )
    quorum_path = tmp_path / "quorum.toml"
    quorum_path.write_text(
        '''schema_version = 2
name = "quorum"
target = "production"
provider = "github"
destination = "repository:refs/heads/main"
approval_quorum = 2

[[steps]]
id = "publish"
name = "Publish"
effect = "external"
action = "git.ref"

[steps.config]
remote = "origin"
ref = "refs/heads/main"
''',
        encoding="utf-8",
    )

    assert load_playbook(default_path).approval_quorum == 1
    assert load_playbook(quorum_path).approval_quorum == 2


@pytest.mark.parametrize("value", ["true", "0", "11", '"2"'])
def test_playbook_rejects_invalid_approval_quorum(tmp_path, value):
    path = tmp_path / "invalid-quorum.toml"
    path.write_text(
        f'''schema_version = 1
name = "invalid-quorum"
target = "local"
approval_quorum = {value}

[[steps]]
id = "tests"
name = "Tests"
effect = "verify"
command = ["python3", "--version"]
''',
        encoding="utf-8",
    )

    with pytest.raises(PlaybookError, match="approval_quorum"):
        load_playbook(path)


def test_load_playbook_preserves_argv_without_a_shell(tmp_path):
    path = tmp_path / "shipyard.toml"
    write_playbook(
        path,
        '''[[steps]]
id = "tests"
name = "Run tests"
effect = "verify"
command = ["python3", "--version"]
timeout_seconds = 20
''',
    )

    playbook = load_playbook(path)

    assert playbook.name == "test-release"
    assert playbook.steps[0].command == ("python3", "--version")
    assert playbook.steps[0].timeout_seconds == 20


def test_duplicate_step_ids_fail_closed(tmp_path):
    path = tmp_path / "shipyard.toml"
    write_playbook(
        path,
        '''[[steps]]
id = "same"
name = "One"
effect = "verify"
command = ["python3", "-V"]

[[steps]]
id = "same"
name = "Two"
effect = "verify"
command = ["git", "status"]
''',
    )

    with pytest.raises(PlaybookError, match="duplicate step id"):
        load_playbook(path)


@pytest.mark.parametrize(
    "command",
    [
        '["git", "push", "origin", "HEAD:main"]',
        '["eas", "update", "--branch", "production"]',
        '["systemctl", "restart", "hermes-gateway"]',
        '["curl", "-X", "POST", "https://example.test/deploy"]',
        '["npx", "eas", "update", "--branch", "production"]',
        '["gh", "workflow", "run", "release.yml"]',
        '["gh", "api", "--method", "POST", "/repos/example/releases"]',
        '["env", "CI=1", "git", "push", "origin", "HEAD:main"]',
        '["bash", "-lc", "git push origin HEAD:main"]',
        '["curl", "--data", "release=1", "https://example.test/deploy"]',
        '["npx", "--yes", "eas", "update", "--branch", "production"]',
        '["gh", "api", "-f", "state=active", "/repos/example/deployments"]',
        '["sudo", "git", "push", "origin", "HEAD:main"]',
        '["git", "-C", "/tmp", "push", "origin", "HEAD:main"]',
        '["gh", "repo", "delete", "owner/repo", "--yes"]',
        '["curl", "-XDELETE", "https://example.test/release"]',
        '["curl", "--request=PATCH", "https://example.test/release"]',
        '["curl", "-dpayload", "https://example.test/release"]',
        '["eas", "branch:delete", "production"]',
        '["eas", "credentials"]',
        '["systemctl", "daemon-reload"]',
        '["docker", "run", "image"]',
        '["docker", "system", "prune", "-f"]',
        '["npm", "unpublish", "package"]',
        '["cargo", "yank", "--vers", "1.0.0"]',
        '["gh", "api", "--method=POST", "/repos/example/releases"]',
        '["gh", "pr", "--repo", "owner/repo", "create"]',
        '["git", "-c", "alias.verify=!touch /tmp/unsafe", "verify"]',
        '["python3", "-c", "print(1)"]',
        '["git", "--config-env=alias.verify=ALIAS", "verify"]',
        '["npx", "--package", "eas-cli", "eas", "update", "--branch", "production"]',
        '["git", "verify"]',
    ],
)
def test_known_external_commands_cannot_be_mislabeled_as_verification(tmp_path, command):
    path = tmp_path / "shipyard.toml"
    write_playbook(
        path,
        f'''[[steps]]
id = "unsafe"
name = "Unsafe"
effect = "verify"
command = {command}
''',
    )

    with pytest.raises(PlaybookError, match="must be marked external"):
        load_playbook(path)


@pytest.mark.parametrize(
    "command",
    [
        '["kubectl", "get", "pods"]',
        '["kubectl", "describe", "pod/example"]',
        '["kubectl", "diff", "-f", "deployment.yml"]',
        '["helm", "get", "manifest", "example"]',
        '["helm", "list"]',
    ],
)
def test_cluster_clis_remain_default_deny_without_an_explicit_policy(
    tmp_path, command
):
    path = tmp_path / "shipyard.toml"
    write_playbook(
        path,
        f'''[[steps]]
id = "cluster"
name = "Cluster read"
effect = "verify"
command = {command}
''',
    )

    with pytest.raises(PlaybookError, match="must be marked external"):
        load_playbook(path)


def test_env_split_string_is_rejected_at_every_effect_boundary(tmp_path):
    for effect in ("verify", "build", "external"):
        for option in (
            "-S",
            "-Sgit push origin HEAD:main",
            "-vS",
            "--split-string",
            "--split-string=git push origin HEAD:main",
        ):
            command = (
                '["env", "' + option + '", "git push origin HEAD:main"]'
                if "=" not in option
                else '["env", "' + option + '"]'
            )
            path = tmp_path / f"{effect}-{option.replace('/', '_')}.toml"
            write_playbook(
                path,
                f'''[[steps]]
id = "unsafe"
name = "Unsafe"
effect = "{effect}"
command = {command}
''',
            )

            with pytest.raises(PlaybookError, match="env split-string is not supported"):
                load_playbook(path)


def test_literal_secret_arguments_are_rejected(tmp_path):
    path = tmp_path / "shipyard.toml"
    write_playbook(
        path,
        '''[[steps]]
id = "leaky"
name = "Leaky"
effect = "external"
command = ["deploy", "--token", "do-not-store-me"]
''',
    )

    with pytest.raises(PlaybookError, match="secret values may not appear"):
        load_playbook(path)


def test_external_git_push_requires_exact_sha_placeholder(tmp_path):
    path = tmp_path / "shipyard.toml"
    write_playbook(
        path,
        '''[[steps]]
id = "push"
name = "Push"
effect = "external"
command = ["git", "push", "origin", "HEAD:refs/heads/main"]
''',
    )

    with pytest.raises(PlaybookError, match="must use the exact .sha. placeholder"):
        load_playbook(path)

    write_playbook(
        path,
        '''[[steps]]
id = "push"
name = "Push"
effect = "external"
command = ["git", "-C", "/tmp", "push", "origin", "HEAD:refs/heads/main"]
''',
    )

    with pytest.raises(PlaybookError, match="must use the exact .sha. placeholder"):
        load_playbook(path)

    write_playbook(
        path,
        '''[[steps]]
id = "push"
name = "Push"
effect = "external"
command = ["env", "CI=1", "git", "push", "origin", "HEAD:refs/heads/main"]
''',
    )

    with pytest.raises(PlaybookError, match="must use the exact .sha. placeholder"):
        load_playbook(path)

    write_playbook(
        path,
        '''[[steps]]
id = "push"
name = "Push"
effect = "external"
command = ["git", "push", "origin", "HEAD:refs/heads/main", "--push-option={sha}"]
''',
    )

    with pytest.raises(PlaybookError, match="must use the exact .sha. placeholder"):
        load_playbook(path)


def test_external_playbooks_cannot_allow_dirty_sources(tmp_path):
    path = tmp_path / "shipyard.toml"
    write_playbook(
        path,
        '''[[steps]]
id = "release"
name = "Release"
effect = "external"
command = ["git", "push", "origin", "{sha}:refs/heads/main"]
''',
        allow_dirty=True,
    )

    with pytest.raises(PlaybookError, match="external steps require a clean source"):
        load_playbook(path)


@pytest.mark.parametrize(
    "command",
    [
        '["env", "--chdir", "/tmp", "git", "push", "origin", "HEAD:main"]',
        '["env", "-C", "/tmp", "git", "push", "origin", "HEAD:main"]',
        '["env", "--unset", "CI", "git", "push", "origin", "HEAD:main"]',
        '["timeout", "30", "git", "push", "origin", "HEAD:main"]',
        '["nohup", "git", "push", "origin", "HEAD:main"]',
        '["nice", "git", "push", "origin", "HEAD:main"]',
        '["stdbuf", "-oL", "git", "push", "origin", "HEAD:main"]',
        '["setsid", "git", "push", "origin", "HEAD:main"]',
        '["gh", "workflow", "--repo", "owner/repo", "run", "release.yml"]',
        '["gh", "run", "--repo", "owner/repo", "cancel", "123"]',
        '["curl", "--data-urlencode", "release=1", "https://example.test"]',
        '["curl", "--form-string", "release=1", "https://example.test"]',
        '["curl", "-X", "PURGE", "https://example.test/cache"]',
        '["docker", "build", "--output", "type=registry", "."]',
        '["service", "nginx", "restart", "status"]',
        '["aws", "s3", "rm", "s3://bucket/key"]',
        '["vercel", "--prod"]',
    ],
)
def test_production_policy_fails_closed_for_mutating_wrappers_and_unknown_tools(
    tmp_path, command
):
    path = tmp_path / "shipyard.toml"
    write_playbook(
        path,
        f'''[[steps]]
id = "unsafe"
name = "Unsafe"
effect = "verify"
command = {command}
''',
    )

    with pytest.raises(PlaybookError, match="must be marked external"):
        load_playbook(path)


@pytest.mark.parametrize(
    "command",
    [
        '["git", "push", "--push-option", "{sha}", "origin", "HEAD:refs/heads/main"]',
        '["git", "push", "origin", "{sha}:refs/heads/main", "HEAD:refs/heads/other"]',
        '["git", "push", "--all", "origin", "{sha}:refs/heads/main"]',
        '["git", "push", "origin", "{sha}"]',
    ],
)
def test_git_push_requires_one_structural_exact_sha_refspec(tmp_path, command):
    path = tmp_path / "shipyard.toml"
    write_playbook(
        path,
        f'''[[steps]]
id = "push"
name = "Push"
effect = "external"
command = {command}
''',
    )

    with pytest.raises(PlaybookError, match="must use the exact"):
        load_playbook(path)


@pytest.mark.parametrize(
    "command",
    [
        '["curl", "--user", "operator:plaintext-password", "https://example.test"]',
        '["curl", "-u", "operator:plaintext-password", "https://example.test"]',
        '["curl", "--oauth2-bearer", "plaintext-token", "https://example.test"]',
    ],
)
def test_additional_credential_arguments_are_rejected(tmp_path, command):
    path = tmp_path / "shipyard.toml"
    write_playbook(
        path,
        f'''[[steps]]
id = "leaky"
name = "Leaky"
effect = "external"
command = {command}
''',
    )

    with pytest.raises(PlaybookError, match="secret values may not appear"):
        load_playbook(path)
