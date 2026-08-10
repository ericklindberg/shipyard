from __future__ import annotations

from pathlib import Path

import pytest

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
