from __future__ import annotations

import json
import sqlite3
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from shipyard.adapters.apple import XcodeCloudBuildAdapter
from shipyard.adapters.apple_testflight import (
    TestFlightGroupAdapter as AppleTestFlightGroupAdapter,
)
from shipyard.adapters.base import (
    AdapterContext,
    AdapterError,
    ConnectionCheck,
    MutationReceipt,
    ProviderReadback,
)
from shipyard.adapters.http import HttpResponse
from shipyard.adapters.kubernetes import KubernetesDeploymentAdapter
from shipyard.adapters.oci import OciPromotionAdapter
from shipyard.adapters.providers import (
    BuzzWorkflowAdapter,
    GitHubWorkflowAdapter,
    GitRefAdapter,
    HerokuBuildAdapter,
    RenderAdapter,
    VercelAdapter,
)
from shipyard.adapters.registry import AdapterRegistry
from shipyard.execution_snapshot import ExecutionSnapshotError
from shipyard.executor import ProvenanceDriftError, ReleaseExecutor
from shipyard.ledger import Ledger, LedgerError
from shipyard.playbook import PlaybookError, load_playbook

SHA = "a" * 40


@dataclass
class FakeHttp:
    responses: list[HttpResponse]
    requests: list[tuple[str, str, dict[str, str], dict[str, object] | None]] = field(
        default_factory=list
    )

    def request(self, method, url, *, headers, body=None):
        self.requests.append((method, url, headers, body))
        return self.responses.pop(0)


def context(provider: str, config: dict[str, object]) -> AdapterContext:
    return AdapterContext("run-1", SHA, provider, "production", config)


def test_registry_exposes_github_workflow_adapter():
    adapter = AdapterRegistry().get("github.workflow")
    assert isinstance(adapter, GitHubWorkflowAdapter)


def test_registry_exposes_typed_apple_adapters():
    registry = AdapterRegistry()

    assert isinstance(registry.get("xcodecloud.build"), XcodeCloudBuildAdapter)
    assert isinstance(
        registry.get("appstoreconnect.testflight"), AppleTestFlightGroupAdapter
    )


def test_registry_exposes_digest_native_oci_and_kubernetes_adapters():
    registry = AdapterRegistry()

    assert isinstance(registry.get("oci.promote"), OciPromotionAdapter)
    assert isinstance(registry.get("kubernetes.deploy"), KubernetesDeploymentAdapter)


def test_git_ref_adapter_connection_check_is_read_only(tmp_path):
    commands = []

    def runner(command, cwd, allowed_env):
        commands.append((command, cwd, allowed_env))
        return 0, f"{SHA}\trefs/heads/main\n"

    adapter = GitRefAdapter(runner=runner)
    result = adapter.check(
        context(
            "github",
            {"remote": "origin", "ref": "refs/heads/main", "repo_path": str(tmp_path)},
        )
    )

    assert result.status == "verified"
    assert result.identity == SHA
    assert commands == [
        (("git", "remote", "get-url", "--", "origin"), tmp_path, ()),
        (("git", "ls-remote", "origin", "refs/heads/main"), tmp_path, ()),
    ]


def test_git_ref_adapter_ignores_non_identity_remote_diagnostics(tmp_path):
    def runner(command, cwd, allowed_env):
        if command[1:4] == ("remote", "get-url", "--"):
            return 0, "ssh://git@example.test/repository.git\n"
        return 0, f"Warning: synthetic SSH diagnostic\n{SHA}\trefs/heads/main\n"

    result = GitRefAdapter(runner=runner).check(
        context(
            "github",
            {"remote": "origin", "ref": "refs/heads/main", "repo_path": str(tmp_path)},
        )
    )

    assert result.status == "verified"
    assert result.identity == SHA


def test_git_ref_adapter_rejects_credential_bearing_https_remote_before_network(
    tmp_path,
):
    calls = []

    def runner(command, cwd, allowed_env):
        calls.append(command)
        if command[1:4] == ("remote", "get-url", "--"):
            return 0, "https://" + "user:secret" + "@example.test/repository.git\n"
        if command[1] == "ls-remote":
            return 0, ""
        raise AssertionError(f"unexpected command: {command}")

    candidate_context = context(
        "github",
        {
            "remote": "origin",
            "ref": f"refs/tags/shipyard-candidate-{SHA}",
            "repo_path": str(tmp_path),
            "tag_kind": "annotated",
        },
    )

    with pytest.raises(AdapterError, match="credential-free"):
        GitRefAdapter(runner=runner).check(candidate_context)

    assert calls == [("git", "remote", "get-url", "--", "origin")]


@pytest.mark.parametrize(
    "remote_url",
    [
        "https://example.test/repository.git?access_token=secret",
        "https://example.test/repository.git#secret",
    ],
)
def test_git_ref_adapter_rejects_http_remote_query_or_fragment_before_network(
    tmp_path, remote_url
):
    calls = []

    def runner(command, cwd, allowed_env):
        calls.append(command)
        if command[1:4] == ("remote", "get-url", "--"):
            return 0, f"{remote_url}\n"
        if command[1] == "ls-remote":
            return 0, ""
        raise AssertionError(f"unexpected command: {command}")

    candidate_context = context(
        "github",
        {
            "remote": "origin",
            "ref": f"refs/tags/shipyard-candidate-{SHA}",
            "repo_path": str(tmp_path),
            "tag_kind": "annotated",
        },
    )

    with pytest.raises(AdapterError, match="credential-free"):
        GitRefAdapter(runner=runner).check(candidate_context)

    assert calls == [("git", "remote", "get-url", "--", "origin")]


def test_git_ref_adapter_allows_absent_destination_after_remote_verification(tmp_path):
    def runner(command, cwd, allowed_env):
        if command[1:4] == ("remote", "get-url", "--"):
            return 0, "ssh://git@example.test/repository.git\n"
        return 0, ""

    result = GitRefAdapter(runner=runner).check(
        context(
            "github",
            {"remote": "origin", "ref": "refs/heads/new", "repo_path": str(tmp_path)},
        )
    )

    assert result.status == "verified"
    assert result.identity == "refs/heads/new"
    assert result.evidence["ref_exists"] is False


def test_git_ref_adapter_check_rejects_missing_named_remote(tmp_path):
    commands = []

    def runner(command, cwd, allowed_env):
        commands.append(command)
        return 2, ""

    adapter = GitRefAdapter(runner=runner)
    with pytest.raises(AdapterError, match="configured named remote"):
        adapter.check(
            context(
                "github",
                {"remote": "origin", "ref": "refs/heads/main", "repo_path": str(tmp_path)},
            )
        )
    assert commands == [("git", "remote", "get-url", "--", "origin")]


def test_buzz_git_ref_isolates_helper_chain_and_forwards_only_nostr_auth(
    tmp_path, monkeypatch
):
    calls = []
    monkeypatch.setenv("NOSTR_PRIVATE_KEY", "synthetic-private-key")

    def runner(command, cwd, allowed_env):
        calls.append((command, allowed_env))
        if command == ("git", "remote", "get-url", "--all", "buzz"):
            return 0, "https://buzz.example.com/git/owner/repository.git\n"
        return 0, f"{SHA}\trefs/heads/main\n"

    result = GitRefAdapter(runner=runner).check(
        context(
            "buzz-git",
            {"remote": "buzz", "ref": "refs/heads/main", "repo_path": str(tmp_path)},
        )
    )

    assert result.status == "verified"
    assert calls == [
        (
            ("git", "remote", "get-url", "--all", "buzz"),
            (),
        ),
        (
            (
                "git",
                "-c",
                "credential.helper=",
                "-c",
                "credential.https://buzz.example.com.helper=",
                "-c",
                "credential.https://buzz.example.com.helper=nostr",
                "-c",
                "credential.https://buzz.example.com.useHttpPath=true",
                "ls-remote",
                "buzz",
                "refs/heads/main",
            ),
            ("NOSTR_PRIVATE_KEY", "BUZZ_AUTH_TAG"),
        ),
    ]


def test_buzz_git_ref_snapshots_keyfile_for_each_operation(tmp_path, monkeypatch):
    monkeypatch.delenv("NOSTR_PRIVATE_KEY", raising=False)
    keyfile = tmp_path / "nostr.key"
    keyfile.write_text("synthetic-private-key", encoding="utf-8")
    keyfile.chmod(0o600)
    observed_copy: Path | None = None

    def runner(command, cwd, allowed_env):
        nonlocal observed_copy
        if command == ("git", "remote", "get-url", "--all", "buzz"):
            return 0, "https://buzz.example.com/git/owner/repository.git\n"
        if command == ("git", "config", "--get", "nostr.keyfile"):
            return 0, f"{keyfile}\n"
        configured = next(
            value.removeprefix("nostr.keyfile=")
            for value in command
            if value.startswith("nostr.keyfile=")
        )
        observed_copy = Path(configured)
        assert observed_copy != keyfile
        assert observed_copy.read_text(encoding="utf-8") == "synthetic-private-key"
        assert observed_copy.stat().st_mode & 0o777 == 0o400
        return 0, f"{SHA}\trefs/heads/main\n"

    result = GitRefAdapter(runner=runner).check(
        context(
            "buzz-git",
            {"remote": "buzz", "ref": "refs/heads/main", "repo_path": str(tmp_path)},
        )
    )

    assert result.status == "verified"
    assert observed_copy is not None
    assert not observed_copy.exists()


def test_buzz_git_ref_canonicalizes_process_owned_temporary_alias(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("NOSTR_PRIVATE_KEY", raising=False)
    keyfile = tmp_path / "nostr.key"
    keyfile.write_text("synthetic-private-key", encoding="utf-8")
    keyfile.chmod(0o600)
    real_temporary = tmp_path / "private" / "temporary"
    real_temporary.mkdir(parents=True)
    alias = tmp_path / "temporary-alias"
    alias.symlink_to(real_temporary, target_is_directory=True)
    observed_copy: Path | None = None

    class AliasTemporaryDirectory:
        def __enter__(self):
            return str(alias)

        def __exit__(self, *_args):
            for child in real_temporary.iterdir():
                child.unlink()
            real_temporary.rmdir()
            alias.unlink()

    monkeypatch.setattr(
        "shipyard.adapters.providers.TemporaryDirectory",
        lambda **_kwargs: AliasTemporaryDirectory(),
    )

    def runner(command, cwd, allowed_env):
        nonlocal observed_copy
        if command == ("git", "remote", "get-url", "--all", "buzz"):
            return 0, "https://buzz.example.com/git/owner/repository.git\n"
        if command == ("git", "config", "--get", "nostr.keyfile"):
            return 0, f"{keyfile}\n"
        configured = next(
            value.removeprefix("nostr.keyfile=")
            for value in command
            if value.startswith("nostr.keyfile=")
        )
        observed_copy = Path(configured)
        assert observed_copy.parent == real_temporary
        assert observed_copy.read_text(encoding="utf-8") == "synthetic-private-key"
        return 0, f"{SHA}\trefs/heads/main\n"

    assert GitRefAdapter(runner=runner).check(
        context(
            "buzz-git",
            {"remote": "buzz", "ref": "refs/heads/main", "repo_path": str(tmp_path)},
        )
    ).status == "verified"
    assert observed_copy is not None
    assert not observed_copy.exists()


def test_github_workflow_connection_check_verifies_canonical_repository_and_workflow(
    monkeypatch,
):
    monkeypatch.setenv("GITHUB_ACTIONS_TOKEN", "synthetic-github-value")
    fake = FakeHttp(
        [
            HttpResponse(200, {"id": 1234, "full_name": "owner/mobile-app"}),
            HttpResponse(
                200,
                {
                    "id": 5678,
                    "path": ".github/workflows/release.yml",
                    "state": "active",
                },
            ),
        ]
    )
    adapter = GitHubWorkflowAdapter(transport=fake)

    result = adapter.check(
        context(
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
        )
    )

    assert result.status == "verified"
    assert result.identity == "1234:5678"
    assert [request[:2] for request in fake.requests] == [
        ("GET", "https://api.github.com/repos/owner/mobile-app"),
        ("GET", "https://api.github.com/repos/owner/mobile-app/actions/workflows/5678"),
    ]
    assert "synthetic-github-value" not in repr(result)


def test_github_workflow_dispatch_binds_exact_sha_and_reads_back_run_identity(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS_TOKEN", "synthetic-github-value")
    repository: dict[str, object] = {"id": 1234, "full_name": "owner/mobile-app"}
    workflow: dict[str, object] = {
        "id": 5678,
        "path": ".github/workflows/release.yml",
        "state": "active",
    }
    fake = FakeHttp(
        [
            HttpResponse(200, repository),
            HttpResponse(200, workflow),
            HttpResponse(200, {"sha": SHA}),
            HttpResponse(
                200,
                {
                    "workflow_run_id": 9001,
                    "run_url": "https://api.github.com/repos/owner/mobile-app/actions/runs/9001",
                    "html_url": "https://github.com/owner/mobile-app/actions/runs/9001",
                },
            ),
            HttpResponse(
                200,
                {
                    "id": 9001,
                    "workflow_id": 5678,
                    "head_sha": SHA,
                    "event": "workflow_dispatch",
                    "status": "completed",
                    "conclusion": "success",
                    "repository": repository,
                },
            ),
        ]
    )
    adapter = GitHubWorkflowAdapter(transport=fake)
    ctx = context(
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
    )

    receipt = adapter.execute(ctx)
    readback = adapter.readback(ctx, receipt)

    candidate_tag = f"shipyard-candidate-{SHA}"
    assert receipt.operation_id == "9001"
    assert fake.requests[2][:2] == (
        "GET",
        f"https://api.github.com/repos/owner/mobile-app/commits/{candidate_tag}",
    )
    assert fake.requests[3][0:2] == (
        "POST",
        "https://api.github.com/repos/owner/mobile-app/actions/workflows/5678/dispatches",
    )
    assert fake.requests[3][3] == {
        "ref": candidate_tag,
        "inputs": {
            "shipyard_candidate_sha": SHA,
            "shipyard_run_id": "run-1",
        },
        "return_run_details": True,
    }
    assert readback.status == "succeeded"
    assert readback.observed_sha == SHA


def test_github_workflow_readback_fails_immediately_when_pending_run_sha_drifted(
    monkeypatch,
):
    monkeypatch.setenv("GITHUB_ACTIONS_TOKEN", "synthetic-github-value")
    fake = FakeHttp(
        [
            HttpResponse(
                200,
                {
                    "id": 9001,
                    "workflow_id": 5678,
                    "head_sha": "b" * 40,
                    "event": "workflow_dispatch",
                    "repository": {"id": 1234},
                    "status": "queued",
                    "conclusion": None,
                },
            )
        ]
    )
    adapter = GitHubWorkflowAdapter(transport=fake)
    result = adapter.readback(
        context(
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
        MutationReceipt(
            "github-actions",
            "github.workflow",
            "9001",
            SHA,
            {},
        ),
    )

    assert result.status == "failed"
    assert result.observed_sha == "b" * 40


def test_github_workflow_rejects_mutable_branch_refs_before_provider_contact(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS_TOKEN", "synthetic-github-value")
    fake = FakeHttp([])
    adapter = GitHubWorkflowAdapter(transport=fake)

    with pytest.raises(AdapterError, match="immutable candidate tag"):
        adapter.execute(
            context(
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
        )

    assert fake.requests == []


def test_github_workflow_ref_must_resolve_to_approved_sha_before_dispatch(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS_TOKEN", "synthetic-github-value")
    fake = FakeHttp(
        [
            HttpResponse(200, {"id": 1234, "full_name": "owner/mobile-app"}),
            HttpResponse(
                200,
                {
                    "id": 5678,
                    "path": ".github/workflows/release.yml",
                    "state": "active",
                },
            ),
            HttpResponse(200, {"sha": "b" * 40}),
        ]
    )
    adapter = GitHubWorkflowAdapter(transport=fake)
    ctx = context(
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
    )

    with pytest.raises(AdapterError, match="approved source SHA"):
        adapter.execute(ctx)

    assert all(request[0] == "GET" for request in fake.requests)


def test_http_provider_connection_checks_use_get_and_never_mutate(monkeypatch):
    monkeypatch.setenv("RENDER_API_KEY", "render-secret")
    monkeypatch.setenv("HEROKU_API_KEY", "heroku-secret")
    monkeypatch.setenv("VERCEL_TOKEN", "vercel-secret")
    cases = [
        (
            RenderAdapter,
            "render",
            {"service_id": "srv-1", "token_env": "RENDER_API_KEY"},
            {"id": "srv-1", "name": "Example"},
            "https://api.render.com/v1/services/srv-1",
        ),
        (
            HerokuBuildAdapter,
            "heroku",
            {
                "app": "example-app",
                "token_env": "HEROKU_API_KEY",
                "source_blob_url_env": "HEROKU_SOURCE_BLOB_URL",
            },
            {"id": "app-1", "name": "example-app"},
            "https://api.heroku.com/apps/example-app",
        ),
        (
            VercelAdapter,
            "vercel",
            {
                "project": "example-site",
                "repo_id": "1234",
                "team_id": "team-1",
                "token_env": "VERCEL_TOKEN",
            },
            {"id": "prj-1", "name": "example-site", "accountId": "team-1"},
            "https://api.vercel.com/v9/projects/example-site?teamId=team-1",
        ),
    ]

    for adapter_type, provider, config, payload, expected_url in cases:
        fake = FakeHttp([HttpResponse(200, payload)])
        result = adapter_type(fake).check(context(provider, config))
        assert result.status == "verified"
        assert result.identity in {"srv-1", "app-1", "prj-1"}
        assert fake.requests == [("GET", expected_url, fake.requests[0][2], None)]
        assert all(
            secret not in repr(result)
            for secret in ("render-secret", "heroku-secret", "vercel-secret")
        )


def test_render_connection_check_rejects_mismatched_service_identity(monkeypatch):
    monkeypatch.setenv("RENDER_API_KEY", "synthetic-render-value")
    fake = FakeHttp([HttpResponse(200, {"id": "srv-other"})])
    adapter = RenderAdapter(transport=fake)

    with pytest.raises(AdapterError, match="different service id"):
        adapter.check(
            context(
                "render",
                {"service_id": "srv-expected", "token_env": "RENDER_API_KEY"},
            )
        )


def test_vercel_connection_check_rejects_mismatched_team_identity(monkeypatch):
    monkeypatch.setenv("VERCEL_TOKEN", "synthetic-vercel-value")
    fake = FakeHttp(
        [
            HttpResponse(
                200,
                {"id": "prj-1", "name": "example-site", "accountId": "team-other"},
            )
        ]
    )
    adapter = VercelAdapter(transport=fake)

    with pytest.raises(AdapterError, match="different team"):
        adapter.check(
            context(
                "vercel",
                {
                    "project": "example-site",
                    "repo_id": "1234",
                    "team_id": "team-expected",
                    "token_env": "VERCEL_TOKEN",
                },
            )
        )


def test_http_adapter_rejects_custom_api_base_before_transport() -> None:
    fake = FakeHttp([])
    adapter = RenderAdapter(transport=fake)
    context = AdapterContext(
        run_id="run-1",
        source_sha="a" * 40,
        provider="render",
        destination="render:service",
        config={
            "service_id": "srv-1",
            "token_env": "RENDER_API_KEY",
            "api_base": "https://metadata.internal.invalid",
        },
    )
    with pytest.raises(AdapterError, match="official provider API"):
        adapter.check(context)
    assert fake.requests == []


def test_buzz_connection_check_gets_workflow_without_triggering():
    calls = []

    def runner(command, cwd, allowed_env):
        calls.append((command, allowed_env))
        return 0, '{"id":"workflow-1"}'

    result = BuzzWorkflowAdapter(runner=runner).check(
        context("buzz", {"workflow_id": "workflow-1"})
    )

    assert result.status == "verified"
    assert result.identity == "workflow-1"
    assert "trigger" not in calls[0][0]
    assert calls[0][0][-4:] == ("workflows", "get", "--workflow", "workflow-1")


def test_git_ref_adapter_pushes_only_exact_sha_and_reads_back(tmp_path):
    commands = []

    def runner(command, cwd, allowed_env):
        commands.append((command, cwd, allowed_env))
        if command[1] == "ls-remote":
            return 0, f"{SHA}\trefs/heads/main\n"
        return 0, "ok"

    adapter = GitRefAdapter(runner=runner)
    ctx = context(
        "github",
        {"remote": "origin", "ref": "refs/heads/main", "repo_path": str(tmp_path)},
    )

    receipt = adapter.execute(ctx)
    readback = adapter.readback(ctx, receipt)

    assert commands[0][0] == (
        "git",
        "push",
        "--porcelain",
        "origin",
        f"{SHA}:refs/heads/main",
    )
    assert readback.status == "succeeded"
    assert readback.observed_sha == SHA


def test_git_ref_readback_rejects_mismatched_receipt_without_remote_access(tmp_path):
    commands = []

    def runner(command, cwd, allowed_env):
        commands.append((command, cwd, allowed_env))
        return 0, ""

    adapter = GitRefAdapter(runner=runner)
    adapter_context = context(
        "github",
        {"remote": "origin", "ref": "refs/heads/main", "repo_path": str(tmp_path)},
    )
    receipt = MutationReceipt("wrong", "git.ref", "git-invalid", SHA, {})

    result = adapter.readback(adapter_context, receipt)

    assert result.status == "failed"
    assert result.observed_sha is None
    assert commands == []


def test_git_ref_readback_rejects_unhashable_receipt_metadata_without_remote_access(
    tmp_path,
):
    commands = []

    def runner(command, cwd, allowed_env):
        commands.append((command, cwd, allowed_env))
        return 0, ""

    adapter = GitRefAdapter(runner=runner)
    adapter_context = context(
        "github",
        {"remote": "origin", "ref": "refs/heads/main", "repo_path": str(tmp_path)},
    )
    valid_receipt = adapter.execute(adapter_context)
    commands.clear()
    malformed = MutationReceipt(
        valid_receipt.provider,
        valid_receipt.action,
        valid_receipt.operation_id,
        valid_receipt.submitted_sha,
        {"remote": "origin", "ref": "refs/heads/main", "tag_kind": []},
    )

    result = adapter.readback(adapter_context, malformed)

    assert result.status == "failed"
    assert result.observed_sha is None
    assert commands == []


def test_git_ref_annotated_execute_rejects_remote_credential_race_before_clone(
    tmp_path,
):
    commands = []

    def runner(command, cwd, allowed_env):
        commands.append(command)
        if command[1:4] == ("remote", "get-url", "--"):
            return 0, "https://example.test/repository.git\n"
        if command[1] == "ls-remote":
            return 0, ""
        if command[1:4] == ("remote", "get-url", "--all"):
            return 0, "https://" + "user:secret" + "@example.test/repository.git\n"
        return 1, ""

    ctx = context(
        "github",
        {
            "remote": "origin",
            "ref": f"refs/tags/shipyard-candidate-{SHA}",
            "repo_path": str(tmp_path),
            "tag_kind": "annotated",
        },
    )

    with pytest.raises(AdapterError, match="credential-free"):
        GitRefAdapter(runner=runner).execute(ctx)

    assert not any(command[1] == "clone" for command in commands)
    assert not any(command[1] == "push" for command in commands)


def test_git_ref_adapter_pushes_annotated_candidate_tag_and_reads_back_peeled_sha(
    git_repo, tmp_path
):
    source_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=git_repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    subprocess.run(
        ["git", "remote", "add", "origin", str(remote)], cwd=git_repo, check=True
    )
    ref = f"refs/tags/shipyard-candidate-{source_sha}"
    ctx = AdapterContext(
        "run-1",
        source_sha,
        "github",
        "production",
        {
            "remote": "origin",
            "ref": ref,
            "repo_path": str(git_repo),
            "tag_kind": "annotated",
        },
    )
    adapter = GitRefAdapter()

    check = adapter.check(ctx)
    receipt = adapter.execute(ctx)
    readback = adapter.readback(ctx, receipt)
    remote_refs = subprocess.run(
        ["git", "ls-remote", "origin", ref, f"{ref}^{{}}"],
        cwd=git_repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout

    assert check.status == "verified"
    assert check.evidence["ref_exists"] is False
    assert receipt.evidence["tag_kind"] == "annotated"
    assert receipt.evidence["tag_object_sha"] != source_sha
    assert f"{receipt.evidence['tag_object_sha']}\t{ref}\n" in remote_refs
    assert f"{source_sha}\t{ref}^{{}}\n" in remote_refs
    assert readback.status == "succeeded"
    assert readback.observed_sha == source_sha
    assert readback.evidence["tag_object_sha"] == receipt.evidence["tag_object_sha"]
    assert not (git_repo / ".git" / "refs" / "tags" / ref.removeprefix("refs/tags/")).exists()


@pytest.mark.parametrize("ref", ["refs/heads/main", "refs/tags/release"])
def test_git_ref_adapter_rejects_annotated_mode_outside_exact_candidate_tag(
    tmp_path, ref
):
    adapter = GitRefAdapter(runner=lambda *_args: (0, ""))
    ctx = context(
        "github",
        {
            "remote": "origin",
            "ref": ref,
            "repo_path": str(tmp_path),
            "tag_kind": "annotated",
        },
    )

    with pytest.raises(AdapterError, match="annotated candidate tag"):
        adapter.check(ctx)


@pytest.mark.parametrize("bad_ref", ["main", "refs/heads/main..evil", "refs/heads/main/"])
def test_git_ref_adapter_rejects_noncanonical_refs(tmp_path, bad_ref):
    adapter = GitRefAdapter(runner=lambda *_args: (0, ""))
    ctx = context(
        "buzz",
        {"remote": "buzz", "ref": bad_ref, "repo_path": str(tmp_path)},
    )
    with pytest.raises(AdapterError, match="canonical"):
        adapter.execute(ctx)


def test_render_adapter_binds_deploy_and_readback_to_sha(monkeypatch):
    monkeypatch.setenv("RENDER_API_KEY", "super-secret")
    fake = FakeHttp(
        [
            HttpResponse(201, {"id": "dep-1"}),
            HttpResponse(200, {"id": "dep-1", "status": "live", "commit": {"id": SHA}}),
        ]
    )
    adapter = RenderAdapter(fake)
    ctx = context("render", {"service_id": "srv-1", "token_env": "RENDER_API_KEY"})

    receipt = adapter.execute(ctx)
    readback = adapter.readback(ctx, receipt)

    assert fake.requests[0][3]["commitId"] == SHA
    assert readback.status == "succeeded"
    assert "super-secret" not in repr(receipt)
    assert "super-secret" not in repr(readback)


def test_render_does_not_claim_success_for_wrong_live_commit(monkeypatch):
    monkeypatch.setenv("RENDER_API_KEY", "secret")
    fake = FakeHttp(
        [
            HttpResponse(201, {"id": "dep-1"}),
            HttpResponse(
                200, {"id": "dep-1", "status": "live", "commit": {"id": "b" * 40}}
            ),
        ]
    )
    adapter = RenderAdapter(fake)
    ctx = context("render", {"service_id": "srv-1", "token_env": "RENDER_API_KEY"})
    receipt = adapter.execute(ctx)
    assert adapter.readback(ctx, receipt).status != "succeeded"


def test_vercel_adapter_requires_ready_exact_git_source(monkeypatch):
    monkeypatch.setenv("VERCEL_TOKEN", "secret")
    fake = FakeHttp(
        [
            HttpResponse(200, {"id": "dpl-1"}),
            HttpResponse(200, {"id": "dpl-1", "readyState": "READY", "gitSource": {"sha": SHA}}),
        ]
    )
    adapter = VercelAdapter(fake)
    ctx = context(
        "vercel",
        {"project": "site", "repo_id": 123, "token_env": "VERCEL_TOKEN"},
    )
    receipt = adapter.execute(ctx)
    readback = adapter.readback(ctx, receipt)
    assert fake.requests[0][3]["gitSource"]["sha"] == SHA
    assert readback.status == "succeeded"


def test_heroku_source_blob_url_is_used_but_never_retained(monkeypatch):
    monkeypatch.setenv("HEROKU_API_KEY", "api-secret")
    monkeypatch.setenv("HEROKU_SOURCE_BLOB_URL", "https://signed.invalid/blob?token=secret")
    fake = FakeHttp(
        [
            HttpResponse(201, {"id": "build-1"}),
            HttpResponse(
                200,
                {
                    "id": "build-1",
                    "status": "succeeded",
                    "source_blob": {"version": SHA},
                },
            ),
        ]
    )
    adapter = HerokuBuildAdapter(fake)
    ctx = context(
        "heroku",
        {
            "app": "my-app",
            "token_env": "HEROKU_API_KEY",
            "source_blob_url_env": "HEROKU_SOURCE_BLOB_URL",
        },
    )
    receipt = adapter.execute(ctx)
    readback = adapter.readback(ctx, receipt)
    assert readback.status == "succeeded"
    assert "signed.invalid" not in repr(receipt)
    assert "api-secret" not in repr(receipt)


def test_buzz_workflow_adapter_binds_trigger_and_readback_to_sha():
    calls = []

    def runner(command, cwd, allowed_env):
        calls.append((command, allowed_env))
        if "trigger" in command:
            return 0, '{"id":"buzz-run-1"}'
        return 0, (
            '{"runs":[{"id":"buzz-run-1","status":"succeeded",'
            f'"inputs":{{"shipyard_candidate_sha":"{SHA}"}}}}]}}'
        )

    adapter = BuzzWorkflowAdapter(runner=runner)
    ctx = context("buzz", {"workflow_id": "workflow-1"})
    receipt = adapter.execute(ctx)
    readback = adapter.readback(ctx, receipt)

    assert readback.status == "succeeded"
    assert readback.observed_sha == SHA
    assert "BUZZ_PRIVATE_KEY" in calls[0][1]


def typed_playbook(tmp_path: Path) -> Path:
    path = tmp_path / "typed.toml"
    path.write_text(
        '''schema_version = 2
name = "typed-render"
target = "production"
provider = "render"
destination = "owner/service/production"

[[steps]]
id = "deploy"
name = "Deploy"
effect = "external"
action = "render.deploy"

[steps.config]
service_id = "srv-1"
token_env = "RENDER_API_KEY"
''',
        encoding="utf-8",
    )
    return path


def test_executor_overwrites_playbook_repo_path_with_governed_run_repository(
    git_repo, tmp_path
):
    playbook_path = typed_playbook(tmp_path)
    playbook_path.write_text(
        playbook_path.read_text(encoding="utf-8") + 'repo_path = "/attacker/path"\n',
        encoding="utf-8",
    )
    ledger = Ledger(tmp_path / "state")
    executor = ReleaseExecutor(ledger)
    prepared = executor.start(git_repo, load_playbook(playbook_path))

    adapter_context = executor._adapter_context(prepared, prepared.steps[0])

    assert adapter_context.config["repo_path"] == str(git_repo.resolve())


class SequenceAdapter:
    action = "render.deploy"

    def __init__(self):
        self.readbacks = ["pending", "succeeded"]

    def check(self, context: AdapterContext) -> ConnectionCheck:
        return ConnectionCheck(
            "verified", "render", self.action, "srv-1", {"read_only": True}
        )

    def execute(self, context: AdapterContext) -> MutationReceipt:
        return MutationReceipt(
            "render",
            self.action,
            "dep-1",
            context.source_sha,
            {"service_id": "srv-1"},
        )

    def readback(
        self, context: AdapterContext, receipt: MutationReceipt
    ) -> ProviderReadback:
        status = self.readbacks.pop(0)
        return ProviderReadback(
            status,
            receipt.operation_id,
            context.source_sha if status == "succeeded" else None,
            {"provider_status": "live" if status == "succeeded" else "build"},
        )


class RejectingCheckAdapter(SequenceAdapter):
    def __init__(self):
        super().__init__()
        self.execute_calls = 0

    def check(self, context: AdapterContext) -> ConnectionCheck:
        raise AdapterError("synthetic read-only identity failure")

    def execute(self, context: AdapterContext) -> MutationReceipt:
        self.execute_calls += 1
        return super().execute(context)


def test_external_adapter_check_failure_never_crosses_mutation_boundary(
    git_repo, tmp_path
):
    ledger = Ledger(tmp_path / "state")
    adapter = RejectingCheckAdapter()
    executor = ReleaseExecutor(ledger, AdapterRegistry([adapter]))
    prepared = executor.start(git_repo, load_playbook(typed_playbook(tmp_path)))

    failed = executor.resume(
        prepared.run_id,
        execute_external=True,
        confirm_sha=prepared.source_sha,
        approve_candidate=prepared.candidate_digest,
        approval_actor="pytest-reviewer",
        approval_reason="preflight boundary regression",
    )

    event_types = [
        event["event_type"] for event in ledger.list_audit_events(prepared.run_id)
    ]
    assert failed.status == "failed"
    assert failed.steps[0].status == "failed"
    assert failed.steps[0].attempts == 1
    assert adapter.execute_calls == 0
    assert ledger.get_adapter_receipt(prepared.run_id, 0) is None
    assert "adapter.check_failed" in event_types
    assert "adapter.mutation_started" not in event_types
    assert "adapter.uncertain" not in event_types


class BrokenCheckAdapter(SequenceAdapter):
    def __init__(self, failure_mode: str):
        super().__init__()
        self.failure_mode = failure_mode
        self.execute_calls = 0

    def check(self, context: AdapterContext) -> ConnectionCheck:
        if self.failure_mode == "exception":
            raise RuntimeError("synthetic unexpected preflight failure")
        return object()  # type: ignore[return-value]

    def execute(self, context: AdapterContext) -> MutationReceipt:
        self.execute_calls += 1
        return super().execute(context)


@pytest.mark.parametrize("failure_mode", ["exception", "malformed"])
def test_external_adapter_unexpected_check_failure_is_terminal_before_mutation(
    git_repo, tmp_path, failure_mode
):
    ledger = Ledger(tmp_path / "state")
    adapter = BrokenCheckAdapter(failure_mode)
    executor = ReleaseExecutor(ledger, AdapterRegistry([adapter]))
    prepared = executor.start(git_repo, load_playbook(typed_playbook(tmp_path)))

    failed = executor.resume(
        prepared.run_id,
        execute_external=True,
        confirm_sha=prepared.source_sha,
        approve_candidate=prepared.candidate_digest,
        approval_actor="pytest-reviewer",
        approval_reason="unexpected preflight boundary regression",
    )

    event_types = [
        event["event_type"] for event in ledger.list_audit_events(prepared.run_id)
    ]
    assert failed.status == "failed"
    assert failed.steps[0].status == "failed"
    assert adapter.execute_calls == 0
    assert ledger.get_adapter_receipt(prepared.run_id, 0) is None
    assert "adapter.check_failed" in event_types
    assert "adapter.mutation_started" not in event_types
    assert "adapter.uncertain" not in event_types


class SnapshotProbeAdapter(SequenceAdapter):
    def __init__(self, original_repo: Path):
        super().__init__()
        self.readbacks = ["succeeded"]
        self.original_repo = original_repo
        self.execution_repo: Path | None = None
        self.observed_artifact: bytes | None = None
        self.artifact_mode: int | None = None
        self.config_mode: int | None = None

    def check(self, context: AdapterContext) -> ConnectionCheck:
        return ConnectionCheck(
            "verified",
            "render",
            self.action,
            "srv-1",
            {"source": context.source_sha},
        )

    def execute(self, context: AdapterContext) -> MutationReceipt:
        (self.original_repo / "release.bin").write_bytes(b"tampered-after-authorization")
        configured = context.config["repo_path"]
        assert isinstance(configured, str)
        self.execution_repo = Path(configured)
        self.observed_artifact = (self.execution_repo / "release.bin").read_bytes()
        self.artifact_mode = (self.execution_repo / "release.bin").stat().st_mode & 0o777
        self.config_mode = (
            self.execution_repo / ".git" / "config"
        ).stat().st_mode & 0o777
        return super().execute(context)


def test_external_adapter_executes_from_approved_immutable_snapshot(git_repo, tmp_path):
    artifact = git_repo / "release.bin"
    artifact.write_bytes(b"approved-artifact")
    subprocess.run(["git", "add", "release.bin"], cwd=git_repo, check=True)
    subprocess.run(
        ["git", "commit", "-m", "add release artifact"], cwd=git_repo, check=True
    )
    playbook_path = typed_playbook(tmp_path)
    playbook_path.write_text(
        playbook_path.read_text(encoding="utf-8")
        + '\n[[artifacts]]\npath = "release.bin"\nrequired = true\n',
        encoding="utf-8",
    )
    ledger = Ledger(tmp_path / "state")
    adapter = SnapshotProbeAdapter(git_repo)
    executor = ReleaseExecutor(
        ledger, AdapterRegistry([adapter])  # type: ignore[list-item]
    )
    prepared = executor.start(git_repo, load_playbook(playbook_path))

    completed = executor.resume(
        prepared.run_id,
        execute_external=True,
        confirm_sha=prepared.source_sha,
        approve_candidate=prepared.candidate_digest,
        approval_actor="pytest-reviewer",
        approval_reason="snapshot boundary regression",
    )

    assert completed.status == "succeeded"
    assert adapter.execution_repo is not None
    assert adapter.execution_repo != git_repo.resolve()
    assert adapter.execution_repo.is_relative_to(ledger.state_dir / "snapshots")
    assert adapter.observed_artifact == b"approved-artifact"
    assert adapter.artifact_mode == 0o400
    assert adapter.config_mode == 0o400
    assert not adapter.execution_repo.exists()
    assert artifact.read_bytes() == b"tampered-after-authorization"


def test_successful_run_audits_snapshot_cleanup_oserror(
    git_repo, tmp_path, monkeypatch
):
    artifact = git_repo / "release.bin"
    artifact.write_bytes(b"approved-artifact")
    subprocess.run(["git", "add", "release.bin"], cwd=git_repo, check=True)
    subprocess.run(
        ["git", "commit", "-m", "add release artifact"], cwd=git_repo, check=True
    )
    playbook_path = typed_playbook(tmp_path)
    playbook_path.write_text(
        playbook_path.read_text(encoding="utf-8")
        + '\n[[artifacts]]\npath = "release.bin"\nrequired = true\n',
        encoding="utf-8",
    )
    ledger = Ledger(tmp_path / "state")
    adapter = SnapshotProbeAdapter(git_repo)
    executor = ReleaseExecutor(
        ledger, AdapterRegistry([adapter])  # type: ignore[list-item]
    )
    prepared = executor.start(git_repo, load_playbook(playbook_path))

    def fail_cleanup(_state_dir: Path, _run_id: str) -> None:
        raise OSError("synthetic cleanup failure")

    monkeypatch.setattr("shipyard.executor.cleanup_execution_snapshot", fail_cleanup)
    completed = executor.resume(
        prepared.run_id,
        execute_external=True,
        confirm_sha=prepared.source_sha,
        approve_candidate=prepared.candidate_digest,
        approval_actor="pytest-reviewer",
        approval_reason="cleanup error regression",
    )

    assert completed.status == "succeeded"
    assert ledger.verify_audit_chain(prepared.run_id)
    assert ledger.list_audit_events(prepared.run_id)[-1]["event_type"] == "snapshot.cleanup_failed"


def test_freeze_failure_removes_snapshot_created_by_current_attempt(
    git_repo, tmp_path, monkeypatch
):
    ledger = Ledger(tmp_path / "state")
    executor = ReleaseExecutor(
        ledger,
        AdapterRegistry([SnapshotProbeAdapter(git_repo)]),  # type: ignore[list-item]
    )
    prepared = executor.start(git_repo, load_playbook(typed_playbook(tmp_path)))

    def fail_freeze(_snapshot: Path) -> None:
        raise ExecutionSnapshotError("synthetic freeze failure")

    monkeypatch.setattr("shipyard.executor.freeze_execution_snapshot", fail_freeze)
    with pytest.raises(ProvenanceDriftError, match="synthetic freeze failure"):
        executor.resume(
            prepared.run_id,
            execute_external=True,
            confirm_sha=prepared.source_sha,
            approve_candidate=prepared.candidate_digest,
            approval_actor="pytest-reviewer",
            approval_reason="freeze cleanup regression",
        )

    assert not (ledger.state_dir / "snapshots" / prepared.run_id).exists()


def test_external_adapter_rejects_remote_drift_after_candidate_approval(
    git_repo, tmp_path
):
    original = tmp_path / "original.git"
    subprocess.run(["git", "init", "--bare", str(original)], check=True)
    subprocess.run(
        ["git", "remote", "add", "origin", str(original)],
        cwd=git_repo,
        check=True,
    )
    ledger = Ledger(tmp_path / "state")
    executor = ReleaseExecutor(
        ledger,
        AdapterRegistry([SnapshotProbeAdapter(git_repo)]),  # type: ignore[list-item]
    )
    prepared = executor.start(git_repo, load_playbook(typed_playbook(tmp_path)))
    replacement = tmp_path / "replacement.git"
    subprocess.run(["git", "init", "--bare", str(replacement)], check=True)
    subprocess.run(
        ["git", "remote", "set-url", "origin", str(replacement)],
        cwd=git_repo,
        check=True,
    )

    with pytest.raises(ProvenanceDriftError, match="remote changed"):
        executor.resume(
            prepared.run_id,
            execute_external=True,
            confirm_sha=prepared.source_sha,
            approve_candidate=prepared.candidate_digest,
            approval_actor="pytest-reviewer",
            approval_reason="remote drift regression",
        )


def test_external_adapter_rejects_preexisting_unmanifested_snapshot(git_repo, tmp_path):
    ledger = Ledger(tmp_path / "state")
    executor = ReleaseExecutor(
        ledger,
        AdapterRegistry([SnapshotProbeAdapter(git_repo)]),  # type: ignore[list-item]
    )
    prepared = executor.start(git_repo, load_playbook(typed_playbook(tmp_path)))
    leftover = ledger.state_dir / "snapshots" / prepared.run_id
    leftover.mkdir(parents=True, mode=0o700)

    with pytest.raises(ProvenanceDriftError, match="not frozen"):
        executor.resume(
            prepared.run_id,
            execute_external=True,
            confirm_sha=prepared.source_sha,
            approve_candidate=prepared.candidate_digest,
            approval_actor="pytest-reviewer",
            approval_reason="leftover snapshot regression",
        )

    assert leftover.exists()


class ReceiptAuditFailureAdapter(SequenceAdapter):
    def __init__(self, ledger: Ledger):
        super().__init__()
        self.ledger = ledger
        self.readbacks = ["succeeded"]

    def execute(self, context: AdapterContext) -> MutationReceipt:
        receipt = super().execute(context)
        with sqlite3.connect(self.ledger.database_path) as connection:
            connection.execute(
                """
                CREATE TRIGGER reject_adapter_receipt_audit
                BEFORE INSERT ON audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'injected receipt audit failure');
                END;
                """
            )
        return receipt


def test_receipt_audit_failure_preserves_recoverable_provider_identity(
    git_repo, tmp_path
):
    ledger = Ledger(tmp_path / "state")
    adapter = ReceiptAuditFailureAdapter(ledger)
    executor = ReleaseExecutor(ledger, AdapterRegistry([adapter]))
    prepared = executor.start(git_repo, load_playbook(typed_playbook(tmp_path)))

    with pytest.raises(LedgerError, match="receipt is durable"):
        executor.resume(
            prepared.run_id,
            execute_external=True,
            confirm_sha=prepared.source_sha,
            approve_candidate=prepared.candidate_digest,
            approval_actor="pytest",
            approval_reason="contract test",
        )

    receipt = ledger.get_adapter_receipt(prepared.run_id, 0)
    assert receipt is not None
    assert receipt.operation_id == "dep-1"
    with sqlite3.connect(ledger.database_path) as connection:
        connection.execute("DROP TRIGGER reject_adapter_receipt_audit")

    uncertain = ledger.get_run(prepared.run_id)
    assert uncertain.status == "uncertain"
    assert uncertain.steps[0].operation_id == "dep-1"
    snapshot = ledger.state_dir / "snapshots" / prepared.run_id
    assert snapshot.exists()
    resolved = executor.resolve(prepared.run_id)
    assert resolved.status == "succeeded"
    assert not snapshot.exists()
    event_types = [
        event["event_type"] for event in ledger.list_audit_events(prepared.run_id)
    ]
    assert event_types.count("adapter.receipt") == 1
    assert event_types.count("adapter.readback") == 1
    assert ledger.verify_audit_chain(prepared.run_id) is True


def test_process_loss_after_receipt_commit_repairs_audit_before_readback(
    git_repo, tmp_path
):
    ledger = Ledger(tmp_path / "state")
    adapter = SequenceAdapter()
    adapter.readbacks = ["succeeded"]
    executor = ReleaseExecutor(ledger, AdapterRegistry([adapter]))
    prepared = executor.start(git_repo, load_playbook(typed_playbook(tmp_path)))
    ledger.begin_step(prepared.run_id, 0)
    ledger.append_audit_event(
        prepared.run_id,
        "adapter.mutation_started",
        {
            "ordinal": 0,
            "action": adapter.action,
            "candidate_digest": prepared.candidate_digest,
            "source_sha": prepared.source_sha,
        },
    )
    receipt = adapter.execute(
        executor._adapter_context(
            ledger.get_run(prepared.run_id), prepared.steps[0]
        )
    )
    with sqlite3.connect(ledger.database_path) as connection:
        connection.execute(
            """
            CREATE TRIGGER reject_adapter_receipt_audit
            BEFORE INSERT ON audit_events
            BEGIN
                SELECT RAISE(ABORT, 'injected receipt audit failure');
            END;
            """
        )
    with pytest.raises(LedgerError, match="receipt is durable"):
        ledger.record_adapter_receipt(prepared.run_id, 0, receipt)
    with sqlite3.connect(ledger.database_path) as connection:
        connection.execute("DROP TRIGGER reject_adapter_receipt_audit")

    recovered = executor.recover_stale(prepared.run_id)

    assert recovered.status == "uncertain"
    assert recovered.steps[0].operation_id == "dep-1"
    event_types = [
        event["event_type"] for event in ledger.list_audit_events(prepared.run_id)
    ]
    assert event_types.count("adapter.receipt") == 1
    assert event_types.count("attempt.recovered_stale") == 1
    assert executor.resolve(prepared.run_id).status == "succeeded"


def test_typed_adapter_run_quarantines_pending_then_resolves_read_only(
    git_repo, tmp_path
):
    ledger = Ledger(tmp_path / "state")
    adapter = SequenceAdapter()
    adapter.readbacks = ["pending", "succeeded", "succeeded"]
    executor = ReleaseExecutor(ledger, AdapterRegistry([adapter]))
    prepared = executor.start(git_repo, load_playbook(typed_playbook(tmp_path)))

    uncertain = executor.resume(
        prepared.run_id,
        execute_external=True,
        confirm_sha=prepared.source_sha,
        approve_candidate=prepared.candidate_digest,
        approval_actor="pytest",
        approval_reason="contract test",
    )
    assert uncertain.status == "uncertain"
    assert uncertain.steps[0].operation_id == "dep-1"

    events_before = ledger.list_audit_events(prepared.run_id)
    observed = executor.readback_once(prepared.run_id)
    still_uncertain = ledger.get_run(prepared.run_id)

    assert observed.status == "succeeded"
    assert observed.observed_sha == prepared.source_sha
    assert still_uncertain.status == "uncertain"
    assert still_uncertain.steps[0].provider_status == "pending"
    assert ledger.list_audit_events(prepared.run_id) == events_before

    resolved = executor.resolve(prepared.run_id)
    assert resolved.status == "succeeded"
    assert resolved.steps[0].provider_status == "succeeded"
    events = ledger.list_audit_events(prepared.run_id)
    assert {event["event_type"] for event in events} >= {
        "run.created",
        "candidate.prepared",
        "candidate.approved",
        "adapter.mutation_started",
        "adapter.receipt",
        "adapter.readback",
    }
    assert all(
        events[index]["previous_hash"] == events[index - 1]["event_hash"]
        for index in range(1, len(events))
    )


def test_github_workflow_run_persists_exact_provider_receipt_and_readback(
    git_repo, tmp_path, monkeypatch
):
    source_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=git_repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    repository: dict[str, object] = {"id": 1234, "full_name": "owner/mobile-app"}
    workflow: dict[str, object] = {
        "id": 5678,
        "path": ".github/workflows/release.yml",
        "state": "active",
    }
    fake = FakeHttp(
        [
            HttpResponse(200, repository),
            HttpResponse(200, workflow),
            HttpResponse(200, repository),
            HttpResponse(200, workflow),
            HttpResponse(200, {"sha": source_sha}),
            HttpResponse(200, {"workflow_run_id": 9001}),
            HttpResponse(
                200,
                {
                    "id": 9001,
                    "workflow_id": 5678,
                    "head_sha": source_sha,
                    "event": "workflow_dispatch",
                    "status": "completed",
                    "conclusion": "success",
                    "repository": repository,
                },
            ),
        ]
    )
    monkeypatch.setenv("GITHUB_ACTIONS_TOKEN", "synthetic-github-value")
    playbook_path = tmp_path / "github-workflow.toml"
    playbook_path.write_text(
        '''schema_version = 2
name = "github-workflow"
target = "production"
provider = "github-actions"
destination = "github-actions:1234:5678:refs/tags/shipyard-candidate-{source_sha}"

[[steps]]
id = "release"
name = "Run release workflow"
effect = "external"
action = "github.workflow"

[steps.config]
owner = "owner"
repo = "mobile-app"
repository_id = "1234"
workflow_id = "5678"
workflow_file = "release.yml"
ref = "refs/tags/shipyard-candidate-{source_sha}"
token_env = "GITHUB_ACTIONS_TOKEN"
''',
        encoding="utf-8",
    )
    ledger = Ledger(tmp_path / "github-state")
    executor = ReleaseExecutor(
        ledger, AdapterRegistry([GitHubWorkflowAdapter(transport=fake)])
    )
    prepared = executor.start(git_repo, load_playbook(playbook_path))

    completed = executor.resume(
        prepared.run_id,
        execute_external=True,
        confirm_sha=prepared.source_sha,
        approve_candidate=prepared.candidate_digest,
        approval_actor="pytest",
        approval_reason="exact GitHub workflow contract",
    )

    assert completed.status == "succeeded"
    assert completed.steps[0].operation_id == "9001"
    assert completed.steps[0].readback is not None
    assert completed.steps[0].readback["observed_sha"] == source_sha
    assert completed.steps[0].provider_status == "succeeded"
    manifest = (ledger.runs_dir / f"{prepared.run_id}.json").read_text(encoding="utf-8")
    assert "synthetic-github-value" not in manifest
    assert json.loads(manifest)["steps"][0]["operation_id"] == "9001"


def test_schema_v2_rejects_raw_external_commands(tmp_path):
    path = tmp_path / "unsafe.toml"
    path.write_text(
        '''schema_version = 2
name = "unsafe"
target = "production"
provider = "render"
destination = "service"

[[steps]]
id = "deploy"
name = "Deploy"
effect = "external"
command = ["render", "deploy"]
''',
        encoding="utf-8",
    )
    with pytest.raises(PlaybookError, match="typed adapter"):
        load_playbook(path)


def test_adapter_config_rejects_embedded_credentials(tmp_path):
    path = typed_playbook(tmp_path)
    text = path.read_text(encoding="utf-8").replace(
        'token_env = "RENDER_API_KEY"', 'token = "do-not-store-me"'
    )
    path.write_text(text, encoding="utf-8")
    with pytest.raises(PlaybookError, match="must name an ._env"):
        load_playbook(path)


def test_git_remote_identity_change_invalidates_approved_candidate(git_repo, tmp_path):
    subprocess.run(
        ["git", "remote", "add", "origin", "https://github.com/example/one.git"],
        cwd=git_repo,
        check=True,
    )
    playbook = tmp_path / "github.toml"
    playbook.write_text(
        '''schema_version = 2
name = "github"
target = "production"
provider = "github"
destination = "example/one:refs/heads/main"

[[steps]]
id = "push"
name = "Push"
effect = "external"
action = "git.ref"

[steps.config]
remote = "origin"
ref = "refs/heads/main"
''',
        encoding="utf-8",
    )
    executor = ReleaseExecutor(Ledger(tmp_path / "state"))
    prepared = executor.start(git_repo, load_playbook(playbook))
    subprocess.run(
        ["git", "remote", "set-url", "origin", "https://github.com/example/two.git"],
        cwd=git_repo,
        check=True,
    )

    with pytest.raises(ProvenanceDriftError, match="release candidate changed"):
        executor.resume(
            prepared.run_id,
            execute_external=True,
            confirm_sha=prepared.source_sha,
            approve_candidate=prepared.candidate_digest,
            approval_actor="pytest",
            approval_reason="remote drift test",
        )
