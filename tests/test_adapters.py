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
    MutationReceipt,
    ProviderReadback,
)
from shipyard.adapters.http import HttpResponse
from shipyard.adapters.providers import (
    BuzzWorkflowAdapter,
    GitHubWorkflowAdapter,
    GitRefAdapter,
    HerokuBuildAdapter,
    RenderAdapter,
    VercelAdapter,
)
from shipyard.adapters.registry import AdapterRegistry
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


class SequenceAdapter:
    action = "render.deploy"

    def __init__(self):
        self.readbacks = ["pending", "succeeded"]

    def execute(self, adapter_context):
        return MutationReceipt(
            "render",
            self.action,
            "dep-1",
            adapter_context.source_sha,
            {"service_id": "srv-1"},
        )

    def readback(self, adapter_context, receipt):
        status = self.readbacks.pop(0)
        return ProviderReadback(
            status,
            receipt.operation_id,
            adapter_context.source_sha if status == "succeeded" else None,
            {"provider_status": "live" if status == "succeeded" else "build"},
        )


class ReceiptAuditFailureAdapter(SequenceAdapter):
    def __init__(self, ledger: Ledger):
        super().__init__()
        self.ledger = ledger
        self.readbacks = ["succeeded"]

    def execute(self, adapter_context):
        receipt = super().execute(adapter_context)
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
    resolved = executor.resolve(prepared.run_id)
    assert resolved.status == "succeeded"
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
