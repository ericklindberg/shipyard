from __future__ import annotations

import json
from pathlib import Path

import pytest

from shipyard.adapters.apple import XcodeCloudRunDiscovery, XcodeCloudSourceDiscovery
from shipyard.adapters.base import AdapterContext, AdapterError
from shipyard.adapters.http import HttpResponse
from shipyard.adapters.providers import GitHubWorkflowRunDiscovery
from shipyard.playbook import PlaybookError, load_playbook

SHA = "a" * 40


class FakeTransport:
    def __init__(self, responses: list[HttpResponse]):
        self.responses = iter(responses)
        self.calls: list[dict[str, object]] = []

    def request(self, method, url, *, headers, body=None):
        self.calls.append({"method": method, "url": url, "headers": headers, "body": body})
        return next(self.responses)


def _write_playbook(path: Path, *, provider: str, action: str, config: str) -> Path:
    path.write_text(
        f'''schema_version = 2
name = "standalone-contract"
target = "production"
provider = "{provider}"
destination = "destination"

[[steps]]
id = "provider"
name = "Provider action"
effect = "external"
action = "{action}"

[steps.config]
{config}
''',
        encoding="utf-8",
    )
    return path


def test_playbook_rejects_provider_action_mismatch_before_run(tmp_path: Path) -> None:
    playbook = _write_playbook(
        tmp_path / "invalid.toml",
        provider="buzz",
        action="git.ref",
        config='remote = "buzz"\nref = "refs/heads/main"\ntag_kind = "annotated"',
    )

    with pytest.raises(
        PlaybookError,
        match="annotated git.ref is supported only by provider github",
    ):
        load_playbook(playbook)


def test_playbook_rejects_annotated_tag_for_buzz_git_before_run(tmp_path: Path) -> None:
    playbook = _write_playbook(
        tmp_path / "invalid-buzz-annotated.toml",
        provider="buzz-git",
        action="git.ref",
        config=(
            'remote = "buzz"\n'
            f'ref = "refs/tags/shipyard-candidate-{SHA}"\n'
            'tag_kind = "annotated"'
        ),
    )

    with pytest.raises(
        PlaybookError,
        match="annotated git.ref is supported only by provider github",
    ):
        load_playbook(playbook)


def test_playbook_rejects_unknown_action_option_before_run(tmp_path: Path) -> None:
    playbook = _write_playbook(
        tmp_path / "invalid-option.toml",
        provider="buzz-git",
        action="git.ref",
        config='remote = "buzz"\nref = "refs/heads/main"\nworkflow_id = "wrong-layer"',
    )

    with pytest.raises(PlaybookError, match="unsupported config option for git.ref: workflow_id"):
        load_playbook(playbook)


def test_xcode_discovery_lists_and_locally_filters_exact_sha_without_post(monkeypatch) -> None:
    monkeypatch.setenv("APPLE_ASC_TOKEN", "secret-token")
    first = HttpResponse(
        200,
        {
            "data": [
                {
                    "type": "ciBuildRuns",
                    "id": "wrong-source",
                    "attributes": {
                        "number": 608,
                        "executionProgress": "COMPLETE",
                        "completionStatus": "SUCCEEDED",
                        "sourceCommit": {"commitSha": "b" * 40},
                    },
                }
            ],
            "links": {
                "next": "https://api.appstoreconnect.apple.com/v1/ciWorkflows/workflow-1/buildRuns?cursor=next"
            },
        },
    )
    second = HttpResponse(
        200,
        {
            "data": [
                {
                    "type": "ciBuildRuns",
                    "id": "exact-run",
                    "attributes": {
                        "number": 609,
                        "executionProgress": "COMPLETE",
                        "completionStatus": "SUCCEEDED",
                        "sourceCommit": {"commitSha": SHA},
                    },
                }
            ],
            "links": {"next": None},
        },
    )
    transport = FakeTransport([first, second])
    context = AdapterContext(
        run_id="discovery",
        source_sha=SHA,
        provider="apple",
        destination="workflow-1",
        config={"workflow_id": "workflow-1", "token_env": "APPLE_ASC_TOKEN"},
    )

    result = XcodeCloudRunDiscovery(transport).discover(context)

    assert result.operation_id == "exact-run"
    assert result.observed_sha == SHA
    assert result.status == "succeeded"
    assert result.evidence["build_number"] == "609"
    assert result.evidence["pages"] == 2
    assert [call["method"] for call in transport.calls] == ["GET", "GET"]
    assert all(call["body"] is None for call in transport.calls)
    assert "filter[" not in str(transport.calls[0]["url"])
    assert "secret-token" not in json.dumps(result.evidence)


def test_xcode_discovery_fails_closed_on_ambiguous_exact_sha(monkeypatch) -> None:
    monkeypatch.setenv("APPLE_ASC_TOKEN", "secret-token")
    response = HttpResponse(
        200,
        {
            "data": [
                {
                    "type": "ciBuildRuns",
                    "id": run_id,
                    "attributes": {
                        "number": number,
                        "executionProgress": "COMPLETE",
                        "completionStatus": "SUCCEEDED",
                        "sourceCommit": {"commitSha": SHA},
                    },
                }
                for run_id, number in (("run-1", 609), ("run-2", 610))
            ]
        },
    )
    context = AdapterContext(
        "discovery",
        SHA,
        "apple",
        "workflow-1",
        {"workflow_id": "workflow-1", "token_env": "APPLE_ASC_TOKEN"},
    )

    with pytest.raises(AdapterError, match="exactly one Xcode Cloud run"):
        XcodeCloudRunDiscovery(FakeTransport([response])).discover(context)


def test_xcode_discovery_reports_absent_without_triggering(monkeypatch) -> None:
    monkeypatch.setenv("APPLE_ASC_TOKEN", "secret-token")
    transport = FakeTransport([HttpResponse(200, {"data": [], "links": {"next": None}})])
    context = AdapterContext(
        "discovery",
        SHA,
        "apple",
        "workflow-1",
        {"workflow_id": "workflow-1", "token_env": "APPLE_ASC_TOKEN"},
    )

    result = XcodeCloudRunDiscovery(transport).discover(context)

    assert result.status == "unknown"
    assert result.evidence["state"] == "absent"
    assert result.evidence["matches"] == 0
    assert [call["method"] for call in transport.calls] == ["GET"]


def _source_discovery_responses(
    *,
    canonical_name: str = f"refs/tags/shipyard-candidate-{SHA}",
    kind: str = "TAG",
    deleted: bool = False,
    repository_id: str = "repo-1",
) -> list[HttpResponse]:
    return [
        HttpResponse(
            200,
            {
                "data": {
                    "type": "ciWorkflows",
                    "id": "workflow-1",
                    "relationships": {
                        "repository": {
                            "data": {"type": "scmRepositories", "id": repository_id}
                        }
                    },
                }
            },
        ),
        HttpResponse(
            200,
            {
                "data": {
                    "type": "scmRepositories",
                    "id": repository_id,
                    "attributes": {
                        "ownerName": "example",
                        "repositoryName": "app",
                        "httpCloneUrl": "https://github.com/example/app.git",
                        "sshCloneUrl": "git@github.com:example/app.git",
                    },
                }
            },
        ),
        HttpResponse(
            200,
            {
                "data": [
                    {
                        "type": "scmGitReferences",
                        "id": "reference-1",
                        "attributes": {
                            "name": canonical_name.removeprefix("refs/tags/"),
                            "canonicalName": canonical_name,
                            "isDeleted": deleted,
                            "kind": kind,
                        },
                        "relationships": {
                            "repository": {
                                "data": {"type": "scmRepositories", "id": repository_id}
                            }
                        },
                    }
                ],
                "links": {"next": None},
            },
        ),
    ]


def test_xcode_source_discovery_resolves_exact_candidate_reference_get_only(
    monkeypatch,
) -> None:
    monkeypatch.setenv("APPLE_ASC_TOKEN", "secret-token")
    transport = FakeTransport(_source_discovery_responses())

    result = XcodeCloudSourceDiscovery(transport).discover(
        workflow_id="workflow-1",
        source_sha=SHA,
        config={"token_env": "APPLE_ASC_TOKEN"},
    )

    assert result.repository_id == "repo-1"
    assert result.git_reference_id == "reference-1"
    assert result.git_reference_name == f"refs/tags/shipyard-candidate-{SHA}"
    assert result.repository_owner == "example"
    assert result.repository_name == "app"
    assert [call["method"] for call in transport.calls] == ["GET", "GET", "GET"]
    assert all(call["body"] is None for call in transport.calls)
    assert "secret-token" not in json.dumps(result.evidence())


@pytest.mark.parametrize(
    ("canonical_name", "kind", "deleted", "message"),
    [
        ("refs/tags/other", "TAG", False, "exactly one"),
        (f"refs/tags/shipyard-candidate-{SHA}", "BRANCH", False, "not a tag"),
        (f"refs/tags/shipyard-candidate-{SHA}", "TAG", True, "deleted"),
    ],
)
def test_xcode_source_discovery_rejects_wrong_or_unusable_candidate_reference(
    monkeypatch, canonical_name, kind, deleted, message
) -> None:
    monkeypatch.setenv("APPLE_ASC_TOKEN", "secret-token")
    transport = FakeTransport(
        _source_discovery_responses(
            canonical_name=canonical_name,
            kind=kind,
            deleted=deleted,
        )
    )

    with pytest.raises(AdapterError, match=message):
        XcodeCloudSourceDiscovery(transport).discover(
            workflow_id="workflow-1",
            source_sha=SHA,
            config={"token_env": "APPLE_ASC_TOKEN"},
        )

    assert all(call["method"] == "GET" for call in transport.calls)


def test_xcode_source_discovery_rejects_reference_repository_drift(monkeypatch) -> None:
    monkeypatch.setenv("APPLE_ASC_TOKEN", "secret-token")
    responses = _source_discovery_responses()
    page = responses[-1].payload["data"]
    assert isinstance(page, list)
    relationships = page[0]["relationships"]
    assert isinstance(relationships, dict)
    relationships["repository"] = {
        "data": {"type": "scmRepositories", "id": "other-repository"}
    }

    with pytest.raises(AdapterError, match="different repository"):
        XcodeCloudSourceDiscovery(FakeTransport(responses)).discover(
            workflow_id="workflow-1",
            source_sha=SHA,
            config={"token_env": "APPLE_ASC_TOKEN"},
        )


def test_github_discovery_adopts_all_required_exact_sha_checks_without_dispatch(
    monkeypatch,
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS_TOKEN", "secret-token")
    transport = FakeTransport(
        [
            HttpResponse(200, {"id": 1234, "full_name": "owner/repo"}),
            HttpResponse(
                200,
                {
                    "workflow_runs": [
                        {
                            "id": 12,
                            "name": "Security",
                            "head_sha": SHA,
                            "status": "completed",
                            "conclusion": "success",
                            "event": "push",
                            "workflow_id": 102,
                            "run_attempt": 1,
                            "html_url": "https://github.com/owner/repo/actions/runs/12",
                        },
                        {
                            "id": 11,
                            "name": "Quality",
                            "head_sha": SHA,
                            "status": "completed",
                            "conclusion": "success",
                            "event": "push",
                            "workflow_id": 101,
                            "run_attempt": 1,
                            "html_url": "https://github.com/owner/repo/actions/runs/11",
                        },
                    ],
                    "total_count": 2,
                },
            )
        ]
    )
    context = AdapterContext(
        "discovery",
        SHA,
        "github-actions",
        "1234",
        {
            "owner": "owner",
            "repo": "repo",
            "repository_id": "1234",
            "token_env": "GITHUB_ACTIONS_TOKEN",
            "required_workflow_ids": "101,102",
        },
    )

    result = GitHubWorkflowRunDiscovery(transport).discover(context)

    assert result.status == "succeeded"
    assert result.observed_sha == SHA
    assert result.operation_id == "github-checks:" + SHA
    assert result.evidence["required"] == 2
    assert result.evidence["succeeded"] == 2
    assert [run["id"] for run in result.evidence["runs"]] == [11, 12]
    assert [call["method"] for call in transport.calls] == ["GET", "GET"]
    runs_url = transport.calls[1]["url"]
    assert isinstance(runs_url, str)
    assert runs_url.endswith(
        f"/actions/runs?head_sha={SHA}&per_page=100&page=1"
    )
    assert all(call["body"] is None for call in transport.calls)
    assert "secret-token" not in json.dumps(result.evidence)


def test_github_discovery_distrusts_head_sha_filter_response(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS_TOKEN", "secret-token")
    transport = FakeTransport(
        [
            HttpResponse(200, {"id": 1234, "full_name": "owner/repo"}),
            HttpResponse(
                200,
                {
                    "workflow_runs": [
                        {
                            "id": 99,
                            "name": "Wrong source",
                            "head_sha": "b" * 40,
                            "status": "completed",
                            "conclusion": "success",
                            "event": "push",
                            "workflow_id": 101,
                        }
                    ],
                    "total_count": 1,
                },
            ),
        ]
    )
    context = AdapterContext(
        "discovery",
        SHA,
        "github-actions",
        "1234",
        {
            "owner": "owner",
            "repo": "repo",
            "repository_id": "1234",
            "token_env": "GITHUB_ACTIONS_TOKEN",
            "required_workflow_ids": "101",
        },
    )

    result = GitHubWorkflowRunDiscovery(transport).discover(context)

    assert result.status == "unknown"
    assert result.evidence["missing_workflow_ids"] == ["101"]
    assert result.evidence["runs"] == []
    assert result.evidence["adopted"] is False
