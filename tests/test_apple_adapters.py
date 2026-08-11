from __future__ import annotations

from collections.abc import Iterable

import pytest

from shipyard.adapters.apple import XcodeCloudBuildAdapter
from shipyard.adapters.apple_testflight import (
    TestFlightGroupAdapter as AppleTestFlightGroupAdapter,
)
from shipyard.adapters.base import AdapterContext, AdapterError, MutationReceipt
from shipyard.adapters.http import HttpResponse


class FakeTransport:
    def __init__(self, responses: Iterable[HttpResponse]):
        self.responses = iter(responses)
        self.calls: list[dict[str, object]] = []

    def request(self, method, url, *, headers, body=None):
        self.calls.append({"method": method, "url": url, "headers": headers, "body": body})
        return next(self.responses)


def _context() -> AdapterContext:
    return AdapterContext(
        run_id="run-1",
        source_sha="a" * 40,
        provider="apple",
        destination="workflow-1:gitref-1",
        config={
            "workflow_id": "workflow-1",
            "git_reference_id": "gitref-1",
            "token_env": "APPLE_ASC_TOKEN",
            "clean": True,
        },
    )


def _resource(resource_type: str, resource_id: str, **extra):
    return HttpResponse(200, {"data": {"type": resource_type, "id": resource_id, **extra}})


def test_xcode_cloud_check_verifies_canonical_workflow_and_git_reference(monkeypatch):
    monkeypatch.setenv("APPLE_ASC_TOKEN", "secret-token")
    transport = FakeTransport(
        [_resource("ciWorkflows", "workflow-1"), _resource("scmGitReferences", "gitref-1")]
    )

    result = XcodeCloudBuildAdapter(transport).check(_context())

    assert result.status == "verified"
    assert result.identity == "workflow-1:gitref-1"
    assert [call["method"] for call in transport.calls] == ["GET", "GET"]
    assert all(
        call["headers"]
        == {"Authorization": "Bearer secret-token", "Accept": "application/json"}
        for call in transport.calls
    )
    assert "secret-token" not in repr(result.evidence)


def test_xcode_cloud_execute_revalidates_identity_and_posts_official_relationships(monkeypatch):
    monkeypatch.setenv("APPLE_ASC_TOKEN", "secret-token")
    created = HttpResponse(201, {"data": {"type": "ciBuildRuns", "id": "build-run-9"}})
    transport = FakeTransport(
        [
            _resource("ciWorkflows", "workflow-1"),
            _resource("scmGitReferences", "gitref-1"),
            created,
        ]
    )

    receipt = XcodeCloudBuildAdapter(transport).execute(_context())

    assert receipt.operation_id == "build-run-9"
    assert receipt.submitted_sha == "a" * 40
    request = transport.calls[-1]
    assert request["method"] == "POST"
    assert request["url"] == "https://api.appstoreconnect.apple.com/v1/ciBuildRuns"
    assert request["body"] == {
        "data": {
            "type": "ciBuildRuns",
            "attributes": {"clean": True},
            "relationships": {
                "workflow": {"data": {"type": "ciWorkflows", "id": "workflow-1"}},
                "sourceBranchOrTag": {
                    "data": {"type": "scmGitReferences", "id": "gitref-1"}
                },
            },
        }
    }


@pytest.mark.parametrize(
    ("progress", "completion", "commit_sha", "expected"),
    [
        ("PENDING", None, "a" * 40, "pending"),
        ("RUNNING", None, "a" * 40, "pending"),
        ("COMPLETE", "SUCCEEDED", "a" * 40, "succeeded"),
        ("COMPLETE", "FAILED", "a" * 40, "failed"),
        ("COMPLETE", "ERRORED", "a" * 40, "failed"),
        ("COMPLETE", "CANCELED", "a" * 40, "failed"),
        ("COMPLETE", "SKIPPED", "a" * 40, "failed"),
        ("COMPLETE", "SUCCEEDED", "b" * 40, "failed"),
        ("SURPRISE", None, "a" * 40, "unknown"),
    ],
)
def test_xcode_cloud_readback_maps_official_status_and_exact_source(
    monkeypatch, progress, completion, commit_sha, expected
):
    monkeypatch.setenv("APPLE_ASC_TOKEN", "secret-token")
    payload = {
        "data": {
            "type": "ciBuildRuns",
            "id": "build-run-9",
            "attributes": {
                "executionProgress": progress,
                "completionStatus": completion,
                "sourceCommit": {"commitSha": commit_sha},
            },
            "relationships": {
                "workflow": {"data": {"type": "ciWorkflows", "id": "workflow-1"}},
                "sourceBranchOrTag": {
                    "data": {"type": "scmGitReferences", "id": "gitref-1"}
                },
            },
        }
    }
    transport = FakeTransport([HttpResponse(200, payload)])
    receipt = MutationReceipt("apple", "xcodecloud.build", "build-run-9", "a" * 40, {})

    result = XcodeCloudBuildAdapter(transport).readback(_context(), receipt)

    assert result.status == expected
    assert result.operation_id == "build-run-9"
    assert result.observed_sha == commit_sha


def test_xcode_cloud_readback_fails_on_provider_relationship_drift(monkeypatch):
    monkeypatch.setenv("APPLE_ASC_TOKEN", "secret-token")
    payload = {
        "data": {
            "type": "ciBuildRuns",
            "id": "build-run-9",
            "attributes": {
                "executionProgress": "COMPLETE",
                "completionStatus": "SUCCEEDED",
                "sourceCommit": {"commitSha": "a" * 40},
            },
            "relationships": {
                "workflow": {"data": {"type": "ciWorkflows", "id": "other"}},
                "sourceBranchOrTag": {
                    "data": {"type": "scmGitReferences", "id": "gitref-1"}
                },
            },
        }
    }
    transport = FakeTransport([HttpResponse(200, payload)])
    receipt = MutationReceipt("apple", "xcodecloud.build", "build-run-9", "a" * 40, {})

    assert XcodeCloudBuildAdapter(transport).readback(_context(), receipt).status == "failed"


@pytest.mark.parametrize(
    ("config_update", "message"),
    [
        ({"token_env": "TOKEN"}, "APPLE_"),
        ({"workflow_id": "https://example.test/workflow"}, "identifier"),
        ({"api_base": "https://proxy.example.test"}, "official"),
    ],
)
def test_xcode_cloud_rejects_unsafe_configuration(monkeypatch, config_update, message):
    monkeypatch.setenv("APPLE_ASC_TOKEN", "secret-token")
    context = _context()
    context.config.update(config_update)

    with pytest.raises(AdapterError, match=message):
        XcodeCloudBuildAdapter(FakeTransport([])).check(context)


def _testflight_context() -> AdapterContext:
    return AdapterContext(
        run_id="run-1",
        source_sha="a" * 40,
        provider="apple",
        destination="app-1:build-1:group-1",
        config={
            "app_id": "app-1",
            "build_id": "build-1",
            "beta_group_id": "group-1",
            "pre_release_version_id": "version-1",
            "xcode_cloud_run_id": "build-run-9",
            "bundle_id": "com.example.app",
            "marketing_version": "2.1",
            "build_number": "42",
            "token_env": "APPLE_ASC_TOKEN",
        },
    )


def _testflight_identity_responses():
    return [
        HttpResponse(
            200,
            {
                "data": {
                    "type": "apps",
                    "id": "app-1",
                    "attributes": {"bundleId": "com.example.app"},
                }
            },
        ),
        HttpResponse(
            200,
            {
                "data": {
                    "type": "builds",
                    "id": "build-1",
                    "attributes": {"version": "42", "processingState": "VALID"},
                    "relationships": {
                        "app": {"data": {"type": "apps", "id": "app-1"}},
                        "preReleaseVersion": {
                            "data": {"type": "preReleaseVersions", "id": "version-1"}
                        },
                    },
                }
            },
        ),
        HttpResponse(
            200,
            {
                "data": {
                    "type": "preReleaseVersions",
                    "id": "version-1",
                    "attributes": {"version": "2.1"},
                }
            },
        ),
        HttpResponse(
            200,
            {
                "data": {
                    "type": "ciBuildRuns",
                    "id": "build-run-9",
                    "attributes": {"sourceCommit": {"commitSha": "a" * 40}},
                    "relationships": {
                        "builds": {"data": [{"type": "builds", "id": "build-1"}]}
                    },
                }
            },
        ),
        _resource("betaGroups", "group-1"),
    ]


def test_testflight_check_binds_app_build_version_xcode_source_and_group(monkeypatch):
    monkeypatch.setenv("APPLE_ASC_TOKEN", "secret-token")
    transport = FakeTransport(_testflight_identity_responses())

    check = AppleTestFlightGroupAdapter(transport).check(_testflight_context())

    assert check.status == "verified"
    assert check.identity == "app-1:build-1:group-1"
    assert check.evidence["source_sha"] == "a" * 40
    assert check.evidence["bundle_id"] == "com.example.app"
    assert "secret-token" not in repr(check.evidence)


def test_testflight_execute_revalidates_then_adds_exact_build_relationship(monkeypatch):
    monkeypatch.setenv("APPLE_ASC_TOKEN", "secret-token")
    transport = FakeTransport([*_testflight_identity_responses(), HttpResponse(204, {})])

    receipt = AppleTestFlightGroupAdapter(transport).execute(_testflight_context())

    assert receipt.operation_id == "group-1:build-1"
    assert receipt.submitted_sha == "a" * 40
    assert transport.calls[-1] == {
        "method": "POST",
        "url": "https://api.appstoreconnect.apple.com/v1/betaGroups/group-1/relationships/builds",
        "headers": {
            "Authorization": "Bearer secret-token",
            "Accept": "application/json",
        },
        "body": {"data": [{"type": "builds", "id": "build-1"}]},
    }


def test_testflight_readback_drains_relationship_pages_and_finds_build(monkeypatch):
    monkeypatch.setenv("APPLE_ASC_TOKEN", "secret-token")
    first = HttpResponse(
        200,
        {
            "data": [{"type": "builds", "id": "other"}],
            "links": {
                "next": "https://api.appstoreconnect.apple.com/v1/betaGroups/group-1/relationships/builds?cursor=next"
            },
        },
    )
    second = HttpResponse(
        200,
        {"data": [{"type": "builds", "id": "build-1"}], "links": {"next": None}},
    )
    transport = FakeTransport([*_testflight_identity_responses(), first, second])
    receipt = MutationReceipt(
        "apple", "appstoreconnect.testflight", "group-1:build-1", "a" * 40, {}
    )

    readback = AppleTestFlightGroupAdapter(transport).readback(_testflight_context(), receipt)

    assert readback.status == "succeeded"
    assert readback.observed_sha == "a" * 40
    assert readback.evidence["pages"] == 2


def test_testflight_readback_rejects_non_apple_pagination_url(monkeypatch):
    monkeypatch.setenv("APPLE_ASC_TOKEN", "secret-token")
    page = HttpResponse(
        200,
        {
            "data": [],
            "links": {"next": "https://attacker.example.test/steal"},
        },
    )
    transport = FakeTransport([*_testflight_identity_responses(), page])
    receipt = MutationReceipt(
        "apple", "appstoreconnect.testflight", "group-1:build-1", "a" * 40, {}
    )

    with pytest.raises(AdapterError, match="pagination"):
        AppleTestFlightGroupAdapter(transport).readback(_testflight_context(), receipt)


def test_testflight_check_rejects_wrong_xcode_source_before_mutation(monkeypatch):
    monkeypatch.setenv("APPLE_ASC_TOKEN", "secret-token")
    responses = _testflight_identity_responses()
    run = responses[3].payload["data"]
    run["attributes"]["sourceCommit"]["commitSha"] = "b" * 40
    transport = FakeTransport(responses)

    with pytest.raises(AdapterError, match="source SHA"):
        AppleTestFlightGroupAdapter(transport).check(_testflight_context())

    assert all(call["method"] == "GET" for call in transport.calls)
