from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from shipyard.adapters.base import AdapterError
from shipyard.adapters.http import HttpResponse
from shipyard.apple_auth import apple_bearer_token
from shipyard.apple_release import AppleReleaseResolver, render_testflight_playbook
from shipyard.playbook import load_playbook

SHA = "a" * 40


class FakeTransport:
    def __init__(self, responses: list[HttpResponse]):
        self.responses = iter(responses)
        self.calls: list[dict[str, object]] = []

    def request(self, method, url, *, headers, body=None):
        self.calls.append({"method": method, "url": url, "headers": headers, "body": body})
        return next(self.responses)


def _resource(
    resource_type: str,
    resource_id: str,
    *,
    attributes: dict[str, object] | None = None,
    relationships: dict[str, object] | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {"type": resource_type, "id": resource_id}
    if attributes is not None:
        result["attributes"] = attributes
    if relationships is not None:
        result["relationships"] = relationships
    return result


def _apple_responses(*, membership: bool = False) -> list[HttpResponse]:
    candidate_ref = f"refs/tags/shipyard-candidate-{SHA}"
    workflow = _resource(
        "ciWorkflows",
        "workflow-1",
        relationships={
            "repository": {"data": {"type": "scmRepositories", "id": "repository-1"}}
        },
    )
    repository = _resource(
        "scmRepositories",
        "repository-1",
        attributes={
            "ownerName": "example",
            "repositoryName": "app",
            "httpCloneUrl": "https://github.com/example/app.git",
            "sshCloneUrl": "git@github.com:example/app.git",
        },
    )
    reference = _resource(
        "scmGitReferences",
        "reference-1",
        attributes={
            "name": candidate_ref.removeprefix("refs/tags/"),
            "canonicalName": candidate_ref,
            "isDeleted": False,
            "kind": "TAG",
        },
        relationships={
            "repository": {"data": {"type": "scmRepositories", "id": "repository-1"}}
        },
    )
    run = _resource(
        "ciBuildRuns",
        "run-609",
        attributes={
            "number": 609,
            "executionProgress": "COMPLETE",
            "completionStatus": "SUCCEEDED",
            "sourceCommit": {"commitSha": SHA},
        },
        relationships={"builds": {"data": [{"type": "builds", "id": "build-609"}]}},
    )
    build = _resource(
        "builds",
        "build-609",
        attributes={
            "version": "609",
            "processingState": "VALID",
            "expired": False,
            "usesNonExemptEncryption": False,
        },
        relationships={
            "app": {"data": {"type": "apps", "id": "app-1"}},
            "preReleaseVersion": {
                "data": {"type": "preReleaseVersions", "id": "version-1"}
            },
        },
    )
    group = _resource(
        "betaGroups",
        "group-testing",
        attributes={"name": "Testing", "isInternalGroup": True},
        relationships={"app": {"data": {"type": "apps", "id": "app-1"}}},
    )
    return [
        HttpResponse(200, {"data": workflow}),
        HttpResponse(200, {"data": repository}),
        HttpResponse(200, {"data": [reference], "links": {"next": None}}),
        HttpResponse(200, {"data": [run], "links": {"next": None}}),
        HttpResponse(
            200,
            {
                "data": [
                    _resource(
                        "apps",
                        "app-1",
                        attributes={"bundleId": "com.example.app", "name": "Example"},
                    )
                ],
                "links": {"next": None},
            },
        ),
        HttpResponse(200, {"data": run}),
        HttpResponse(200, {"data": build}),
        HttpResponse(
            200,
            {
                "data": _resource(
                    "preReleaseVersions", "version-1", attributes={"version": "1.1"}
                )
            },
        ),
        HttpResponse(200, {"data": [group], "links": {"next": None}}),
        HttpResponse(
            200,
            {
                "data": (
                    [{"type": "builds", "id": "build-609"}] if membership else []
                ),
                "links": {"next": None},
            },
        ),
        HttpResponse(
            200,
            {
                "data": _resource(
                    "buildBetaDetails",
                    "build-609",
                    attributes={
                        "internalBuildState": (
                            "IN_BETA_TESTING" if membership else "READY_FOR_BETA_TESTING"
                        ),
                        "externalBuildState": "READY_FOR_BETA_SUBMISSION",
                    },
                )
            },
        ),
    ]


def _config() -> dict[str, object]:
    return {
        "workflow_id": "workflow-1",
        "source_remote": "https://github.com/example/app.git",
        "bundle_id": "com.example.app",
        "beta_group_name": "Testing",
        "expected_build_number": "609",
        "expected_marketing_version": "1.1",
        "token_env": "APPLE_ASC_TOKEN",
    }


def test_apple_release_resolver_discovers_all_opaque_ids_get_only(monkeypatch) -> None:
    monkeypatch.setenv("APPLE_ASC_TOKEN", "secret-token")
    transport = FakeTransport(_apple_responses())

    result = AppleReleaseResolver(transport).resolve(source_sha=SHA, config=_config())

    assert result.source_sha == SHA
    assert result.run_id == "run-609"
    assert result.repository_id == "repository-1"
    assert result.repository_identity == "github.com/example/app"
    assert result.git_reference_id == "reference-1"
    assert result.run_number == "609"
    assert result.build_id == "build-609"
    assert result.build_number == "609"
    assert result.app_id == "app-1"
    assert result.pre_release_version_id == "version-1"
    assert result.marketing_version == "1.1"
    assert result.beta_group_id == "group-testing"
    assert result.beta_group_internal is True
    assert result.relationship_present is False
    assert result.digest
    assert all(call["method"] == "GET" for call in transport.calls)
    assert all(call["body"] is None for call in transport.calls)
    assert "secret-token" not in json.dumps(result.payload())


def test_resolved_apple_playbook_is_secret_free_and_parser_valid(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("APPLE_ASC_TOKEN", "secret-token")
    coordinates = AppleReleaseResolver(FakeTransport(_apple_responses())).resolve(
        source_sha=SHA, config=_config()
    )

    rendered = render_testflight_playbook(
        coordinates,
        credential_config={"token_env": "APPLE_ASC_TOKEN"},
        name="example-609-testing",
    )
    path = tmp_path / "shipyard.toml"
    path.write_text(rendered, encoding="utf-8")
    playbook = load_playbook(path)

    assert playbook.provider == "apple"
    assert playbook.destination == "app-1:build-609:group-testing"
    assert playbook.steps[0].config["xcode_cloud_run_id"] == "run-609"
    assert playbook.steps[0].config["token_env"] == "APPLE_ASC_TOKEN"
    assert "secret-token" not in rendered


def test_apple_playbook_refuses_noop_when_group_already_contains_build(monkeypatch) -> None:
    monkeypatch.setenv("APPLE_ASC_TOKEN", "secret-token")
    coordinates = AppleReleaseResolver(FakeTransport(_apple_responses(membership=True))).resolve(
        source_sha=SHA, config=_config()
    )

    with pytest.raises(AdapterError, match="already contains"):
        render_testflight_playbook(
            coordinates,
            credential_config={"token_env": "APPLE_ASC_TOKEN"},
            name="example-609-testing",
        )


def _decode(segment: str) -> dict[str, object]:
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def test_native_apple_jwt_is_short_lived_valid_es256_and_secret_free(monkeypatch, tmp_path) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    key_path = tmp_path / "AuthKey_TEST01.p8"
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    monkeypatch.setenv("APPLE_ISSUER_ID", "11111111-2222-3333-4444-555555555555")
    monkeypatch.setenv("APPLE_KEY_ID", "TEST01")
    monkeypatch.setenv("APPLE_PRIVATE_KEY_PATH", str(key_path))
    config = {
        "issuer_id_env": "APPLE_ISSUER_ID",
        "key_id_env": "APPLE_KEY_ID",
        "private_key_path_env": "APPLE_PRIVATE_KEY_PATH",
    }

    token = apple_bearer_token(config)
    header_segment, payload_segment, signature_segment = token.split(".")
    header = _decode(header_segment)
    payload = _decode(payload_segment)
    raw_signature = base64.urlsafe_b64decode(
        signature_segment + "=" * (-len(signature_segment) % 4)
    )
    r = int.from_bytes(raw_signature[:32], "big")
    s = int.from_bytes(raw_signature[32:], "big")
    private_key.public_key().verify(
        encode_dss_signature(r, s),
        f"{header_segment}.{payload_segment}".encode("ascii"),
        ec.ECDSA(hashes.SHA256()),
    )

    assert header == {"alg": "ES256", "kid": "TEST01", "typ": "JWT"}
    assert payload["iss"] == "11111111-2222-3333-4444-555555555555"
    assert payload["aud"] == "appstoreconnect-v1"
    issued_at = payload["iat"]
    expires_at = payload["exp"]
    assert isinstance(issued_at, int)
    assert isinstance(expires_at, int)
    assert expires_at - issued_at == 600
    assert key_path.read_text(encoding="utf-8").strip() not in token


def test_native_apple_jwt_rejects_group_readable_private_key(monkeypatch, tmp_path) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    key_path = tmp_path / "AuthKey_TEST01.p8"
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o640)
    monkeypatch.setenv("APPLE_ISSUER_ID", "11111111-2222-3333-4444-555555555555")
    monkeypatch.setenv("APPLE_KEY_ID", "TEST01")
    monkeypatch.setenv("APPLE_PRIVATE_KEY_PATH", str(key_path))

    with pytest.raises(AdapterError, match="mode 0400 or 0600"):
        apple_bearer_token(
            {
                "issuer_id_env": "APPLE_ISSUER_ID",
                "key_id_env": "APPLE_KEY_ID",
                "private_key_path_env": "APPLE_PRIVATE_KEY_PATH",
            }
        )
