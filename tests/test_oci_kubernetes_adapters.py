from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

import pytest

from shipyard.adapters.base import AdapterContext, AdapterError
from shipyard.adapters.kubernetes import KubernetesDeploymentAdapter
from shipyard.adapters.oci import OciPromotionAdapter
from shipyard.adapters.raw_http import RawHttpResponse, UrllibRawTransport

SHA = "a" * 40


@dataclass
class FakeRawTransport:
    responses: list[RawHttpResponse]
    requests: list[dict[str, object]] = field(default_factory=list)

    def request(self, method, url, *, headers, body=None, content_type=None):
        self.requests.append(
            {
                "method": method,
                "url": url,
                "headers": headers,
                "body": body,
                "content_type": content_type,
            }
        )
        return self.responses.pop(0)


def _raw_json(payload: dict[str, object], status: int = 200) -> RawHttpResponse:
    return RawHttpResponse(
        status=status,
        headers={"content-type": "application/json"},
        body=json.dumps(payload, separators=(",", ":")).encode(),
    )


def _oci_context(digest: str) -> AdapterContext:
    return AdapterContext(
        run_id="run-1",
        source_sha=SHA,
        provider="oci",
        destination="registry.example.com/team/app:stable",
        config={
            "registry": "registry.example.com",
            "repository": "team/app",
            "manifest_digest": digest,
            "target_tag": "stable",
            "token_env": "OCI_REGISTRY_TOKEN",
        },
    )


def test_oci_promotion_hashes_exact_manifest_puts_once_and_reads_back(monkeypatch):
    monkeypatch.setenv("OCI_REGISTRY_TOKEN", "synthetic-token")
    image_config = json.dumps(
        {"config": {"Labels": {"org.opencontainers.image.revision": SHA}}},
        separators=(",", ":"),
    ).encode()
    config_digest = f"sha256:{hashlib.sha256(image_config).hexdigest()}"
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": len(image_config),
            },
            "layers": [],
        },
        separators=(",", ":"),
    ).encode()
    digest = f"sha256:{hashlib.sha256(manifest).hexdigest()}"
    media_type = "application/vnd.oci.image.manifest.v1+json"
    transport = FakeRawTransport(
        [
            RawHttpResponse(200, {"docker-content-digest": digest}, b""),
            RawHttpResponse(
                200,
                {"docker-content-digest": digest, "content-type": media_type},
                manifest,
            ),
            RawHttpResponse(
                200,
                {"content-type": "application/vnd.oci.image.config.v1+json"},
                image_config,
            ),
            RawHttpResponse(201, {"docker-content-digest": digest}, b""),
            RawHttpResponse(200, {"docker-content-digest": digest}, b""),
        ]
    )
    adapter = OciPromotionAdapter(transport)
    context = _oci_context(digest)

    receipt = adapter.execute(context)
    readback = adapter.readback(context, receipt)

    assert [request["method"] for request in transport.requests] == [
        "HEAD",
        "GET",
        "GET",
        "PUT",
        "HEAD",
    ]
    put = transport.requests[3]
    assert put["body"] == manifest
    assert put["content_type"] == media_type
    assert receipt.evidence["manifest_digest"] == digest
    assert receipt.submitted_sha == SHA
    assert readback.status == "succeeded"
    assert readback.observed_sha == SHA


def test_oci_promotion_refuses_image_not_bound_to_approved_source_before_put(monkeypatch):
    monkeypatch.setenv("OCI_REGISTRY_TOKEN", "synthetic-token")
    image_config = json.dumps(
        {"config": {"Labels": {"org.opencontainers.image.revision": "c" * 40}}},
        separators=(",", ":"),
    ).encode()
    config_digest = f"sha256:{hashlib.sha256(image_config).hexdigest()}"
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": len(image_config),
            },
            "layers": [],
        },
        separators=(",", ":"),
    ).encode()
    digest = f"sha256:{hashlib.sha256(manifest).hexdigest()}"
    transport = FakeRawTransport(
        [
            RawHttpResponse(200, {"docker-content-digest": digest}, b""),
            RawHttpResponse(
                200,
                {
                    "docker-content-digest": digest,
                    "content-type": "application/vnd.oci.image.manifest.v1+json",
                },
                manifest,
            ),
            RawHttpResponse(
                200,
                {"content-type": "application/vnd.oci.image.config.v1+json"},
                image_config,
            ),
        ]
    )

    with pytest.raises(AdapterError, match="source revision"):
        OciPromotionAdapter(transport).execute(_oci_context(digest))

    assert [request["method"] for request in transport.requests] == [
        "HEAD",
        "GET",
        "GET",
    ]


def test_oci_promotion_refuses_digest_drift_before_put(monkeypatch):
    monkeypatch.setenv("OCI_REGISTRY_TOKEN", "synthetic-token")
    digest = f"sha256:{'b' * 64}"
    transport = FakeRawTransport(
        [RawHttpResponse(200, {"docker-content-digest": f"sha256:{'c' * 64}"}, b"")]
    )

    with pytest.raises(AdapterError, match="manifest digest"):
        OciPromotionAdapter(transport).execute(_oci_context(digest))

    assert [request["method"] for request in transport.requests] == ["HEAD"]


@pytest.mark.parametrize(
    "update",
    [
        {"registry": "https://registry.example.com"},
        {"registry": "user@registry.example.com"},
        {"repository": "../team/app"},
        {"target_tag": "latest/unsafe"},
        {"token_env": "GITHUB_TOKEN"},
    ],
)
def test_oci_promotion_rejects_unsafe_coordinates_without_network(update):
    digest = f"sha256:{'b' * 64}"
    context = _oci_context(digest)
    context.config.update(update)
    transport = FakeRawTransport([])

    with pytest.raises(AdapterError):
        OciPromotionAdapter(transport).check(context)

    assert transport.requests == []


def _namespace(uid: str = "namespace-uid") -> dict[str, object]:
    return {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {"name": "production", "uid": uid},
    }


def _deployment(
    *,
    uid: str = "deployment-uid",
    image: str = "registry.example.com/team/app:old",
    generation: int = 7,
    observed_generation: int = 7,
    replicas: int = 3,
    updated: int = 3,
    available: int = 3,
) -> dict[str, object]:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "web",
            "namespace": "production",
            "uid": uid,
            "resourceVersion": "42",
            "generation": generation,
        },
        "spec": {
            "replicas": replicas,
            "template": {
                "spec": {
                    "containers": [
                        {"name": "web", "image": image},
                        {"name": "sidecar", "image": "example/sidecar@sha256:" + "d" * 64},
                    ]
                }
            },
        },
        "status": {
            "observedGeneration": observed_generation,
            "updatedReplicas": updated,
            "availableReplicas": available,
            "conditions": [
                {"type": "Available", "status": "True"},
                {
                    "type": "Progressing",
                    "status": "True",
                    "reason": "NewReplicaSetAvailable",
                },
            ],
        },
    }


def _kubernetes_context() -> AdapterContext:
    digest = f"sha256:{'b' * 64}"
    return AdapterContext(
        run_id="run-1",
        source_sha=SHA,
        provider="kubernetes",
        destination="prod-cluster:production:web:web",
        config={
            "api_base": "https://kubernetes.example.com",
            "cluster_id": "prod-cluster",
            "namespace": "production",
            "namespace_uid": "namespace-uid",
            "deployment": "web",
            "deployment_uid": "deployment-uid",
            "container": "web",
            "image_repository": "registry.example.com/team/app",
            "manifest_digest": digest,
            "token_env": "KUBERNETES_API_TOKEN",
        },
    )


def test_kubernetes_deployment_patches_exact_digest_once_and_verifies_rollout(monkeypatch):
    monkeypatch.setenv("KUBERNETES_API_TOKEN", "synthetic-token")
    context = _kubernetes_context()
    expected_image = (
        f"{context.config['image_repository']}@{context.config['manifest_digest']}"
    )
    transport = FakeRawTransport(
        [
            _raw_json(_namespace()),
            _raw_json(_deployment()),
            _raw_json(_deployment(image=expected_image, generation=8, observed_generation=7)),
            _raw_json(_deployment(image=expected_image, generation=8, observed_generation=8)),
        ]
    )
    adapter = KubernetesDeploymentAdapter(transport)

    receipt = adapter.execute(context)
    readback = adapter.readback(context, receipt)

    assert [request["method"] for request in transport.requests] == [
        "GET",
        "GET",
        "PATCH",
        "GET",
    ]
    encoded_patch = transport.requests[2]["body"]
    assert isinstance(encoded_patch, bytes)
    patch = json.loads(encoded_patch)
    assert patch["metadata"]["resourceVersion"] == "42"
    assert patch["spec"]["template"]["spec"]["containers"] == [
        {"name": "web", "image": expected_image}
    ]
    assert transport.requests[2]["content_type"] == (
        "application/strategic-merge-patch+json"
    )
    assert receipt.evidence["image"] == expected_image
    assert readback.status == "succeeded"
    assert readback.observed_sha == SHA


def test_kubernetes_deployment_returns_pending_until_rollout_is_observed(monkeypatch):
    monkeypatch.setenv("KUBERNETES_API_TOKEN", "synthetic-token")
    context = _kubernetes_context()
    expected_image = (
        f"{context.config['image_repository']}@{context.config['manifest_digest']}"
    )
    transport = FakeRawTransport(
        [_raw_json(_deployment(image=expected_image, generation=8, observed_generation=7))]
    )
    receipt = KubernetesDeploymentAdapter.operation_receipt(context, "42")

    readback = KubernetesDeploymentAdapter(transport).readback(context, receipt)

    assert readback.status == "pending"
    assert readback.observed_sha is None
    assert [request["method"] for request in transport.requests] == ["GET"]


def test_kubernetes_readback_fails_closed_on_deployment_uid_drift(monkeypatch):
    monkeypatch.setenv("KUBERNETES_API_TOKEN", "synthetic-token")
    context = _kubernetes_context()
    expected_image = (
        f"{context.config['image_repository']}@{context.config['manifest_digest']}"
    )
    transport = FakeRawTransport(
        [_raw_json(_deployment(uid="different-uid", image=expected_image))]
    )
    receipt = KubernetesDeploymentAdapter.operation_receipt(context, "42")

    with pytest.raises(AdapterError, match="deployment identity"):
        KubernetesDeploymentAdapter(transport).readback(context, receipt)


def test_kubernetes_scale_zero_rollout_reconciles_exact_observed_image(monkeypatch):
    monkeypatch.setenv("KUBERNETES_API_TOKEN", "synthetic-token")
    context = _kubernetes_context()
    expected_image = (
        f"{context.config['image_repository']}@{context.config['manifest_digest']}"
    )
    deployment = _deployment(
        image=expected_image,
        replicas=0,
        updated=0,
        available=0,
    )
    status = deployment["status"]
    assert isinstance(status, dict)
    conditions = status["conditions"]
    assert isinstance(conditions, list)
    conditions[0] = {"type": "Available", "status": "False"}
    transport = FakeRawTransport([_raw_json(deployment)])
    receipt = KubernetesDeploymentAdapter.operation_receipt(context, "42")

    readback = KubernetesDeploymentAdapter(transport).readback(context, receipt)

    assert readback.status == "succeeded"
    assert readback.observed_sha == SHA


def test_kubernetes_deployment_refuses_uid_drift_before_patch(monkeypatch):
    monkeypatch.setenv("KUBERNETES_API_TOKEN", "synthetic-token")
    transport = FakeRawTransport(
        [_raw_json(_namespace()), _raw_json(_deployment(uid="different-uid"))]
    )

    with pytest.raises(AdapterError, match="deployment identity"):
        KubernetesDeploymentAdapter(transport).execute(_kubernetes_context())

    assert [request["method"] for request in transport.requests] == ["GET", "GET"]


@pytest.mark.parametrize(
    "update",
    [
        {"api_base": "http://kubernetes.example.com"},
        {"api_base": "https://user@kubernetes.example.com"},
        {"namespace": "../production"},
        {"manifest_digest": "sha256:mutable"},
        {"token_env": "GITHUB_TOKEN"},
    ],
)
def test_kubernetes_deployment_rejects_unsafe_coordinates_without_network(update):
    context = _kubernetes_context()
    context.config.update(update)
    transport = FakeRawTransport([])

    with pytest.raises(AdapterError):
        KubernetesDeploymentAdapter(transport).check(context)

    assert transport.requests == []


@pytest.mark.parametrize(
    "url",
    [
        "http://provider.example.com/v1/resource",
        "https://user@provider.example.com/v1/resource",
        "https://provider.example.com/v1/resource#fragment",
    ],
)
def test_raw_http_transport_rejects_unsafe_urls_before_network(url):
    with pytest.raises(AdapterError):
        UrllibRawTransport().request("GET", url, headers={})


def test_raw_http_transport_rejects_oversized_outgoing_body_before_network():
    with pytest.raises(AdapterError, match="4 MiB"):
        UrllibRawTransport().request(
            "PUT",
            "https://provider.example.com/v1/resource",
            headers={},
            body=b"x" * (4 * 1024 * 1024 + 1),
            content_type="application/octet-stream",
        )
