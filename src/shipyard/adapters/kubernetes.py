from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

from .base import AdapterContext, AdapterError, ConnectionCheck, MutationReceipt, ProviderReadback
from .oci import OciPromotionAdapter
from .raw_http import RawHttpResponse, RawHttpTransport, UrllibRawTransport

_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
_CONTAINER = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
_UID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CLUSTER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_IMAGE_REPOSITORY = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?/)?"
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$"
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ENV = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")


@dataclass(frozen=True)
class _Coordinates:
    api_base: str
    cluster_id: str
    namespace: str
    namespace_uid: str
    deployment: str
    deployment_uid: str
    container: str
    image_repository: str
    manifest_digest: str
    registry: str
    repository: str
    registry_token_env: str
    token_env: str

    @property
    def destination(self) -> str:
        return f"{self.cluster_id}:{self.namespace}:{self.deployment}:{self.container}"

    @property
    def image(self) -> str:
        return f"{self.image_repository}@{self.manifest_digest}"

    @property
    def namespace_url(self) -> str:
        return f"{self.api_base}/api/v1/namespaces/{quote(self.namespace, safe='')}"

    @property
    def deployment_url(self) -> str:
        return (
            f"{self.api_base}/apis/apps/v1/namespaces/"
            f"{quote(self.namespace, safe='')}/deployments/{quote(self.deployment, safe='')}"
        )


class KubernetesDeploymentAdapter:
    """Deploy one immutable image digest to one identity-bound Deployment container."""

    action = "kubernetes.deploy"

    def __init__(self, transport: RawHttpTransport | None = None) -> None:
        self.transport = transport or UrllibRawTransport()

    @staticmethod
    def _config_string(context: AdapterContext, name: str) -> str:
        value = context.config.get(name)
        if not isinstance(value, str) or not value.strip():
            raise AdapterError(f"kubernetes.deploy config requires {name}")
        return value.strip()

    @classmethod
    def _coordinates(cls, context: AdapterContext) -> _Coordinates:
        api_base = cls._config_string(context, "api_base").rstrip("/")
        parsed = urlsplit(api_base)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise AdapterError("kubernetes.deploy api_base must be an HTTPS origin")
        coordinates = _Coordinates(
            api_base=api_base,
            cluster_id=cls._config_string(context, "cluster_id"),
            namespace=cls._config_string(context, "namespace"),
            namespace_uid=cls._config_string(context, "namespace_uid"),
            deployment=cls._config_string(context, "deployment"),
            deployment_uid=cls._config_string(context, "deployment_uid"),
            container=cls._config_string(context, "container"),
            image_repository=cls._config_string(context, "image_repository"),
            manifest_digest=cls._config_string(context, "manifest_digest"),
            registry=cls._config_string(context, "registry"),
            repository=cls._config_string(context, "repository"),
            registry_token_env=cls._config_string(context, "registry_token_env"),
            token_env=cls._config_string(context, "token_env"),
        )
        if _CLUSTER.fullmatch(coordinates.cluster_id) is None:
            raise AdapterError("kubernetes.deploy cluster_id is invalid")
        if (
            _NAME.fullmatch(coordinates.namespace) is None
            or len(coordinates.namespace) > 63
            or _NAME.fullmatch(coordinates.deployment) is None
        ):
            raise AdapterError("kubernetes.deploy resource name is invalid")
        if (
            _UID.fullmatch(coordinates.namespace_uid) is None
            or _UID.fullmatch(coordinates.deployment_uid) is None
        ):
            raise AdapterError("kubernetes.deploy resource UID is invalid")
        if _CONTAINER.fullmatch(coordinates.container) is None:
            raise AdapterError("kubernetes.deploy container name is invalid")
        if (
            _IMAGE_REPOSITORY.fullmatch(coordinates.image_repository) is None
            or "@" in coordinates.image_repository
        ):
            raise AdapterError("kubernetes.deploy image repository is invalid")
        if coordinates.image_repository != (
            f"{coordinates.registry}/{coordinates.repository}"
        ):
            raise AdapterError(
                "kubernetes.deploy image_repository must equal registry/repository"
            )
        if _DIGEST.fullmatch(coordinates.manifest_digest) is None:
            raise AdapterError("kubernetes.deploy requires an exact sha256 manifest digest")
        if (
            _ENV.fullmatch(coordinates.registry_token_env) is None
            or not coordinates.registry_token_env.startswith("OCI_")
        ):
            raise AdapterError(
                "kubernetes.deploy registry_token_env must use an OCI_ variable"
            )
        if (
            _ENV.fullmatch(coordinates.token_env) is None
            or not coordinates.token_env.startswith("KUBERNETES_")
        ):
            raise AdapterError(
                "kubernetes.deploy token_env must use a KUBERNETES_ variable"
            )
        if context.destination != coordinates.destination:
            raise AdapterError(
                "kubernetes.deploy destination does not match cluster coordinates"
            )
        return coordinates

    @staticmethod
    def _headers(coordinates: _Coordinates) -> dict[str, str]:
        token = os.environ.get(coordinates.token_env)
        if not token:
            raise AdapterError(
                f"credential environment variable {coordinates.token_env} is not set"
            )
        if any(character in token for character in ("\x00", "\r", "\n")):
            raise AdapterError("Kubernetes credential environment variable is malformed")
        return {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    @staticmethod
    def _json(response: RawHttpResponse, operation: str) -> dict[str, object]:
        if not 200 <= response.status < 300:
            raise AdapterError(f"{operation} failed with status {response.status}")
        try:
            payload = json.loads(response.body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise AdapterError(f"{operation} returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise AdapterError(f"{operation} returned a non-object response")
        return payload

    @staticmethod
    def _metadata(resource: dict[str, object], operation: str) -> dict[str, object]:
        metadata = resource.get("metadata")
        if not isinstance(metadata, dict):
            raise AdapterError(f"{operation} omitted resource metadata")
        return metadata

    @staticmethod
    def _container_image(resource: dict[str, object], container: str) -> str:
        spec = resource.get("spec")
        template = spec.get("template") if isinstance(spec, dict) else None
        pod_spec = template.get("spec") if isinstance(template, dict) else None
        containers = pod_spec.get("containers") if isinstance(pod_spec, dict) else None
        if not isinstance(containers, list):
            raise AdapterError("Kubernetes deployment omitted pod containers")
        matches = [
            item
            for item in containers
            if isinstance(item, dict) and item.get("name") == container
        ]
        if len(matches) != 1 or not isinstance(matches[0].get("image"), str):
            raise AdapterError("Kubernetes deployment container identity is ambiguous")
        return str(matches[0]["image"])

    def _identity(
        self, context: AdapterContext
    ) -> tuple[_Coordinates, dict[str, str], dict[str, object]]:
        coordinates = self._coordinates(context)
        headers = self._headers(coordinates)
        source_context = AdapterContext(
            run_id=context.run_id,
            source_sha=context.source_sha,
            provider="oci",
            destination=(
                f"{coordinates.registry}/{coordinates.repository}:"
                "shipyard-source-verification"
            ),
            config={
                "registry": coordinates.registry,
                "repository": coordinates.repository,
                "manifest_digest": coordinates.manifest_digest,
                "target_tag": "shipyard-source-verification",
                "token_env": coordinates.registry_token_env,
            },
        )
        OciPromotionAdapter(self.transport).check(source_context)
        namespace = self._json(
            self.transport.request(
                "GET", coordinates.namespace_url, headers=headers
            ),
            "Kubernetes namespace verification",
        )
        namespace_metadata = self._metadata(
            namespace, "Kubernetes namespace verification"
        )
        if (
            namespace.get("apiVersion") != "v1"
            or namespace.get("kind") != "Namespace"
            or namespace_metadata.get("name") != coordinates.namespace
            or namespace_metadata.get("uid") != coordinates.namespace_uid
        ):
            raise AdapterError("Kubernetes namespace identity differs")
        deployment = self._json(
            self.transport.request(
                "GET", coordinates.deployment_url, headers=headers
            ),
            "Kubernetes deployment verification",
        )
        metadata = self._metadata(deployment, "Kubernetes deployment verification")
        if (
            deployment.get("apiVersion") != "apps/v1"
            or deployment.get("kind") != "Deployment"
            or metadata.get("name") != coordinates.deployment
            or metadata.get("namespace") != coordinates.namespace
            or metadata.get("uid") != coordinates.deployment_uid
            or not isinstance(metadata.get("resourceVersion"), str)
        ):
            raise AdapterError("Kubernetes deployment identity differs")
        self._container_image(deployment, coordinates.container)
        return coordinates, headers, deployment

    def check(self, context: AdapterContext) -> ConnectionCheck:
        coordinates, _, deployment = self._identity(context)
        return ConnectionCheck(
            "verified",
            context.provider,
            self.action,
            f"{coordinates.namespace_uid}:{coordinates.deployment_uid}:{coordinates.container}",
            {
                "destination": coordinates.destination,
                "current_image": self._container_image(
                    deployment, coordinates.container
                ),
                "target_image": coordinates.image,
            },
        )

    @classmethod
    def operation_receipt(
        cls, context: AdapterContext, resource_version: str
    ) -> MutationReceipt:
        coordinates = cls._coordinates(context)
        operation_id = "k8s-" + hashlib.sha256(
            (
                f"{coordinates.deployment_uid}\0{resource_version}\0{coordinates.image}"
            ).encode()
        ).hexdigest()[:24]
        return MutationReceipt(
            context.provider,
            cls.action,
            operation_id,
            context.source_sha,
            {
                "destination": coordinates.destination,
                "deployment_uid": coordinates.deployment_uid,
                "resource_version": resource_version,
                "image": coordinates.image,
            },
        )

    def execute(self, context: AdapterContext) -> MutationReceipt:
        coordinates, headers, deployment = self._identity(context)
        metadata = self._metadata(deployment, "Kubernetes deployment verification")
        resource_version = str(metadata["resourceVersion"])
        patch = json.dumps(
            {
                "metadata": {"resourceVersion": resource_version},
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": coordinates.container,
                                    "image": coordinates.image,
                                }
                            ]
                        }
                    }
                },
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        updated = self._json(
            self.transport.request(
                "PATCH",
                coordinates.deployment_url,
                headers=headers,
                body=patch,
                content_type="application/strategic-merge-patch+json",
            ),
            "Kubernetes deployment update",
        )
        updated_metadata = self._metadata(updated, "Kubernetes deployment update")
        if (
            updated_metadata.get("uid") != coordinates.deployment_uid
            or self._container_image(updated, coordinates.container) != coordinates.image
        ):
            raise AdapterError(
                "Kubernetes deployment update outcome is uncertain and requires readback"
            )
        return self.operation_receipt(context, resource_version)

    def readback(
        self, context: AdapterContext, receipt: MutationReceipt
    ) -> ProviderReadback:
        coordinates = self._coordinates(context)
        headers = self._headers(coordinates)
        try:
            response = self.transport.request(
                "GET", coordinates.deployment_url, headers=headers
            )
        except AdapterError:
            return ProviderReadback(
                "unknown",
                receipt.operation_id,
                None,
                {"destination": coordinates.destination},
            )
        deployment = self._json(response, "Kubernetes deployment readback")
        metadata = self._metadata(deployment, "Kubernetes deployment readback")
        if metadata.get("uid") != coordinates.deployment_uid:
            raise AdapterError("Kubernetes deployment identity differs")
        observed_image = self._container_image(deployment, coordinates.container)
        if observed_image != coordinates.image:
            status = "failed"
        else:
            status_data = deployment.get("status")
            spec = deployment.get("spec")
            if not isinstance(status_data, dict) or not isinstance(spec, dict):
                status = "unknown"
            else:
                generation = metadata.get("generation")
                observed_generation = status_data.get("observedGeneration")
                replicas = spec.get("replicas", 1)
                conditions = status_data.get("conditions")
                condition_map = {
                    item.get("type"): item
                    for item in conditions
                    if isinstance(item, dict) and isinstance(item.get("type"), str)
                } if isinstance(conditions, list) else {}
                progressing = condition_map.get("Progressing", {})
                available = condition_map.get("Available", {})
                if progressing.get("status") == "False":
                    status = "failed"
                elif (
                    not isinstance(generation, int)
                    or isinstance(generation, bool)
                    or not isinstance(observed_generation, int)
                    or isinstance(observed_generation, bool)
                    or not isinstance(replicas, int)
                    or isinstance(replicas, bool)
                    or replicas < 0
                ):
                    status = "unknown"
                elif (
                    observed_generation >= generation
                    and status_data.get("updatedReplicas", 0) == replicas
                    and status_data.get("availableReplicas", 0) == replicas
                    and (replicas == 0 or available.get("status") == "True")
                    and progressing.get("status") == "True"
                    and progressing.get("reason") == "NewReplicaSetAvailable"
                ):
                    status = "succeeded"
                else:
                    status = "pending"
        return ProviderReadback(
            status,
            receipt.operation_id,
            context.source_sha if status == "succeeded" else None,
            {
                "destination": coordinates.destination,
                "expected_image": coordinates.image,
                "observed_image": observed_image,
                "deployment_uid": coordinates.deployment_uid,
            },
        )
