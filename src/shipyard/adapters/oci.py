from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from urllib.parse import quote

from .base import AdapterContext, AdapterError, ConnectionCheck, MutationReceipt, ProviderReadback
from .raw_http import RawHttpTransport, UrllibRawTransport

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REGISTRY = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?|\[[0-9a-fA-F:]+\])(?::[0-9]{1,5})?$"
)
_REPOSITORY = re.compile(
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$"
)
_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")
_ENV = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
_CONFIG_MEDIA_TYPES = {
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
}
_ACCEPT = ", ".join(sorted(_MEDIA_TYPES))


@dataclass(frozen=True)
class _Coordinates:
    registry: str
    repository: str
    manifest_digest: str
    target_tag: str
    token_env: str

    @property
    def destination(self) -> str:
        return f"{self.registry}/{self.repository}:{self.target_tag}"

    def manifest_url(self, reference: str) -> str:
        path = "/".join(quote(part, safe="") for part in self.repository.split("/"))
        return f"https://{self.registry}/v2/{path}/manifests/{quote(reference, safe=':')}"

    def blob_url(self, digest: str) -> str:
        path = "/".join(quote(part, safe="") for part in self.repository.split("/"))
        return f"https://{self.registry}/v2/{path}/blobs/{quote(digest, safe=':')}"


class OciPromotionAdapter:
    """Promote one verified OCI manifest digest to one target tag."""

    action = "oci.promote"

    def __init__(self, transport: RawHttpTransport | None = None) -> None:
        self.transport = transport or UrllibRawTransport()

    @staticmethod
    def _config_string(context: AdapterContext, name: str) -> str:
        value = context.config.get(name)
        if not isinstance(value, str) or not value.strip():
            raise AdapterError(f"oci.promote config requires {name}")
        return value.strip()

    @classmethod
    def _coordinates(cls, context: AdapterContext) -> _Coordinates:
        coordinates = _Coordinates(
            registry=cls._config_string(context, "registry"),
            repository=cls._config_string(context, "repository"),
            manifest_digest=cls._config_string(context, "manifest_digest"),
            target_tag=cls._config_string(context, "target_tag"),
            token_env=cls._config_string(context, "token_env"),
        )
        if (
            _REGISTRY.fullmatch(coordinates.registry) is None
            or "/" in coordinates.registry
            or "@" in coordinates.registry
        ):
            raise AdapterError("oci.promote registry must be a canonical HTTPS host")
        if _REPOSITORY.fullmatch(coordinates.repository) is None:
            raise AdapterError("oci.promote repository is invalid")
        if _DIGEST.fullmatch(coordinates.manifest_digest) is None:
            raise AdapterError("oci.promote requires an exact sha256 manifest digest")
        if _TAG.fullmatch(coordinates.target_tag) is None:
            raise AdapterError("oci.promote target tag is invalid")
        if (
            _ENV.fullmatch(coordinates.token_env) is None
            or not coordinates.token_env.startswith("OCI_")
        ):
            raise AdapterError("oci.promote token_env must use an OCI_ variable")
        if context.destination != coordinates.destination:
            raise AdapterError("oci.promote destination does not match registry coordinates")
        return coordinates

    @staticmethod
    def _headers(coordinates: _Coordinates) -> dict[str, str]:
        token = os.environ.get(coordinates.token_env)
        if not token:
            raise AdapterError(
                f"credential environment variable {coordinates.token_env} is not set"
            )
        if any(character in token for character in ("\x00", "\r", "\n")):
            raise AdapterError("OCI credential environment variable is malformed")
        return {"Authorization": f"Bearer {token}", "Accept": _ACCEPT}

    def _verify_source(
        self, coordinates: _Coordinates, headers: dict[str, str]
    ) -> None:
        response = self.transport.request(
            "HEAD",
            coordinates.manifest_url(coordinates.manifest_digest),
            headers=headers,
        )
        if response.status != 200:
            raise AdapterError("OCI source manifest verification failed")
        if response.headers.get("docker-content-digest") != coordinates.manifest_digest:
            raise AdapterError("OCI source manifest digest does not match approved digest")

    def _load_verified_manifest(
        self,
        context: AdapterContext,
        coordinates: _Coordinates,
        headers: dict[str, str],
    ) -> tuple[bytes, str]:
        self._verify_source(coordinates, headers)
        source = self.transport.request(
            "GET",
            coordinates.manifest_url(coordinates.manifest_digest),
            headers=headers,
        )
        media_type = source.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        observed_digest = source.headers.get("docker-content-digest")
        computed_digest = f"sha256:{hashlib.sha256(source.body).hexdigest()}"
        if (
            source.status != 200
            or media_type not in _MEDIA_TYPES
            or observed_digest != coordinates.manifest_digest
            or computed_digest != coordinates.manifest_digest
        ):
            raise AdapterError("OCI manifest body does not match approved digest")
        try:
            manifest = json.loads(source.body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise AdapterError("OCI manifest is not valid JSON") from exc
        descriptor = manifest.get("config") if isinstance(manifest, dict) else None
        if not isinstance(descriptor, dict):
            raise AdapterError("OCI image manifest omitted its config descriptor")
        config_digest = descriptor.get("digest")
        config_size = descriptor.get("size")
        config_media_type = descriptor.get("mediaType")
        if (
            not isinstance(config_digest, str)
            or _DIGEST.fullmatch(config_digest) is None
            or not isinstance(config_size, int)
            or isinstance(config_size, bool)
            or config_size < 0
            or config_media_type not in _CONFIG_MEDIA_TYPES
        ):
            raise AdapterError("OCI image config descriptor is invalid")
        config_response = self.transport.request(
            "GET", coordinates.blob_url(config_digest), headers=headers
        )
        returned_media_type = (
            config_response.headers.get("content-type", "")
            .split(";", 1)[0]
            .strip()
            .lower()
        )
        if (
            config_response.status != 200
            or returned_media_type != config_media_type
            or len(config_response.body) != config_size
            or f"sha256:{hashlib.sha256(config_response.body).hexdigest()}"
            != config_digest
        ):
            raise AdapterError("OCI image config does not match its manifest descriptor")
        try:
            image_config = json.loads(config_response.body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise AdapterError("OCI image config is not valid JSON") from exc
        config = image_config.get("config") if isinstance(image_config, dict) else None
        labels = config.get("Labels") if isinstance(config, dict) else None
        if (
            not isinstance(labels, dict)
            or labels.get("org.opencontainers.image.revision") != context.source_sha
        ):
            raise AdapterError("OCI image source revision does not match approved source SHA")
        return source.body, media_type

    def check(self, context: AdapterContext) -> ConnectionCheck:
        coordinates = self._coordinates(context)
        headers = self._headers(coordinates)
        self._load_verified_manifest(context, coordinates, headers)
        return ConnectionCheck(
            "verified",
            context.provider,
            self.action,
            coordinates.destination,
            {
                "manifest_digest": coordinates.manifest_digest,
                "repository": f"{coordinates.registry}/{coordinates.repository}",
                "target_tag": coordinates.target_tag,
            },
        )

    def execute(self, context: AdapterContext) -> MutationReceipt:
        coordinates = self._coordinates(context)
        headers = self._headers(coordinates)
        manifest, media_type = self._load_verified_manifest(
            context, coordinates, headers
        )
        promoted = self.transport.request(
            "PUT",
            coordinates.manifest_url(coordinates.target_tag),
            headers={"Authorization": headers["Authorization"], "Accept": _ACCEPT},
            body=manifest,
            content_type=media_type,
        )
        if (
            promoted.status != 201
            or promoted.headers.get("docker-content-digest")
            != coordinates.manifest_digest
        ):
            raise AdapterError(
                "OCI tag promotion outcome is uncertain and requires authoritative readback"
            )
        operation_id = "oci-" + hashlib.sha256(
            (
                f"{coordinates.destination}\0{coordinates.manifest_digest}"
            ).encode()
        ).hexdigest()[:24]
        return MutationReceipt(
            context.provider,
            self.action,
            operation_id,
            context.source_sha,
            {
                "destination": coordinates.destination,
                "manifest_digest": coordinates.manifest_digest,
                "target_tag": coordinates.target_tag,
            },
        )

    def readback(
        self, context: AdapterContext, receipt: MutationReceipt
    ) -> ProviderReadback:
        coordinates = self._coordinates(context)
        headers = self._headers(coordinates)
        try:
            response = self.transport.request(
                "HEAD",
                coordinates.manifest_url(coordinates.target_tag),
                headers=headers,
            )
        except AdapterError:
            return ProviderReadback(
                "unknown",
                receipt.operation_id,
                None,
                {"destination": coordinates.destination},
            )
        observed_digest = response.headers.get("docker-content-digest")
        if response.status != 200 or _DIGEST.fullmatch(observed_digest or "") is None:
            status = "unknown"
        elif observed_digest == coordinates.manifest_digest:
            status = "succeeded"
        else:
            status = "failed"
        return ProviderReadback(
            status,
            receipt.operation_id,
            context.source_sha if status == "succeeded" else None,
            {
                "destination": coordinates.destination,
                "expected_manifest_digest": coordinates.manifest_digest,
                "observed_manifest_digest": observed_digest or "",
            },
        )
