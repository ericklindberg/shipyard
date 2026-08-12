from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

from .adapters.apple import (
    _APPLE_API,
    _RESOURCE_ID,
    XcodeCloudRunDiscovery,
    XcodeCloudSourceDiscovery,
    _relationship_id_or_related,
    _relationship_ids_or_related,
    _resource_data,
)
from .adapters.base import AdapterContext, AdapterError, ProviderReadback
from .adapters.http import HttpTransport
from .apple_auth import (
    APPLE_AUTH_OPTION_KEYS,
    apple_headers,
    validate_apple_credential_references,
)
from .candidate import canonical_repository_identity
from .gates import GateAttestation, GateError, verify_gate_evidence

_BUNDLE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{2,254}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MAX_PAGES = 20


@dataclass(frozen=True)
class AppleReleaseCoordinates:
    source_sha: str
    workflow_id: str
    repository_id: str
    repository_identity: str
    git_reference_id: str
    git_reference_name: str
    app_id: str
    bundle_id: str
    run_id: str
    run_number: str
    run_status: str
    build_id: str
    build_number: str
    processing_state: str
    expired: bool
    pre_release_version_id: str
    marketing_version: str
    beta_group_id: str
    beta_group_name: str
    beta_group_internal: bool
    relationship_present: bool
    internal_build_state: str | None
    external_build_state: str | None

    @property
    def operation_destination(self) -> str:
        return f"{self.app_id}:{self.build_id}:{self.beta_group_id}"

    def payload(self) -> dict[str, object]:
        return {
            "schema_version": "shipyard.apple-release-observation/v1",
            "source_sha": self.source_sha,
            "workflow_id": self.workflow_id,
            "repository_id": self.repository_id,
            "repository_identity": self.repository_identity,
            "git_reference_id": self.git_reference_id,
            "git_reference_name": self.git_reference_name,
            "app_id": self.app_id,
            "bundle_id": self.bundle_id,
            "run_id": self.run_id,
            "run_number": self.run_number,
            "run_status": self.run_status,
            "build_id": self.build_id,
            "build_number": self.build_number,
            "processing_state": self.processing_state,
            "expired": self.expired,
            "pre_release_version_id": self.pre_release_version_id,
            "marketing_version": self.marketing_version,
            "beta_group_id": self.beta_group_id,
            "beta_group_name": self.beta_group_name,
            "beta_group_internal": self.beta_group_internal,
            "relationship_present": self.relationship_present,
            "internal_build_state": self.internal_build_state,
            "external_build_state": self.external_build_state,
            "read_only": True,
        }

    @property
    def digest(self) -> str:
        canonical = json.dumps(self.payload(), separators=(",", ":"), sort_keys=True).encode()
        return hashlib.sha256(canonical).hexdigest()


class AppleReleaseResolver:
    """Resolve stable Apple release inputs into exact current provider coordinates."""

    def __init__(self, transport: HttpTransport) -> None:
        self.transport = transport
        self.xcode = XcodeCloudRunDiscovery(transport)
        self.source = XcodeCloudSourceDiscovery(transport)

    @staticmethod
    def _require_string(config: Mapping[str, object], key: str) -> str:
        value = config.get(key)
        if not isinstance(value, str) or not value.strip():
            raise AdapterError(f"Apple release project {key} is required")
        if any(character in value for character in ("\x00", "\r", "\n")):
            raise AdapterError(f"Apple release project {key} must be one line")
        return value.strip()

    @staticmethod
    def _page_url(
        url: str,
        *,
        expected_path: str,
        seen: set[str],
        operation: str,
    ) -> None:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.netloc != "api.appstoreconnect.apple.com"
            or parsed.path != expected_path
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or url in seen
        ):
            raise AdapterError(f"{operation} pagination URL is invalid")

    def _pages(
        self,
        url: str,
        headers: dict[str, str],
        *,
        expected_path: str,
        expected_type: str,
        operation: str,
    ) -> list[dict[str, object]]:
        seen: set[str] = set()
        result: list[dict[str, object]] = []
        for _page in range(_MAX_PAGES):
            self._page_url(
                url,
                expected_path=expected_path,
                seen=seen,
                operation=operation,
            )
            seen.add(url)
            response = self.transport.request("GET", url, headers=headers)
            if not 200 <= response.status < 300:
                raise AdapterError(f"{operation} failed with status {response.status}")
            data = response.payload.get("data")
            if not isinstance(data, list):
                raise AdapterError(f"{operation} returned malformed data")
            for resource in data:
                if (
                    not isinstance(resource, dict)
                    or resource.get("type") != expected_type
                    or not isinstance(resource.get("id"), str)
                ):
                    raise AdapterError(f"{operation} returned malformed data")
                result.append(resource)
            links = response.payload.get("links")
            if links is None:
                return result
            if not isinstance(links, dict):
                raise AdapterError(f"{operation} returned malformed pagination")
            next_url = links.get("next")
            if next_url is None:
                return result
            if not isinstance(next_url, str) or not next_url:
                raise AdapterError(f"{operation} returned malformed pagination")
            url = next_url
        raise AdapterError(f"{operation} pagination exceeded the page limit")

    @staticmethod
    def _exactly_one(
        resources: Iterable[dict[str, object]],
        *,
        label: str,
    ) -> dict[str, object]:
        selected = list(resources)
        if len(selected) != 1:
            raise AdapterError(f"expected exactly one {label}; found {len(selected)}")
        return selected[0]

    def _resource(
        self,
        headers: dict[str, str],
        resource_type: str,
        resource_id: str,
        operation: str,
    ) -> dict[str, object]:
        if _RESOURCE_ID.fullmatch(resource_id) is None:
            raise AdapterError(f"{operation} resource id is invalid")
        resource = _resource_data(
            self.transport.request(
                "GET",
                f"{_APPLE_API}/v1/{resource_type}/{quote(resource_id, safe='')}",
                headers=headers,
            ),
            operation,
        )
        if resource.get("type") != resource_type or resource.get("id") != resource_id:
            raise AdapterError(f"{operation} returned a different resource identity")
        return resource

    def _app(
        self, headers: dict[str, str], bundle_id: str
    ) -> dict[str, object]:
        expected_path = "/v1/apps"
        resources = self._pages(
            f"{_APPLE_API}{expected_path}?filter[bundleId]={quote(bundle_id, safe='')}&limit=200",
            headers,
            expected_path=expected_path,
            expected_type="apps",
            operation="App Store Connect app discovery",
        )
        def matches_bundle(resource: dict[str, object]) -> bool:
            attributes = resource.get("attributes")
            return isinstance(attributes, dict) and attributes.get("bundleId") == bundle_id

        return self._exactly_one(
            (resource for resource in resources if matches_bundle(resource)),
            label=f"App Store Connect app for bundle {bundle_id}",
        )

    def _build(
        self,
        headers: dict[str, str],
        run_id: str,
        source_sha: str,
        expected_run_number: str,
        expected_build_number: str | None,
    ) -> dict[str, object]:
        run = self._resource(headers, "ciBuildRuns", run_id, "Xcode Cloud run verification")
        run_attributes = run.get("attributes")
        source_commit = (
            run_attributes.get("sourceCommit")
            if isinstance(run_attributes, dict)
            else None
        )
        if (
            not isinstance(run_attributes, dict)
            or not isinstance(source_commit, dict)
            or source_commit.get("commitSha") != source_sha
            or run_attributes.get("executionProgress") != "COMPLETE"
            or run_attributes.get("completionStatus") != "SUCCEEDED"
            or str(run_attributes.get("number")) != expected_run_number
        ):
            raise AdapterError("Xcode Cloud run identity changed after exact-SHA discovery")
        build_ids = _relationship_ids_or_related(
            self.transport,
            headers,
            run,
            parent_type="ciBuildRuns",
            parent_id=run_id,
            relationship="builds",
            expected_type="builds",
            operation="Xcode Cloud run build relationship",
        )
        builds = [
            self._resource(headers, "builds", build_id, "App Store Connect build discovery")
            for build_id in sorted(build_ids)
        ]
        valid: list[dict[str, object]] = []
        for build in builds:
            attributes = build.get("attributes")
            if not isinstance(attributes, dict):
                raise AdapterError(
                    "App Store Connect build discovery returned malformed attributes"
                )
            version = attributes.get("version")
            if (
                attributes.get("processingState") == "VALID"
                and attributes.get("expired") is False
                and isinstance(version, (str, int))
                and not isinstance(version, bool)
                and bool(str(version))
                and (
                    expected_build_number is None
                    or str(version) == expected_build_number
                )
            ):
                valid.append(build)
        return self._exactly_one(valid, label="valid nonexpired build linked to exact Xcode run")

    def _group(
        self,
        headers: dict[str, str],
        app_id: str,
        group_name: str,
    ) -> dict[str, object]:
        expected_path = "/v1/betaGroups"
        resources = self._pages(
            f"{_APPLE_API}{expected_path}?filter[app]={quote(app_id, safe='')}&limit=200",
            headers,
            expected_path=expected_path,
            expected_type="betaGroups",
            operation="TestFlight beta group discovery",
        )
        def matches_name(resource: dict[str, object]) -> bool:
            attributes = resource.get("attributes")
            return isinstance(attributes, dict) and attributes.get("name") == group_name

        return self._exactly_one(
            (resource for resource in resources if matches_name(resource)),
            label=f"TestFlight beta group named {group_name}",
        )

    def _relationship_contains(
        self,
        headers: dict[str, str],
        group_id: str,
        build_id: str,
    ) -> bool:
        expected_path = f"/v1/betaGroups/{quote(group_id, safe='')}/relationships/builds"
        resources = self._pages(
            f"{_APPLE_API}{expected_path}?limit=200",
            headers,
            expected_path=expected_path,
            expected_type="builds",
            operation="TestFlight beta group membership readback",
        )
        return any(resource.get("id") == build_id for resource in resources)

    def _beta_states(
        self, headers: dict[str, str], build_id: str
    ) -> tuple[str | None, str | None]:
        response = self.transport.request(
            "GET",
            f"{_APPLE_API}/v1/builds/{quote(build_id, safe='')}/buildBetaDetail",
            headers=headers,
        )
        detail = _resource_data(response, "TestFlight beta state readback")
        if detail.get("type") != "buildBetaDetails":
            raise AdapterError("TestFlight beta state readback returned a different resource type")
        attributes = detail.get("attributes")
        if not isinstance(attributes, dict):
            raise AdapterError("TestFlight beta state readback returned malformed attributes")
        internal = attributes.get("internalBuildState")
        external = attributes.get("externalBuildState")
        if internal is not None and not isinstance(internal, str):
            raise AdapterError("TestFlight internal beta state is malformed")
        if external is not None and not isinstance(external, str):
            raise AdapterError("TestFlight external beta state is malformed")
        return internal, external

    def resolve(
        self,
        *,
        source_sha: str,
        config: Mapping[str, object],
    ) -> AppleReleaseCoordinates:
        if re.fullmatch(r"[0-9a-f]{40}", source_sha) is None:
            raise AdapterError("Apple release resolution requires a full source SHA")
        workflow_id = self._require_string(config, "workflow_id")
        source_remote = self._require_string(config, "source_remote")
        bundle_id = self._require_string(config, "bundle_id")
        group_name = self._require_string(config, "beta_group_name")
        if _RESOURCE_ID.fullmatch(workflow_id) is None:
            raise AdapterError("Apple release project workflow_id is invalid")
        if _BUNDLE_ID.fullmatch(bundle_id) is None or "." not in bundle_id:
            raise AdapterError("Apple release project bundle_id is invalid")
        if len(group_name) > 255:
            raise AdapterError("Apple release project beta_group_name is too long")
        expected_build = config.get("expected_build_number")
        expected_version = config.get("expected_marketing_version")
        for key, value in (
            ("expected_build_number", expected_build),
            ("expected_marketing_version", expected_version),
        ):
            if value is not None and (
                not isinstance(value, str) or _VERSION.fullmatch(value) is None
            ):
                raise AdapterError(f"Apple release project {key} is invalid")
        credentials = {key: config[key] for key in APPLE_AUTH_OPTION_KEYS if key in config}
        headers = apple_headers(credentials)
        source = self.source.discover(
            workflow_id=workflow_id,
            source_sha=source_sha,
            config=credentials,
        )
        expected_repository = canonical_repository_identity(source_remote)
        observed_repositories = {
            identity
            for identity in (
                canonical_repository_identity(source.http_clone_url),
                canonical_repository_identity(source.ssh_clone_url),
            )
            if identity is not None
        }
        if (
            expected_repository is None
            or not observed_repositories
            or observed_repositories != {expected_repository}
        ):
            raise AdapterError(
                "Xcode Cloud workflow repository does not match Apple source_remote"
            )
        run_readback: ProviderReadback = self.xcode.discover(
            AdapterContext(
                "apple-release-resolve",
                source_sha,
                "apple",
                workflow_id,
                {"workflow_id": workflow_id, **credentials},
            )
        )
        run_id = run_readback.operation_id
        if run_readback.status != "succeeded":
            raise AdapterError(
                f"exact-SHA Xcode Cloud run is not successful: {run_readback.status}"
            )
        run_number = run_readback.evidence.get("build_number")
        if not isinstance(run_number, str) or not run_number:
            raise AdapterError("exact-SHA Xcode Cloud run number is malformed")
        app = self._app(headers, bundle_id)
        app_id = str(app["id"])
        build = self._build(
            headers,
            run_id,
            source_sha,
            run_number,
            str(expected_build) if expected_build is not None else None,
        )
        build_id = str(build["id"])
        build_attributes = build.get("attributes")
        assert isinstance(build_attributes, dict)
        build_app_id = _relationship_id_or_related(
            self.transport,
            headers,
            build,
            parent_type="builds",
            parent_id=build_id,
            relationship="app",
            expected_type="apps",
            operation="App Store Connect build app relationship",
        )
        version_id = _relationship_id_or_related(
            self.transport,
            headers,
            build,
            parent_type="builds",
            parent_id=build_id,
            relationship="preReleaseVersion",
            expected_type="preReleaseVersions",
            operation="App Store Connect build version relationship",
        )
        if build_app_id != app_id:
            raise AdapterError("exact-run build does not belong to the configured app")
        version = self._resource(
            headers,
            "preReleaseVersions",
            version_id,
            "App Store Connect pre-release version discovery",
        )
        version_attributes = version.get("attributes")
        if not isinstance(version_attributes, dict) or not isinstance(
            version_attributes.get("version"), str
        ):
            raise AdapterError("App Store Connect marketing version is malformed")
        marketing_version = version_attributes["version"]
        if expected_version is not None and marketing_version != expected_version:
            raise AdapterError("App Store Connect marketing version differs from expectation")
        group = self._group(headers, app_id, group_name)
        group_id = str(group["id"])
        group_app_id = _relationship_id_or_related(
            self.transport,
            headers,
            group,
            parent_type="betaGroups",
            parent_id=group_id,
            relationship="app",
            expected_type="apps",
            operation="TestFlight beta group app relationship",
        )
        if group_app_id != app_id:
            raise AdapterError("TestFlight beta group does not belong to the configured app")
        group_attributes = group.get("attributes")
        if not isinstance(group_attributes, dict) or not isinstance(
            group_attributes.get("isInternalGroup"), bool
        ):
            raise AdapterError("TestFlight beta group internal/external identity is malformed")
        relationship_present = self._relationship_contains(
            headers, group_id, build_id
        )
        internal_state, external_state = self._beta_states(headers, build_id)
        return AppleReleaseCoordinates(
            source_sha=source_sha,
            workflow_id=workflow_id,
            repository_id=source.repository_id,
            repository_identity=expected_repository,
            git_reference_id=source.git_reference_id,
            git_reference_name=source.git_reference_name,
            app_id=app_id,
            bundle_id=bundle_id,
            run_id=run_id,
            run_number=run_number,
            run_status=run_readback.status,
            build_id=build_id,
            build_number=str(build_attributes.get("version")),
            processing_state=str(build_attributes.get("processingState")),
            expired=bool(build_attributes.get("expired")),
            pre_release_version_id=version_id,
            marketing_version=marketing_version,
            beta_group_id=group_id,
            beta_group_name=group_name,
            beta_group_internal=group_attributes["isInternalGroup"],
            relationship_present=relationship_present,
            internal_build_state=internal_state,
            external_build_state=external_state,
        )


def render_testflight_playbook(
    coordinates: AppleReleaseCoordinates,
    *,
    credential_config: Mapping[str, object],
    name: str,
    target: str = "production",
    project_digest: str | None = None,
    apple_observation_digest: str | None = None,
    physical_device_attestation: GateAttestation | None = None,
) -> str:
    if coordinates.relationship_present:
        raise AdapterError(
            "resolved TestFlight group already contains the build; no mutation playbook is needed"
        )
    if not name or any(character in name for character in ("\x00", "\r", "\n")):
        raise AdapterError("release playbook name is invalid")
    credentials = {
        key: credential_config[key]
        for key in APPLE_AUTH_OPTION_KEYS
        if key in credential_config
    }
    validate_apple_credential_references(credentials)
    gate_config: dict[str, object] = {}
    if not coordinates.beta_group_internal:
        if (
            not isinstance(project_digest, str)
            or not project_digest
            or not isinstance(apple_observation_digest, str)
            or not apple_observation_digest
            or physical_device_attestation is None
            or physical_device_attestation.path is None
        ):
            raise AdapterError(
                "external TestFlight playbook requires a verified physical-device gate"
            )
        gate = physical_device_attestation
        try:
            verify_gate_evidence(gate)
        except GateError as exc:
            raise AdapterError(f"physical-device gate evidence is invalid: {exc}") from exc
        if (
            gate.gate != "physical-device"
            or gate.status != "passed"
            or gate.source_sha != coordinates.source_sha
            or gate.project_digest != project_digest
            or gate.apple_observation_digest != apple_observation_digest
            or gate.app_version != coordinates.marketing_version
            or gate.build_number != coordinates.build_number
        ):
            raise AdapterError(
                "physical-device gate does not match the external TestFlight release"
            )
        gate_config = {
            "physical_device_attestation": str(gate.path),
            "release_project_digest": project_digest,
            "apple_observation_digest": apple_observation_digest,
        }
    lines = [
        "# Generated from a read-only exact-SHA Apple release observation.",
        "# Credential values are not stored; only environment-variable references appear.",
        "schema_version = 2",
        f"name = {json.dumps(name)}",
        f"target = {json.dumps(target)}",
        'provider = "apple"',
        f"destination = {json.dumps(coordinates.operation_destination)}",
        "approval_quorum = 1",
        "",
        "[[steps]]",
        'id = "attach-testflight-group"',
        f"name = {json.dumps('Attach exact build to ' + coordinates.beta_group_name)}",
        'effect = "external"',
        'action = "appstoreconnect.testflight"',
        "",
        "[steps.config]",
    ]
    config: dict[str, object] = {
        "app_id": coordinates.app_id,
        "build_id": coordinates.build_id,
        "beta_group_id": coordinates.beta_group_id,
        "pre_release_version_id": coordinates.pre_release_version_id,
        "xcode_cloud_run_id": coordinates.run_id,
        "bundle_id": coordinates.bundle_id,
        "marketing_version": coordinates.marketing_version,
        "build_number": coordinates.build_number,
        **credentials,
        **gate_config,
    }
    for key, value in sorted(config.items()):
        lines.append(f"{key} = {json.dumps(value)}")
    return "\n".join(lines) + "\n"
