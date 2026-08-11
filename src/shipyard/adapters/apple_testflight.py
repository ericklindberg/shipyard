from __future__ import annotations

import os
import re
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

from .apple import (
    _APPLE_API,
    _ENV_NAME,
    _RESOURCE_ID,
    _config_string,
    _relationship_id_or_related,
    _relationship_ids_or_related,
    _resource_data,
)
from .base import AdapterContext, AdapterError, ConnectionCheck, MutationReceipt, ProviderReadback
from .http import HttpTransport


@dataclass(frozen=True)
class _Coordinates:
    app_id: str
    build_id: str
    beta_group_id: str
    pre_release_version_id: str
    xcode_cloud_run_id: str
    bundle_id: str
    marketing_version: str
    build_number: str
    token_env: str

    @property
    def identity(self) -> str:
        return f"{self.app_id}:{self.build_id}:{self.beta_group_id}"


class TestFlightGroupAdapter:
    """Attach one source-bound App Store Connect build to one TestFlight group."""

    action = "appstoreconnect.testflight"
    _MAX_RELATIONSHIP_PAGES = 20

    def __init__(self, transport: HttpTransport) -> None:
        self.transport = transport

    @staticmethod
    def _coordinates(context: AdapterContext) -> _Coordinates:
        identifiers = {
            key: _config_string(context, key)
            for key in (
                "app_id",
                "build_id",
                "beta_group_id",
                "pre_release_version_id",
                "xcode_cloud_run_id",
            )
        }
        if any(_RESOURCE_ID.fullmatch(value) is None for value in identifiers.values()):
            raise AdapterError(
                "appstoreconnect.testflight requires conservative provider identifiers"
            )
        bundle_id = _config_string(context, "bundle_id")
        if (
            len(bundle_id) > 255
            or "." not in bundle_id
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]+", bundle_id) is None
        ):
            raise AdapterError("appstoreconnect.testflight bundle_id is invalid")
        marketing_version = _config_string(context, "marketing_version")
        build_number = _config_string(context, "build_number")
        if any(
            len(value) > 64 or any(character.isspace() for character in value)
            for value in (marketing_version, build_number)
        ):
            raise AdapterError("App Store Connect version identities are invalid")
        token_env = _config_string(context, "token_env")
        if _ENV_NAME.fullmatch(token_env) is None or not token_env.startswith("APPLE_"):
            raise AdapterError(
                "appstoreconnect.testflight token_env must use an APPLE_ variable"
            )
        configured_base = context.config.get("api_base", _APPLE_API)
        if not isinstance(configured_base, str) or configured_base.rstrip("/") != _APPLE_API:
            raise AdapterError(
                "appstoreconnect.testflight only connects to the official Apple API"
            )
        coordinates = _Coordinates(
            **identifiers,
            bundle_id=bundle_id,
            marketing_version=marketing_version,
            build_number=build_number,
            token_env=token_env,
        )
        if context.destination != coordinates.identity:
            raise AdapterError(
                "appstoreconnect.testflight destination does not match provider identifiers"
            )
        return coordinates

    @staticmethod
    def _headers(coordinates: _Coordinates) -> dict[str, str]:
        token = os.environ.get(coordinates.token_env)
        if not token:
            raise AdapterError(
                f"credential environment variable {coordinates.token_env} is not set"
            )
        if "\x00" in token or "\r" in token or "\n" in token:
            raise AdapterError("Apple credential environment variable is malformed")
        return {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    def _get(
        self,
        coordinates: _Coordinates,
        headers: dict[str, str],
        resource_type: str,
        resource_id: str,
        operation: str,
    ) -> dict[str, object]:
        resource = _resource_data(
            self.transport.request(
                "GET",
                f"{_APPLE_API}/v1/{resource_type}/{quote(resource_id, safe='')}",
                headers=headers,
            ),
            operation,
        )
        if resource.get("id") != resource_id:
            raise AdapterError(f"{operation} returned a different resource id")
        return resource

    def _identity(self, context: AdapterContext) -> tuple[_Coordinates, dict[str, str]]:
        coordinates = self._coordinates(context)
        headers = self._headers(coordinates)
        app = self._get(coordinates, headers, "apps", coordinates.app_id, "Apple app verification")
        app_attributes = app.get("attributes")
        if (
            app.get("type") != "apps"
            or not isinstance(app_attributes, dict)
            or app_attributes.get("bundleId") != coordinates.bundle_id
        ):
            raise AdapterError("Apple app verification returned a different bundle identity")

        build = self._get(
            coordinates,
            headers,
            "builds",
            coordinates.build_id,
            "App Store Connect build verification",
        )
        build_attributes = build.get("attributes")
        if (
            build.get("type") != "builds"
            or not isinstance(build_attributes, dict)
            or build_attributes.get("version") != coordinates.build_number
            or build_attributes.get("processingState") != "VALID"
        ):
            raise AdapterError("App Store Connect build identity is not valid")
        build_app_id = _relationship_id_or_related(
            self.transport,
            headers,
            build,
            parent_type="builds",
            parent_id=coordinates.build_id,
            relationship="app",
            expected_type="apps",
            operation="App Store Connect build app relationship verification",
        )
        build_version_id = _relationship_id_or_related(
            self.transport,
            headers,
            build,
            parent_type="builds",
            parent_id=coordinates.build_id,
            relationship="preReleaseVersion",
            expected_type="preReleaseVersions",
            operation="App Store Connect build version relationship verification",
        )
        if (
            build_app_id != coordinates.app_id
            or build_version_id != coordinates.pre_release_version_id
        ):
            raise AdapterError("App Store Connect build identity is not valid")

        version = self._get(
            coordinates,
            headers,
            "preReleaseVersions",
            coordinates.pre_release_version_id,
            "App Store Connect version verification",
        )
        version_attributes = version.get("attributes")
        if (
            version.get("type") != "preReleaseVersions"
            or not isinstance(version_attributes, dict)
            or version_attributes.get("version") != coordinates.marketing_version
        ):
            raise AdapterError("App Store Connect marketing version identity differs")

        build_run = self._get(
            coordinates,
            headers,
            "ciBuildRuns",
            coordinates.xcode_cloud_run_id,
            "Xcode Cloud source build verification",
        )
        run_attributes = build_run.get("attributes")
        source_commit = (
            run_attributes.get("sourceCommit")
            if isinstance(run_attributes, dict)
            else None
        )
        if (
            build_run.get("type") != "ciBuildRuns"
            or not isinstance(source_commit, dict)
            or source_commit.get("commitSha") != context.source_sha
        ):
            raise AdapterError(
                "Xcode Cloud build does not bind the App Store build to the approved source SHA"
            )
        linked_builds = _relationship_ids_or_related(
            self.transport,
            headers,
            build_run,
            parent_type="ciBuildRuns",
            parent_id=coordinates.xcode_cloud_run_id,
            relationship="builds",
            expected_type="builds",
            operation="Xcode Cloud build relationship verification",
        )
        if coordinates.build_id not in linked_builds:
            raise AdapterError(
                "Xcode Cloud build does not bind the App Store build to the approved source SHA"
            )

        group = self._get(
            coordinates,
            headers,
            "betaGroups",
            coordinates.beta_group_id,
            "TestFlight beta group verification",
        )
        if group.get("type") != "betaGroups":
            raise AdapterError(
                "TestFlight beta group does not belong to the configured app"
            )
        group_app_id = _relationship_id_or_related(
            self.transport,
            headers,
            group,
            parent_type="betaGroups",
            parent_id=coordinates.beta_group_id,
            relationship="app",
            expected_type="apps",
            operation="TestFlight beta group app relationship verification",
        )
        if group_app_id != coordinates.app_id:
            raise AdapterError(
                "TestFlight beta group does not belong to the configured app"
            )
        return coordinates, headers

    def check(self, context: AdapterContext) -> ConnectionCheck:
        coordinates, _ = self._identity(context)
        return ConnectionCheck(
            "verified",
            context.provider,
            self.action,
            coordinates.identity,
            {
                "app_id": coordinates.app_id,
                "build_id": coordinates.build_id,
                "beta_group_id": coordinates.beta_group_id,
                "bundle_id": coordinates.bundle_id,
                "marketing_version": coordinates.marketing_version,
                "build_number": coordinates.build_number,
                "xcode_cloud_run_id": coordinates.xcode_cloud_run_id,
                "source_sha": context.source_sha,
            },
        )

    def execute(self, context: AdapterContext) -> MutationReceipt:
        coordinates, headers = self._identity(context)
        response = self.transport.request(
            "POST",
            f"{_APPLE_API}/v1/betaGroups/{quote(coordinates.beta_group_id, safe='')}"
            "/relationships/builds",
            headers=headers,
            body={"data": [{"type": "builds", "id": coordinates.build_id}]},
        )
        if response.status != 204:
            raise AdapterError(f"TestFlight build attachment failed with status {response.status}")
        return MutationReceipt(
            context.provider,
            self.action,
            f"{coordinates.beta_group_id}:{coordinates.build_id}",
            context.source_sha,
            {
                "app_id": coordinates.app_id,
                "build_id": coordinates.build_id,
                "beta_group_id": coordinates.beta_group_id,
                "xcode_cloud_run_id": coordinates.xcode_cloud_run_id,
                "http_status": response.status,
            },
        )

    def _contains_build(
        self, coordinates: _Coordinates, headers: dict[str, str]
    ) -> tuple[bool, int]:
        expected_path = (
            f"/v1/betaGroups/{quote(coordinates.beta_group_id, safe='')}/relationships/builds"
        )
        url = f"{_APPLE_API}{expected_path}"
        seen: set[str] = set()
        for page_number in range(1, self._MAX_RELATIONSHIP_PAGES + 1):
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
                raise AdapterError("TestFlight relationship pagination URL is invalid")
            seen.add(url)
            response = self.transport.request("GET", url, headers=headers)
            if not 200 <= response.status < 300:
                raise AdapterError(
                    f"TestFlight relationship readback failed with status {response.status}"
                )
            data = response.payload.get("data")
            if not isinstance(data, list):
                raise AdapterError("TestFlight relationship readback is malformed")
            for item in data:
                if (
                    not isinstance(item, dict)
                    or item.get("type") != "builds"
                    or not isinstance(item.get("id"), str)
                ):
                    raise AdapterError("TestFlight relationship readback is malformed")
                if item["id"] == coordinates.build_id:
                    return True, page_number
            links = response.payload.get("links")
            if links is None:
                return False, page_number
            if not isinstance(links, dict):
                raise AdapterError("TestFlight relationship pagination is malformed")
            next_url = links.get("next")
            if next_url is None:
                return False, page_number
            if not isinstance(next_url, str) or not next_url:
                raise AdapterError("TestFlight relationship pagination is malformed")
            url = next_url
        raise AdapterError("TestFlight relationship pagination exceeded the page limit")

    def readback(
        self, context: AdapterContext, receipt: MutationReceipt
    ) -> ProviderReadback:
        coordinates = self._coordinates(context)
        expected_operation = f"{coordinates.beta_group_id}:{coordinates.build_id}"
        if (
            receipt.provider != context.provider
            or receipt.action != self.action
            or receipt.operation_id != expected_operation
            or receipt.submitted_sha != context.source_sha
        ):
            return ProviderReadback("failed", receipt.operation_id, None, {"identity_match": False})
        coordinates, headers = self._identity(context)
        found, pages = self._contains_build(coordinates, headers)
        return ProviderReadback(
            "succeeded" if found else "pending",
            receipt.operation_id,
            context.source_sha,
            {
                "app_id": coordinates.app_id,
                "build_id": coordinates.build_id,
                "beta_group_id": coordinates.beta_group_id,
                "pages": pages,
                "relationship_present": found,
            },
        )
