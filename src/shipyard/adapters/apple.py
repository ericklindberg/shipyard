from __future__ import annotations

import re
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlsplit

from ..apple_auth import apple_headers, validate_apple_credential_references
from ..runtime import resolve_executable, sanitized_environment
from .base import (
    AdapterContext,
    AdapterError,
    AdapterStatus,
    ConnectionCheck,
    MutationReceipt,
    ProviderReadback,
)
from .http import HttpResponse, HttpTransport

_APPLE_API = "https://api.appstoreconnect.apple.com"
_RESOURCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
_NAMED_REMOTE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_FAILURE_COMPLETIONS = {"FAILED", "ERRORED", "CANCELED", "SKIPPED"}


def _config_string(context: AdapterContext, key: str) -> str:
    value = context.config.get(key)
    if not isinstance(value, str) or not value:
        raise AdapterError(f"{context.provider} {key} is required")
    return value


def _resource_data(response: HttpResponse, operation: str) -> dict[str, object]:
    if not 200 <= response.status < 300:
        raise AdapterError(f"{operation} failed with status {response.status}")
    data = response.payload.get("data")
    if not isinstance(data, dict):
        raise AdapterError(f"{operation} returned malformed resource data")
    return data


def _relationship_id_or_related(
    transport: HttpTransport,
    headers: dict[str, str],
    resource: dict[str, object],
    *,
    parent_type: str,
    parent_id: str,
    relationship: str,
    expected_type: str,
    operation: str,
) -> str:
    relationships = resource.get("relationships")
    if relationships is not None and not isinstance(relationships, dict):
        raise AdapterError(f"{operation} returned malformed relationship data")
    entry = relationships.get(relationship) if isinstance(relationships, dict) else None
    if entry is not None and not isinstance(entry, dict):
        raise AdapterError(f"{operation} returned malformed relationship data")
    data = entry.get("data") if isinstance(entry, dict) else None
    if data is not None:
        if not isinstance(data, dict) or data.get("type") != expected_type:
            raise AdapterError(f"{operation} returned malformed relationship data")
        identifier = data.get("id")
        if not isinstance(identifier, str):
            raise AdapterError(f"{operation} returned malformed relationship data")
        return identifier
    response = transport.request(
        "GET",
        f"{_APPLE_API}/v1/{quote(parent_type, safe='')}/{quote(parent_id, safe='')}"
        f"/{quote(relationship, safe='')}",
        headers=headers,
    )
    related = _resource_data(response, operation)
    identifier = related.get("id")
    if related.get("type") != expected_type or not isinstance(identifier, str):
        raise AdapterError(f"{operation} returned malformed relationship data")
    return identifier


def _inline_relationship_id(
    resource: dict[str, object], relationship: str, expected_type: str
) -> str | None:
    relationships = resource.get("relationships")
    if relationships is None:
        return None
    if not isinstance(relationships, dict):
        raise AdapterError("App Store Connect returned malformed relationships")
    if relationship not in relationships:
        return None
    entry = relationships[relationship]
    if not isinstance(entry, dict):
        raise AdapterError("App Store Connect returned malformed relationship data")
    data = entry.get("data")
    if data is None:
        return None
    if (
        not isinstance(data, dict)
        or data.get("type") != expected_type
        or not isinstance(data.get("id"), str)
        or _RESOURCE_ID.fullmatch(data["id"]) is None
    ):
        raise AdapterError("App Store Connect returned malformed relationship data")
    return data["id"]


def _relationship_ids_or_related(
    transport: HttpTransport,
    headers: dict[str, str],
    resource: dict[str, object],
    *,
    parent_type: str,
    parent_id: str,
    relationship: str,
    expected_type: str,
    operation: str,
    max_pages: int = 20,
) -> set[str]:
    relationships = resource.get("relationships")
    if relationships is not None and not isinstance(relationships, dict):
        raise AdapterError(f"{operation} returned malformed relationship data")
    entry = relationships.get(relationship) if isinstance(relationships, dict) else None
    if entry is not None and not isinstance(entry, dict):
        raise AdapterError(f"{operation} returned malformed relationship data")
    data = entry.get("data") if isinstance(entry, dict) else None
    if isinstance(data, list):
        result: set[str] = set()
        for item in data:
            if (
                not isinstance(item, dict)
                or item.get("type") != expected_type
                or not isinstance(item.get("id"), str)
            ):
                raise AdapterError(f"{operation} returned malformed relationship data")
            result.add(item["id"])
        return result
    if data is not None:
        raise AdapterError(f"{operation} returned malformed relationship data")

    expected_path = (
        f"/v1/{quote(parent_type, safe='')}/{quote(parent_id, safe='')}"
        f"/{quote(relationship, safe='')}"
    )
    url = f"{_APPLE_API}{expected_path}"
    seen: set[str] = set()
    result = set()
    for _page in range(max_pages):
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
        seen.add(url)
        response = transport.request("GET", url, headers=headers)
        if not 200 <= response.status < 300:
            raise AdapterError(f"{operation} failed with status {response.status}")
        page_data = response.payload.get("data")
        if not isinstance(page_data, list):
            raise AdapterError(f"{operation} returned malformed relationship data")
        for item in page_data:
            if (
                not isinstance(item, dict)
                or item.get("type") != expected_type
                or not isinstance(item.get("id"), str)
            ):
                raise AdapterError(f"{operation} returned malformed relationship data")
            result.add(item["id"])
        links = response.payload.get("links")
        if links is None:
            return result
        if not isinstance(links, dict):
            raise AdapterError(f"{operation} pagination is malformed")
        next_url = links.get("next")
        if next_url is None:
            return result
        if not isinstance(next_url, str) or not next_url:
            raise AdapterError(f"{operation} pagination is malformed")
        url = next_url
    raise AdapterError(f"{operation} pagination exceeded the page limit")


def _relationship_resources_or_related(
    transport: HttpTransport,
    headers: dict[str, str],
    resource: dict[str, object],
    *,
    parent_type: str,
    parent_id: str,
    relationship: str,
    expected_type: str,
    operation: str,
    max_pages: int = 20,
) -> list[dict[str, object]]:
    relationships = resource.get("relationships")
    if relationships is not None and not isinstance(relationships, dict):
        raise AdapterError(f"{operation} returned malformed relationship data")
    entry = relationships.get(relationship) if isinstance(relationships, dict) else None
    if entry is not None and not isinstance(entry, dict):
        raise AdapterError(f"{operation} returned malformed relationship data")
    data = entry.get("data") if isinstance(entry, dict) else None
    if isinstance(data, list):
        inline: list[dict[str, object]] = []
        seen_ids: set[str] = set()
        for item in data:
            if (
                not isinstance(item, dict)
                or item.get("type") != expected_type
                or not isinstance(item.get("id"), str)
                or _RESOURCE_ID.fullmatch(item["id"]) is None
                or item["id"] in seen_ids
            ):
                raise AdapterError(f"{operation} returned malformed relationship data")
            seen_ids.add(item["id"])
            inline.append(item)
        if all(isinstance(item.get("attributes"), dict) for item in inline):
            return inline
    elif data is not None:
        raise AdapterError(f"{operation} returned malformed relationship data")

    expected_path = (
        f"/v1/{quote(parent_type, safe='')}/{quote(parent_id, safe='')}"
        f"/{quote(relationship, safe='')}"
    )
    url = f"{_APPLE_API}{expected_path}"
    seen_urls: set[str] = set()
    seen_ids: set[str] = set()
    result: list[dict[str, object]] = []
    for _page in range(max_pages):
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.netloc != "api.appstoreconnect.apple.com"
            or parsed.path != expected_path
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or url in seen_urls
        ):
            raise AdapterError(f"{operation} pagination URL is invalid")
        seen_urls.add(url)
        response = transport.request("GET", url, headers=headers)
        if not 200 <= response.status < 300:
            raise AdapterError(f"{operation} failed with status {response.status}")
        page_data = response.payload.get("data")
        if not isinstance(page_data, list):
            raise AdapterError(f"{operation} returned malformed relationship data")
        for item in page_data:
            if (
                not isinstance(item, dict)
                or item.get("type") != expected_type
                or not isinstance(item.get("id"), str)
                or _RESOURCE_ID.fullmatch(item["id"]) is None
                or item["id"] in seen_ids
            ):
                raise AdapterError(f"{operation} returned malformed relationship data")
            seen_ids.add(item["id"])
            result.append(item)
        links = response.payload.get("links")
        if links is None:
            return result
        if not isinstance(links, dict):
            raise AdapterError(f"{operation} pagination is malformed")
        next_url = links.get("next")
        if next_url is None:
            return result
        if not isinstance(next_url, str) or not next_url:
            raise AdapterError(f"{operation} pagination is malformed")
        url = next_url
    raise AdapterError(f"{operation} pagination exceeded the page limit")


@dataclass(frozen=True)
class XcodeCloudSourceCoordinates:
    workflow_id: str
    repository_id: str
    git_reference_id: str
    git_reference_name: str
    repository_owner: str
    repository_name: str
    http_clone_url: str | None
    ssh_clone_url: str | None

    def evidence(self) -> dict[str, object]:
        return {
            "workflow_id": self.workflow_id,
            "repository_id": self.repository_id,
            "git_reference_id": self.git_reference_id,
            "git_reference_name": self.git_reference_name,
            "repository_owner": self.repository_owner,
            "repository_name": self.repository_name,
            "http_clone_url": self.http_clone_url,
            "ssh_clone_url": self.ssh_clone_url,
            "read_only": True,
        }


class XcodeCloudSourceDiscovery:
    """Resolve a workflow's exact immutable candidate reference without mutation."""

    def __init__(self, transport: HttpTransport) -> None:
        self.transport = transport

    @staticmethod
    def _headers(config: Mapping[str, object]) -> dict[str, str]:
        return apple_headers(config)

    @staticmethod
    def _optional_url(attributes: dict[str, object], key: str) -> str | None:
        value = attributes.get(key)
        if value is None:
            return None
        if not isinstance(value, str) or not value or any(ch in value for ch in "\x00\r\n"):
            raise AdapterError(f"Xcode Cloud repository {key} is malformed")
        return value

    def discover(
        self,
        *,
        workflow_id: str,
        source_sha: str,
        config: Mapping[str, object],
    ) -> XcodeCloudSourceCoordinates:
        if _RESOURCE_ID.fullmatch(workflow_id) is None:
            raise AdapterError("Xcode Cloud source discovery workflow_id is invalid")
        if re.fullmatch(r"[0-9a-f]{40}", source_sha) is None:
            raise AdapterError("Xcode Cloud source discovery requires a full source SHA")
        configured_base = config.get("api_base", _APPLE_API)
        if (
            not isinstance(configured_base, str)
            or configured_base.rstrip("/") != _APPLE_API
        ):
            raise AdapterError(
                "Xcode Cloud source discovery only connects to the official Apple API"
            )
        headers = self._headers(config)
        workflow = _resource_data(
            self.transport.request(
                "GET",
                f"{_APPLE_API}/v1/ciWorkflows/{quote(workflow_id, safe='')}",
                headers=headers,
            ),
            "Xcode Cloud workflow discovery",
        )
        if workflow.get("type") != "ciWorkflows" or workflow.get("id") != workflow_id:
            raise AdapterError("Xcode Cloud workflow discovery returned a different identity")
        repository_id = _relationship_id_or_related(
            self.transport,
            headers,
            workflow,
            parent_type="ciWorkflows",
            parent_id=workflow_id,
            relationship="repository",
            expected_type="scmRepositories",
            operation="Xcode Cloud workflow repository discovery",
        )
        repository = _resource_data(
            self.transport.request(
                "GET",
                f"{_APPLE_API}/v1/scmRepositories/{quote(repository_id, safe='')}",
                headers=headers,
            ),
            "Xcode Cloud repository discovery",
        )
        if repository.get("type") != "scmRepositories" or repository.get("id") != repository_id:
            raise AdapterError("Xcode Cloud repository discovery returned a different identity")
        attributes = repository.get("attributes")
        if not isinstance(attributes, dict):
            raise AdapterError("Xcode Cloud repository discovery returned malformed attributes")
        owner = attributes.get("ownerName")
        name = attributes.get("repositoryName")
        if not isinstance(owner, str) or not owner or not isinstance(name, str) or not name:
            raise AdapterError("Xcode Cloud repository identity is malformed")
        expected_ref = f"refs/tags/shipyard-candidate-{source_sha}"
        refs = _relationship_resources_or_related(
            self.transport,
            headers,
            repository,
            parent_type="scmRepositories",
            parent_id=repository_id,
            relationship="gitReferences",
            expected_type="scmGitReferences",
            operation="Xcode Cloud Git reference discovery",
        )
        matches: list[dict[str, object]] = []
        seen_ids: set[str] = set()
        for resource in refs:
            reference_id = resource.get("id")
            if not isinstance(reference_id, str) or _RESOURCE_ID.fullmatch(reference_id) is None:
                raise AdapterError("Xcode Cloud Git reference identity is malformed")
            if reference_id in seen_ids:
                raise AdapterError(
                    "Xcode Cloud Git reference discovery returned duplicate identity"
                )
            seen_ids.add(reference_id)
            ref_attributes = resource.get("attributes")
            if not isinstance(ref_attributes, dict):
                raise AdapterError("Xcode Cloud Git reference attributes are malformed")
            if ref_attributes.get("canonicalName") == expected_ref:
                matches.append(resource)
        if len(matches) != 1:
            raise AdapterError(
                "expected exactly one Xcode Cloud candidate reference for exact source SHA; "
                f"found {len(matches)}"
            )
        selected = matches[0]
        selected_attributes = selected.get("attributes")
        assert isinstance(selected_attributes, dict)
        if (
            selected_attributes.get("isDeleted") is not False
            or selected_attributes.get("kind") != "TAG"
            or selected_attributes.get("canonicalName") != expected_ref
        ):
            raise AdapterError("Xcode Cloud candidate reference is deleted, not a tag, or changed")
        selected_repository = _inline_relationship_id(
            selected, "repository", "scmRepositories"
        )
        if selected_repository not in {None, repository_id}:
            raise AdapterError("Xcode Cloud candidate reference belongs to a different repository")
        selected_id = selected.get("id")
        assert isinstance(selected_id, str)
        return XcodeCloudSourceCoordinates(
            workflow_id=workflow_id,
            repository_id=repository_id,
            git_reference_id=selected_id,
            git_reference_name=expected_ref,
            repository_owner=owner,
            repository_name=name,
            http_clone_url=self._optional_url(attributes, "httpCloneUrl"),
            ssh_clone_url=self._optional_url(attributes, "sshCloneUrl"),
        )


@dataclass(frozen=True)
class _XcodeCoordinates:
    workflow_id: str
    git_reference_id: str
    git_reference_name: str
    source_remote: str
    repo_path: Path
    clean: bool
    base: str

    @property
    def identity(self) -> str:
        return f"{self.workflow_id}:{self.git_reference_id}"


class XcodeCloudRunDiscovery:
    """Read-only adoption of exactly one Xcode Cloud run for an approved source SHA."""

    _MAX_PAGES = 20

    def __init__(self, transport: HttpTransport) -> None:
        self.transport = transport

    @staticmethod
    def _headers(context: AdapterContext) -> dict[str, str]:
        return apple_headers(context.config)

    @staticmethod
    def _validate_page_url(url: str, workflow_id: str, seen: set[str]) -> None:
        parsed = urlsplit(url)
        expected_path = f"/v1/ciWorkflows/{quote(workflow_id, safe='')}/buildRuns"
        if (
            parsed.scheme != "https"
            or parsed.netloc != "api.appstoreconnect.apple.com"
            or parsed.path != expected_path
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or url in seen
        ):
            raise AdapterError("Xcode Cloud discovery pagination URL is invalid")

    @staticmethod
    def _run_status(attributes: dict[str, object]) -> AdapterStatus:
        progress = attributes.get("executionProgress")
        completion = attributes.get("completionStatus")
        if progress in {"PENDING", "RUNNING"}:
            return "pending"
        if progress == "COMPLETE" and completion == "SUCCEEDED":
            return "succeeded"
        if progress == "COMPLETE" and completion in _FAILURE_COMPLETIONS:
            return "failed"
        return "unknown"

    def discover(self, context: AdapterContext) -> ProviderReadback:
        if context.provider != "apple":
            raise AdapterError("Xcode Cloud discovery requires provider apple")
        if re.fullmatch(r"[0-9a-f]{40}", context.source_sha) is None:
            raise AdapterError("Xcode Cloud discovery requires a full source SHA")
        workflow_id = _config_string(context, "workflow_id")
        if _RESOURCE_ID.fullmatch(workflow_id) is None:
            raise AdapterError("Xcode Cloud discovery workflow_id is invalid")
        configured_base = context.config.get("api_base", _APPLE_API)
        if not isinstance(configured_base, str) or configured_base.rstrip("/") != _APPLE_API:
            raise AdapterError("Xcode Cloud discovery only connects to the official Apple API")
        headers = self._headers(context)
        url = f"{_APPLE_API}/v1/ciWorkflows/{quote(workflow_id, safe='')}/buildRuns"
        seen: set[str] = set()
        matches: list[tuple[str, dict[str, object]]] = []
        pages = 0
        for _page in range(self._MAX_PAGES):
            self._validate_page_url(url, workflow_id, seen)
            seen.add(url)
            pages += 1
            response = self.transport.request("GET", url, headers=headers)
            if not 200 <= response.status < 300:
                raise AdapterError(
                    f"Xcode Cloud run discovery failed with status {response.status}"
                )
            data = response.payload.get("data")
            if not isinstance(data, list):
                raise AdapterError("Xcode Cloud run discovery returned malformed data")
            for resource in data:
                if not isinstance(resource, dict) or resource.get("type") != "ciBuildRuns":
                    raise AdapterError(
                        "Xcode Cloud run discovery returned malformed run data"
                    )
                run_id = resource.get("id")
                attributes = resource.get("attributes")
                source = (
                    attributes.get("sourceCommit")
                    if isinstance(attributes, dict)
                    else None
                )
                sha = source.get("commitSha") if isinstance(source, dict) else None
                if not isinstance(run_id, str) or not isinstance(attributes, dict):
                    raise AdapterError(
                        "Xcode Cloud run discovery returned malformed run data"
                    )
                if sha == context.source_sha:
                    matches.append((run_id, attributes))
            links = response.payload.get("links")
            if links is None:
                break
            if not isinstance(links, dict):
                raise AdapterError(
                    "Xcode Cloud run discovery returned malformed pagination"
                )
            next_url = links.get("next")
            if next_url is None:
                break
            if not isinstance(next_url, str) or not next_url:
                raise AdapterError(
                    "Xcode Cloud run discovery returned malformed pagination"
                )
            url = next_url
        else:
            raise AdapterError("Xcode Cloud run discovery exceeded the page limit")
        if not matches:
            return ProviderReadback(
                "unknown",
                f"xcodecloud:{context.source_sha}",
                context.source_sha,
                {
                    "workflow_id": workflow_id,
                    "state": "absent",
                    "pages": pages,
                    "matches": 0,
                    "adopted": False,
                    "read_only": True,
                },
            )
        if len(matches) != 1:
            raise AdapterError(
                "expected exactly one Xcode Cloud run for exact source SHA; "
                f"found {len(matches)}"
            )
        run_id, attributes = matches[0]
        number = attributes.get("number")
        return ProviderReadback(
            self._run_status(attributes),
            run_id,
            context.source_sha,
            {
                "workflow_id": workflow_id,
                "build_number": (
                    str(number) if isinstance(number, (str, int)) else None
                ),
                "execution_progress": attributes.get("executionProgress"),
                "completion_status": attributes.get("completionStatus"),
                "pages": pages,
                "matches": 1,
                "adopted": True,
                "read_only": True,
            },
        )


class XcodeCloudBuildAdapter:
    """Start and semantically read back one exact-source Xcode Cloud build."""

    action = "xcodecloud.build"

    def __init__(
        self,
        transport: HttpTransport,
        *,
        source_resolver: Callable[[Path, str, str], str] | None = None,
    ) -> None:
        self.transport = transport
        self.source_resolver = source_resolver or self._resolve_remote_source

    @staticmethod
    def _resolve_remote_source(repo_path: Path, remote: str, reference: str) -> str:
        git = resolve_executable("git", repo_path)
        try:
            configured = subprocess.run(  # noqa: S603
                (str(git), "remote", "get-url", "--all", remote),
                cwd=repo_path,
                env=sanitized_environment(),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            configured_urls = [line for line in configured.stdout.splitlines() if line]
            if configured.returncode != 0 or len(configured_urls) != 1:
                raise AdapterError(
                    "Xcode Cloud source remote must name exactly one configured Git remote"
                )
            completed = subprocess.run(  # noqa: S603
                (str(git), "ls-remote", "--exit-code", remote, reference, f"{reference}^{{}}"),
                cwd=repo_path,
                env=sanitized_environment(),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise AdapterError("Xcode Cloud source remote preflight failed") from exc
        if completed.returncode != 0:
            raise AdapterError("Xcode Cloud source remote preflight failed")
        refs: dict[str, str] = {}
        for line in completed.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) != 2 or re.fullmatch(r"[0-9a-f]{40}", parts[0]) is None:
                raise AdapterError("Xcode Cloud source remote returned malformed identity")
            if parts[1] in refs:
                raise AdapterError("Xcode Cloud source remote returned ambiguous identity")
            refs[parts[1]] = parts[0]
        observed = refs.get(f"{reference}^{{}}", refs.get(reference))
        if observed is None:
            raise AdapterError("Xcode Cloud source remote omitted the candidate reference")
        return observed

    @staticmethod
    def _coordinates(context: AdapterContext) -> _XcodeCoordinates:
        workflow_id = _config_string(context, "workflow_id")
        git_reference_id = _config_string(context, "git_reference_id")
        for value in (workflow_id, git_reference_id):
            if _RESOURCE_ID.fullmatch(value) is None:
                raise AdapterError("xcodecloud.build requires conservative provider identifiers")
        validate_apple_credential_references(context.config)
        clean = context.config.get("clean", True)
        if not isinstance(clean, bool):
            raise AdapterError("xcodecloud.build clean must be a boolean")
        configured_base = context.config.get("api_base", _APPLE_API)
        if not isinstance(configured_base, str) or configured_base.rstrip("/") != _APPLE_API:
            raise AdapterError("xcodecloud.build only connects to the official Apple API")
        git_reference_name = _config_string(context, "git_reference_name")
        expected_reference = f"refs/tags/shipyard-candidate-{context.source_sha}"
        if git_reference_name != expected_reference:
            raise AdapterError("xcodecloud.build requires the exact candidate tag reference")
        source_remote = _config_string(context, "source_remote")
        if (
            _NAMED_REMOTE.fullmatch(source_remote) is None
            or ".." in source_remote
            or source_remote.endswith(".")
        ):
            raise AdapterError("xcodecloud.build source_remote must be a named Git remote")
        configured_repo = _config_string(context, "repo_path")
        try:
            repo_path = Path(configured_repo).resolve(strict=True)
        except OSError as exc:
            raise AdapterError("xcodecloud.build governed repository is unavailable") from exc
        if not repo_path.is_dir():
            raise AdapterError("xcodecloud.build governed repository is unavailable")
        coordinates = _XcodeCoordinates(
            workflow_id,
            git_reference_id,
            git_reference_name,
            source_remote,
            repo_path,
            clean,
            _APPLE_API,
        )
        if context.destination != coordinates.identity:
            raise AdapterError("xcodecloud.build destination does not match provider identifiers")
        return coordinates

    @staticmethod
    def _headers(context: AdapterContext) -> dict[str, str]:
        return apple_headers(context.config)

    def _identity(
        self, context: AdapterContext
    ) -> tuple[_XcodeCoordinates, dict[str, str], dict[str, object]]:
        coordinates = self._coordinates(context)
        headers = self._headers(context)
        workflow = _resource_data(
            self.transport.request(
                "GET",
                f"{coordinates.base}/v1/ciWorkflows/{quote(coordinates.workflow_id, safe='')}",
                headers=headers,
            ),
            "Xcode Cloud workflow verification",
        )
        if workflow.get("type") != "ciWorkflows" or workflow.get("id") != coordinates.workflow_id:
            raise AdapterError("Xcode Cloud workflow verification returned a different identity")
        git_reference = _resource_data(
            self.transport.request(
                "GET",
                f"{coordinates.base}/v1/scmGitReferences/"
                f"{quote(coordinates.git_reference_id, safe='')}",
                headers=headers,
            ),
            "Xcode Cloud Git reference verification",
        )
        if (
            git_reference.get("type") != "scmGitReferences"
            or git_reference.get("id") != coordinates.git_reference_id
        ):
            raise AdapterError(
                "Xcode Cloud Git reference verification returned a different identity"
            )
        attributes = git_reference.get("attributes")
        if (
            not isinstance(attributes, dict)
            or attributes.get("canonicalName") != coordinates.git_reference_name
        ):
            raise AdapterError("Xcode Cloud Git reference does not match the candidate tag")
        observed_sha = self.source_resolver(
            coordinates.repo_path,
            coordinates.source_remote,
            coordinates.git_reference_name,
        )
        if observed_sha != context.source_sha:
            raise AdapterError(
                "Xcode Cloud candidate tag does not resolve to the approved source SHA"
            )
        return coordinates, headers, workflow

    def check(self, context: AdapterContext) -> ConnectionCheck:
        coordinates, _, _ = self._identity(context)
        source_observation_digest = context.config.get("source_observation_digest")
        return ConnectionCheck(
            "verified",
            context.provider,
            self.action,
            coordinates.identity,
            {
                "workflow_id": coordinates.workflow_id,
                "git_reference_id": coordinates.git_reference_id,
                "git_reference_name": coordinates.git_reference_name,
                "source_remote": coordinates.source_remote,
                "source_sha": context.source_sha,
                "source_observation_digest": source_observation_digest,
            },
        )

    def execute(self, context: AdapterContext) -> MutationReceipt:
        coordinates, headers, _ = self._identity(context)
        created = self.transport.request(
            "POST",
            f"{coordinates.base}/v1/ciBuildRuns",
            headers=headers,
            body={
                "data": {
                    "type": "ciBuildRuns",
                    "attributes": {"clean": coordinates.clean},
                    "relationships": {
                        "workflow": {
                            "data": {
                                "type": "ciWorkflows",
                                "id": coordinates.workflow_id,
                            }
                        },
                        "sourceBranchOrTag": {
                            "data": {
                                "type": "scmGitReferences",
                                "id": coordinates.git_reference_id,
                            }
                        },
                    },
                }
            },
        )
        resource = _resource_data(created, "Xcode Cloud build creation")
        operation_id = resource.get("id")
        if created.status != 201 or resource.get("type") != "ciBuildRuns":
            raise AdapterError("Xcode Cloud build creation returned an invalid resource")
        if not isinstance(operation_id, str) or _RESOURCE_ID.fullmatch(operation_id) is None:
            raise AdapterError("Xcode Cloud build creation omitted a valid build run id")
        return MutationReceipt(
            context.provider,
            self.action,
            operation_id,
            context.source_sha,
            {
                "workflow_id": coordinates.workflow_id,
                "git_reference_id": coordinates.git_reference_id,
                "http_status": created.status,
                "source_observation_digest": context.config.get(
                    "source_observation_digest"
                ),
            },
        )

    def readback(
        self, context: AdapterContext, receipt: MutationReceipt
    ) -> ProviderReadback:
        coordinates = self._coordinates(context)
        if (
            receipt.provider != context.provider
            or receipt.action != self.action
            or receipt.submitted_sha != context.source_sha
            or _RESOURCE_ID.fullmatch(receipt.operation_id) is None
        ):
            return ProviderReadback(
                "failed", receipt.operation_id, None, {"identity_match": False}
            )
        headers = self._headers(context)
        response = self.transport.request(
            "GET",
            f"{coordinates.base}/v1/ciBuildRuns/{quote(receipt.operation_id, safe='')}",
            headers=headers,
        )
        resource = _resource_data(response, "Xcode Cloud build readback")
        attributes = resource.get("attributes")
        source_commit = attributes.get("sourceCommit") if isinstance(attributes, dict) else None
        observed_sha = (
            source_commit.get("commitSha") if isinstance(source_commit, dict) else None
        )
        if (
            resource.get("type") != "ciBuildRuns"
            or resource.get("id") != receipt.operation_id
        ):
            return ProviderReadback(
                "failed",
                receipt.operation_id,
                observed_sha if isinstance(observed_sha, str) else None,
                {"identity_match": False},
            )
        workflow_id = _inline_relationship_id(resource, "workflow", "ciWorkflows")
        git_reference_id = _inline_relationship_id(
            resource, "sourceBranchOrTag", "scmGitReferences"
        )
        inline_drift = (
            workflow_id not in {None, coordinates.workflow_id}
            or git_reference_id not in {None, coordinates.git_reference_id}
        )
        identity_source = "inline"
        if inline_drift:
            identity_matches = False
        elif workflow_id is not None and git_reference_id is not None:
            identity_matches = True
        else:
            verified_coordinates, fallback_headers, workflow = self._identity(context)
            linked_runs = _relationship_ids_or_related(
                self.transport,
                fallback_headers,
                workflow,
                parent_type="ciWorkflows",
                parent_id=verified_coordinates.workflow_id,
                relationship="buildRuns",
                expected_type="ciBuildRuns",
                operation="Xcode Cloud workflow run membership readback",
            )
            identity_matches = receipt.operation_id in linked_runs
            identity_source = "workflow_membership"
        progress = attributes.get("executionProgress") if isinstance(attributes, dict) else None
        completion = attributes.get("completionStatus") if isinstance(attributes, dict) else None
        if not identity_matches or observed_sha != receipt.submitted_sha:
            status: AdapterStatus = "failed"
        elif progress in {"PENDING", "RUNNING"}:
            status = "pending"
        elif progress == "COMPLETE" and completion == "SUCCEEDED":
            status = "succeeded"
        elif progress == "COMPLETE" and completion in _FAILURE_COMPLETIONS:
            status = "failed"
        else:
            status = "unknown"
        return ProviderReadback(
            status,
            receipt.operation_id,
            observed_sha if isinstance(observed_sha, str) else None,
            {
                "workflow_id": coordinates.workflow_id,
                "git_reference_id": coordinates.git_reference_id,
                "identity_source": identity_source,
                "execution_progress": progress,
                "completion_status": completion,
                "source_observation_digest": context.config.get(
                    "source_observation_digest"
                ),
            },
        )
