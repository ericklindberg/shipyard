from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

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


def _relationship_id(resource: dict[str, object], name: str, expected_type: str) -> str | None:
    relationships = resource.get("relationships")
    if not isinstance(relationships, dict):
        return None
    relationship = relationships.get(name)
    if not isinstance(relationship, dict):
        return None
    data = relationship.get("data")
    if not isinstance(data, dict) or data.get("type") != expected_type:
        return None
    identifier = data.get("id")
    return identifier if isinstance(identifier, str) else None


@dataclass(frozen=True)
class _XcodeCoordinates:
    workflow_id: str
    git_reference_id: str
    git_reference_name: str
    source_remote: str
    repo_path: Path
    token_env: str
    clean: bool
    base: str

    @property
    def identity(self) -> str:
        return f"{self.workflow_id}:{self.git_reference_id}"


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
        token_env = _config_string(context, "token_env")
        if _ENV_NAME.fullmatch(token_env) is None or not token_env.startswith("APPLE_"):
            raise AdapterError("xcodecloud.build token_env must use an APPLE_ variable")
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
            token_env,
            clean,
            _APPLE_API,
        )
        if context.destination != coordinates.identity:
            raise AdapterError("xcodecloud.build destination does not match provider identifiers")
        return coordinates

    @staticmethod
    def _headers(coordinates: _XcodeCoordinates) -> dict[str, str]:
        token = os.environ.get(coordinates.token_env)
        if not token:
            raise AdapterError(
                f"credential environment variable {coordinates.token_env} is not set"
            )
        if "\x00" in token or "\r" in token or "\n" in token:
            raise AdapterError("Apple credential environment variable is malformed")
        return {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    def _identity(
        self, context: AdapterContext
    ) -> tuple[_XcodeCoordinates, dict[str, str]]:
        coordinates = self._coordinates(context)
        headers = self._headers(coordinates)
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
        return coordinates, headers

    def check(self, context: AdapterContext) -> ConnectionCheck:
        coordinates, _ = self._identity(context)
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
            },
        )

    def execute(self, context: AdapterContext) -> MutationReceipt:
        coordinates, headers = self._identity(context)
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
            },
        )

    def readback(
        self, context: AdapterContext, receipt: MutationReceipt
    ) -> ProviderReadback:
        coordinates = self._coordinates(context)
        headers = self._headers(coordinates)
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
        workflow_id = _relationship_id(resource, "workflow", "ciWorkflows")
        git_reference_id = _relationship_id(
            resource, "sourceBranchOrTag", "scmGitReferences"
        )
        identity_matches = (
            receipt.provider == context.provider
            and receipt.action == self.action
            and receipt.submitted_sha == context.source_sha
            and resource.get("type") == "ciBuildRuns"
            and resource.get("id") == receipt.operation_id
            and workflow_id == coordinates.workflow_id
            and git_reference_id == coordinates.git_reference_id
        )
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
                "execution_progress": progress,
                "completion_status": completion,
            },
        )
