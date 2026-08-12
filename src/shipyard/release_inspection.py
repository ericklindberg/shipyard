from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .adapters.apple import XcodeCloudRunDiscovery, XcodeCloudSourceDiscovery
from .adapters.base import AdapterContext, AdapterError, AdapterStatus, ProviderReadback
from .adapters.http import HttpTransport, UrllibTransport
from .adapters.providers import GitHubWorkflowRunDiscovery
from .apple_release import AppleReleaseResolver
from .candidate import canonical_repository_identity
from .release_project import ReleaseProject, ReleaseProjectError

_STATUS_PRIORITY: dict[AdapterStatus, int] = {
    "succeeded": 0,
    "pending": 1,
    "unknown": 2,
    "failed": 3,
}


@dataclass(frozen=True)
class ProviderInspection:
    provider: str
    readback: ProviderReadback

    def payload(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "status": self.readback.status,
            "state": self.readback.evidence.get("state", "present"),
            "operation_id": self.readback.operation_id,
            "observed_sha": self.readback.observed_sha,
            "evidence": self.readback.evidence,
        }


@dataclass(frozen=True)
class ReleaseInspection:
    source_sha: str
    inspections: tuple[ProviderInspection, ...]

    @property
    def status(self) -> AdapterStatus:
        if not self.inspections:
            return "unknown"
        return max(
            (inspection.readback.status for inspection in self.inspections),
            key=_STATUS_PRIORITY.__getitem__,
        )

    def payload(self) -> dict[str, object]:
        return {
            "source_sha": self.source_sha,
            "status": self.status,
            "read_only": True,
            "provider_mutations": 0,
            "providers": [inspection.payload() for inspection in self.inspections],
        }


def _github_inspection(
    project: ReleaseProject,
    source_sha: str,
    transport: HttpTransport,
) -> ProviderInspection:
    if project.github is None:
        raise ReleaseProjectError("release project does not configure GitHub")
    readback = GitHubWorkflowRunDiscovery(transport).discover(
        AdapterContext(
            "release-inspect",
            source_sha,
            "github-actions",
            project.github.repository_id,
            project.github.config(),
        )
    )
    return ProviderInspection("github", readback)


def _apple_inspection(
    project: ReleaseProject,
    source_sha: str,
    transport: HttpTransport,
    *,
    expected_build_number: str | None,
) -> ProviderInspection:
    apple = project.apple
    if apple is None:
        raise ReleaseProjectError("release project does not configure Apple")
    source_coordinates = XcodeCloudSourceDiscovery(transport).discover(
        workflow_id=apple.workflow_id,
        source_sha=source_sha,
        config=apple.credential_config,
    )
    expected_repository = canonical_repository_identity(apple.source_remote)
    observed_repositories = {
        identity
        for identity in (
            canonical_repository_identity(source_coordinates.http_clone_url),
            canonical_repository_identity(source_coordinates.ssh_clone_url),
        )
        if identity is not None
    }
    if expected_repository is None or observed_repositories != {expected_repository}:
        raise AdapterError(
            "Xcode Cloud workflow repository does not match Apple source_remote"
        )
    config = apple.config(expected_build_number=expected_build_number)
    run_readback = XcodeCloudRunDiscovery(transport).discover(
        AdapterContext(
            "release-inspect",
            source_sha,
            "apple",
            apple.workflow_id,
            config,
        )
    )
    source_evidence = {
        **source_coordinates.evidence(),
        "repository_identity": expected_repository,
    }
    if run_readback.status != "succeeded":
        return ProviderInspection(
            "apple",
            ProviderReadback(
                run_readback.status,
                run_readback.operation_id,
                run_readback.observed_sha,
                {**source_evidence, **run_readback.evidence},
            ),
        )
    coordinates = AppleReleaseResolver(transport).resolve(
        source_sha=source_sha,
        config=config,
    )
    return ProviderInspection(
        "apple",
        ProviderReadback(
            "succeeded",
            coordinates.run_id,
            source_sha,
            {
                **coordinates.payload(),
                "observation_digest": coordinates.digest,
            },
        ),
    )


def inspect_release(
    project: ReleaseProject,
    source_sha: str,
    *,
    provider: str = "all",
    expected_build_number: str | None = None,
    transport_factory: Callable[[], HttpTransport] = UrllibTransport,
) -> ReleaseInspection:
    if provider not in {"all", "github", "apple"}:
        raise ReleaseProjectError("release inspection provider is invalid")
    inspections: list[ProviderInspection] = []
    if provider in {"all", "github"}:
        inspections.append(_github_inspection(project, source_sha, transport_factory()))
    if provider in {"all", "apple"}:
        inspections.append(
            _apple_inspection(
                project,
                source_sha,
                transport_factory(),
                expected_build_number=expected_build_number,
            )
        )
    return ReleaseInspection(source_sha, tuple(inspections))
