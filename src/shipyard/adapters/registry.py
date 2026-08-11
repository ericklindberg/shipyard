from __future__ import annotations

from .apple import XcodeCloudBuildAdapter
from .apple_testflight import TestFlightGroupAdapter
from .base import AdapterError, DeploymentAdapter
from .http import UrllibTransport
from .kubernetes import KubernetesDeploymentAdapter
from .oci import OciPromotionAdapter
from .providers import (
    BuzzWorkflowAdapter,
    GitHubWorkflowAdapter,
    GitRefAdapter,
    HerokuBuildAdapter,
    RenderAdapter,
    VercelAdapter,
)


class AdapterRegistry:
    def __init__(self, adapters: list[DeploymentAdapter] | None = None) -> None:
        configured = adapters or [
            GitRefAdapter(),
            GitHubWorkflowAdapter(),
            BuzzWorkflowAdapter(),
            RenderAdapter(),
            HerokuBuildAdapter(),
            VercelAdapter(),
            XcodeCloudBuildAdapter(UrllibTransport()),
            TestFlightGroupAdapter(UrllibTransport()),
            OciPromotionAdapter(),
            KubernetesDeploymentAdapter(),
        ]
        self._adapters = {adapter.action: adapter for adapter in configured}

    def get(self, action: str) -> DeploymentAdapter:
        try:
            return self._adapters[action]
        except KeyError as exc:
            raise AdapterError(f"no adapter registered for action {action}") from exc

    def actions(self) -> tuple[str, ...]:
        return tuple(sorted(self._adapters))
