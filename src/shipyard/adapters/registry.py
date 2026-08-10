from __future__ import annotations

from .base import AdapterError, DeploymentAdapter
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
        ]
        self._adapters = {adapter.action: adapter for adapter in configured}

    def get(self, action: str) -> DeploymentAdapter:
        try:
            return self._adapters[action]
        except KeyError as exc:
            raise AdapterError(f"no adapter registered for action {action}") from exc

    def actions(self) -> tuple[str, ...]:
        return tuple(sorted(self._adapters))
