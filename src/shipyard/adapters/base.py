from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

AdapterStatus = Literal["succeeded", "failed", "pending", "unknown"]
ConnectionStatus = Literal["verified", "unknown"]


class AdapterError(RuntimeError):
    pass


@dataclass(frozen=True)
class AdapterContext:
    run_id: str
    source_sha: str
    provider: str
    destination: str
    config: dict[str, object]


@dataclass(frozen=True)
class ConnectionCheck:
    status: ConnectionStatus
    provider: str
    action: str
    identity: str | None
    evidence: dict[str, object]


@dataclass(frozen=True)
class MutationReceipt:
    provider: str
    action: str
    operation_id: str
    submitted_sha: str
    evidence: dict[str, object]


@dataclass(frozen=True)
class ProviderReadback:
    status: AdapterStatus
    operation_id: str
    observed_sha: str | None
    evidence: dict[str, object]


class DeploymentAdapter(Protocol):
    action: str

    def check(self, context: AdapterContext) -> ConnectionCheck: ...

    def execute(self, context: AdapterContext) -> MutationReceipt: ...

    def readback(
        self, context: AdapterContext, receipt: MutationReceipt
    ) -> ProviderReadback: ...
