from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .adapters.base import AdapterContext, DeploymentAdapter


class ContractError(ValueError):
    pass


@dataclass(frozen=True)
class ContractResult:
    final_status: Literal["succeeded", "failed", "uncertain"]
    calls: tuple[str, ...]
    attempts: int
    identity_match: bool | None
    check: object
    receipt: object
    readback: object


def exercise_adapter(
    adapter: DeploymentAdapter,
    context: AdapterContext,
    *,
    expected_identity: str | None = None,
    allow_execute: bool = False,
) -> ContractResult:
    """Exercise an adapter with a read-only default and a single guarded mutation."""
    calls: list[str] = []
    check = adapter.check(context)
    calls.append("check")
    if check.status not in {"verified", "unknown"}:
        raise ContractError("check must be read-only and return a valid status")
    if check.provider != context.provider or check.action != adapter.action:
        raise ContractError("check provider/action identity mismatch")
    identity_match = expected_identity is None or check.identity == expected_identity
    if not identity_match:
        raise ContractError("provider identity mismatch")
    if not allow_execute:
        return ContractResult("uncertain", tuple(calls), 0, identity_match, check, None, None)
    if check.status != "verified" or check.identity is None:
        raise ContractError("mutation requires a verified provider identity")

    receipt = adapter.execute(context)
    calls.append("execute")
    if (
        receipt.provider != context.provider
        or receipt.action != adapter.action
        or not receipt.operation_id
        or receipt.submitted_sha != context.source_sha
    ):
        raise ContractError("execute receipt does not preserve provider/action/SHA identity")
    readback = adapter.readback(context, receipt)
    calls.append("readback")
    if (
        readback.operation_id != receipt.operation_id
        or (readback.observed_sha is not None and readback.observed_sha != receipt.submitted_sha)
    ):
        raise ContractError("readback identity mismatch")
    if readback.status == "unknown" or readback.status == "pending":
        status = "uncertain"
    elif readback.status == "succeeded":
        status = "succeeded"
    elif readback.status == "failed":
        status = "failed"
    else:
        raise ContractError("invalid readback status")
    return ContractResult(status, tuple(calls), 1, identity_match, check, receipt, readback)
