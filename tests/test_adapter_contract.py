from __future__ import annotations

from dataclasses import dataclass

import pytest

from shipyard.adapter_contract import ContractError, exercise_adapter
from shipyard.adapters.base import (
    AdapterContext,
    ConnectionCheck,
    MutationReceipt,
    ProviderReadback,
)


@dataclass
class FakeAdapter:
    readback_value: ProviderReadback
    check_status: str = "verified"
    identity: str | None = "acme/widget"
    action: str = "deploy"

    def __post_init__(self):
        self.calls: list[str] = []

    def check(self, context):
        self.calls.append("check")
        return ConnectionCheck(
            self.check_status, "fake", self.action, self.identity, {}
        )

    def execute(self, context):
        self.calls.append("execute")
        return MutationReceipt("fake", self.action, "op-1", context.source_sha, {})

    def readback(self, context, receipt):
        self.calls.append("readback")
        return self.readback_value


def _context() -> AdapterContext:
    return AdapterContext("run", "abc", "fake", "acme/widget", {})


def test_harness_is_read_only_by_default():
    adapter = FakeAdapter(ProviderReadback("succeeded", "op-1", "abc", {}))

    result = exercise_adapter(adapter, _context(), expected_identity="acme/widget")

    assert result.final_status == "uncertain"
    assert result.calls == ("check",)
    assert result.attempts == 0
    assert adapter.calls == ["check"]


def test_harness_executes_once_only_after_explicit_opt_in_and_verified_identity():
    adapter = FakeAdapter(ProviderReadback("succeeded", "op-1", "abc", {}))

    result = exercise_adapter(
        adapter,
        _context(),
        expected_identity="acme/widget",
        allow_execute=True,
    )

    assert result.final_status == "succeeded"
    assert result.calls == ("check", "execute", "readback")
    assert result.attempts == 1
    assert result.identity_match is True


@pytest.mark.parametrize("status", ["unknown", "pending"])
def test_harness_represents_uncertain_without_retrying(status):
    adapter = FakeAdapter(ProviderReadback(status, "op-1", None, {}))

    result = exercise_adapter(
        adapter,
        _context(),
        expected_identity="acme/widget",
        allow_execute=True,
    )

    assert result.final_status == "uncertain"
    assert result.attempts == 1
    assert adapter.calls == ["check", "execute", "readback"]


def test_harness_rejects_provider_identity_before_mutation():
    adapter = FakeAdapter(ProviderReadback("succeeded", "op-1", "abc", {}))

    with pytest.raises(ContractError, match="provider identity"):
        exercise_adapter(
            adapter,
            _context(),
            expected_identity="different",
            allow_execute=True,
        )

    assert adapter.calls == ["check"]


def test_harness_rejects_unknown_check_before_mutation():
    adapter = FakeAdapter(
        ProviderReadback("succeeded", "op-1", "abc", {}),
        check_status="unknown",
        identity=None,
    )

    with pytest.raises(ContractError, match="verified provider identity"):
        exercise_adapter(adapter, _context(), allow_execute=True)

    assert adapter.calls == ["check"]


def test_harness_rejects_readback_identity_mismatch_without_retry():
    adapter = FakeAdapter(ProviderReadback("succeeded", "op-1", "different", {}))

    with pytest.raises(ContractError, match="readback identity"):
        exercise_adapter(
            adapter,
            _context(),
            expected_identity="acme/widget",
            allow_execute=True,
        )

    assert adapter.calls == ["check", "execute", "readback"]
