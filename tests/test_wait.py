from dataclasses import dataclass

import pytest

from shipyard.wait import WaitError, WaitState, wait_for_reconciliation


@dataclass(frozen=True)
class Readback:
    status: str


def test_wait_polls_read_only_until_succeeded():
    states = iter([Readback("pending"), Readback("succeeded")])
    sleeps: list[float] = []
    result = wait_for_reconciliation(
        lambda: next(states),
        timeout=10,
        interval=2,
        clock=iter([0, 1]).__next__,
        sleep=sleeps.append,
    )

    assert result.state is WaitState.SUCCEEDED
    assert result.polls == 2
    assert sleeps == [2]


def test_wait_stops_on_failed_and_never_calls_sleep():
    calls: list[str] = []
    result = wait_for_reconciliation(
        lambda: calls.append("read") or "failed",
        timeout=5,
        interval=1,
        clock=iter([0]).__next__,
        sleep=lambda _: calls.append("sleep"),
    )

    assert result.state is WaitState.FAILED
    assert calls == ["read"]


@pytest.mark.parametrize("timeout,interval", [(0, 1), (1, 0), (-1, 1), (1, -1)])
def test_wait_validates_positive_bounds(timeout, interval):
    with pytest.raises(ValueError):
        wait_for_reconciliation(lambda: "pending", timeout=timeout, interval=interval)


def test_wait_times_out_while_provider_remains_pending():
    times = iter([0, 0, 3, 6])
    result = wait_for_reconciliation(
        lambda: "pending",
        timeout=5,
        interval=2,
        clock=times.__next__,
        sleep=lambda _: None,
    )

    assert result.state is WaitState.TIMEOUT
    assert result.polls == 3


@pytest.mark.parametrize("status", ["unknown", "uncertain", "still_uncertain"])
def test_wait_preserves_still_uncertain_outcome_at_deadline(status):
    result = wait_for_reconciliation(
        lambda: status,
        timeout=1,
        interval=2,
        clock=iter([0, 1]).__next__,
        sleep=lambda _: None,
    )

    assert result.state is WaitState.STILL_UNCERTAIN


@pytest.mark.parametrize("status", [None, True, 1, [], {}, "surprise"])
def test_wait_fails_closed_on_malformed_readback_status(status):
    with pytest.raises(WaitError):
        wait_for_reconciliation(
            lambda: status,
            timeout=1,
            interval=1,
            clock=iter([0]).__next__,
        )


def test_wait_rejects_non_monotonic_clock():
    with pytest.raises(WaitError, match="backwards"):
        wait_for_reconciliation(
            lambda: "pending",
            timeout=5,
            interval=1,
            clock=iter([2, 1]).__next__,
            sleep=lambda _: None,
        )
