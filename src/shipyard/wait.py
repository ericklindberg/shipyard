"""Bounded, read-only reconciliation polling."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class WaitState(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    STILL_UNCERTAIN = "still_uncertain"
    TIMEOUT = "timeout"


class WaitError(ValueError):
    """The read-only provider callback returned a malformed result."""


@dataclass(frozen=True)
class WaitResult:
    state: WaitState
    polls: int
    last_status: str | None = None
    last_value: Any = None


def wait_for_reconciliation(
    readback: Callable[[], Any],
    *,
    timeout: float,
    interval: float,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> WaitResult:
    """Poll an already-authorized readback callback without invoking mutation APIs."""
    if timeout <= 0 or interval <= 0:
        raise ValueError("timeout and interval must be positive")
    started = clock()
    deadline = started + timeout
    previous_time = started
    polls = 0
    while True:
        value = readback()
        polls += 1
        status = _status(value)
        if status == "succeeded":
            return WaitResult(WaitState.SUCCEEDED, polls, status, value)
        if status == "failed":
            return WaitResult(WaitState.FAILED, polls, status, value)
        current = clock()
        if current < previous_time:
            raise WaitError("monotonic clock moved backwards")
        previous_time = current
        remaining = deadline - current
        if remaining <= 0:
            state = (
                WaitState.STILL_UNCERTAIN
                if status in {"unknown", "uncertain"}
                else WaitState.TIMEOUT
            )
            return WaitResult(state, polls, status, value)
        sleep(min(interval, remaining))


def _status(value: Any) -> str:
    candidate = value if isinstance(value, str) else getattr(value, "status", None)
    if not isinstance(candidate, str):
        raise WaitError("readback status must be a string")
    status = candidate.lower()
    if status == "still_uncertain":
        status = "uncertain"
    if status not in {"pending", "unknown", "uncertain", "succeeded", "failed"}:
        raise WaitError(f"unsupported readback status: {status!r}")
    return status
