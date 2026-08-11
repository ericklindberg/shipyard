from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import threading
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .adapters.base import AdapterContext, AdapterError, ProviderReadback
from .adapters.registry import AdapterRegistry
from .candidate import build_candidate
from .connections import inspect_buzz_git_auth
from .execution_snapshot import (
    ExecutionSnapshotError,
    cleanup_execution_snapshot,
    execution_snapshot_run,
    freeze_execution_snapshot,
    prepare_execution_snapshot,
)
from .gitops import snapshot_repository
from .ledger import Ledger, RunBusyError
from .models import Playbook, ReleaseRun, StepRun, StepStatus
from .redact import redact
from .runtime import resolve_executable, sanitized_environment


class AuthorizationError(RuntimeError):
    pass


class ProvenanceDriftError(RuntimeError):
    pass


class UncertainOutcomeError(RuntimeError):
    pass


class ProcessInterrupted(RuntimeError):
    pass


@dataclass(frozen=True)
class ProcessOutcome:
    returncode: int
    output_tail: str
    output_sha256: str
    truncated: bool


_MAX_CAPTURE_BYTES = 1024 * 1024
_SIGNAL_HANDLER_LOCK = threading.Lock()


@contextmanager
def _interrupt_handlers() -> Iterator[None]:
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    if not _SIGNAL_HANDLER_LOCK.acquire(blocking=False):
        yield
        return
    previous: dict[signal.Signals, Any] = {}

    def interrupt(signum: int, _frame: object) -> None:
        raise ProcessInterrupted(f"execution interrupted by signal {signum}")

    handled = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    try:
        for handled_signal in handled:
            previous[handled_signal] = signal.getsignal(handled_signal)
            signal.signal(handled_signal, interrupt)
        yield
    finally:
        for handled_signal, handler in previous.items():
            signal.signal(handled_signal, handler)
        _SIGNAL_HANDLER_LOCK.release()


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    process.wait()


def _run_process(
    command: tuple[str, ...], repo_path: Path, timeout_seconds: int
) -> ProcessOutcome:
    executable = resolve_executable(command[0], repo_path)
    resolved_command = (str(executable), *command[1:])
    process = subprocess.Popen(
        resolved_command,
        cwd=repo_path,
        env=sanitized_environment(),
        text=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    digest = hashlib.sha256()
    tail = bytearray()
    total_bytes = 0

    output_stream = process.stdout
    if output_stream is None:
        _kill_process_group(process)
        raise RuntimeError("subprocess output pipe was not created")

    def drain() -> None:
        nonlocal total_bytes
        while chunk := output_stream.read(64 * 1024):
            digest.update(chunk)
            total_bytes += len(chunk)
            tail.extend(chunk)
            if len(tail) > _MAX_CAPTURE_BYTES:
                del tail[: len(tail) - _MAX_CAPTURE_BYTES]

    reader = threading.Thread(target=drain, name="shipyard-output-drain", daemon=True)
    reader.start()
    timed_out = False
    try:
        with _interrupt_handlers():
            process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_process_group(process)
    except BaseException:
        _kill_process_group(process)
        raise
    finally:
        reader.join(timeout=5)
    output = tail.decode("utf-8", errors="replace")
    if timed_out:
        output = f"{output}\nTimed out after {timeout_seconds} seconds."
    return ProcessOutcome(
        returncode=124 if timed_out else process.returncode,
        output_tail=output,
        output_sha256=digest.hexdigest(),
        truncated=total_bytes > _MAX_CAPTURE_BYTES,
    )


class ReleaseExecutor:
    def __init__(self, ledger: Ledger, adapters: AdapterRegistry | None = None) -> None:
        self.ledger = ledger
        self.adapters = adapters or AdapterRegistry()

    def start(
        self,
        repo_path: str | Path,
        playbook: Playbook,
        *,
        execute_external: bool = False,
        confirm_sha: str | None = None,
        approve_candidate: str | None = None,
        approval_actor: str | None = None,
        approval_reason: str | None = None,
    ) -> ReleaseRun:
        if (
            os.environ.get("SHIPYARD_ENABLE_LEGACY_EXTERNAL") != "1"
            and any(step.effect == "external" and not step.action for step in playbook.steps)
        ):
            raise AuthorizationError(
                "legacy raw external commands are disabled; use a schema_version 2 "
                "typed adapter action"
            )
        snapshot = snapshot_repository(repo_path)
        if snapshot.dirty and not playbook.allow_dirty:
            raise ProvenanceDriftError("working tree is dirty")
        target_lock = (
            self.ledger.lock_target(snapshot.path, f"{playbook.provider}:{playbook.destination}")
            if execute_external and any(step.effect == "external" for step in playbook.steps)
            else nullcontext()
        )
        with target_lock:
            run = self.ledger.create_run(snapshot, playbook)
            with self.ledger.lock_run(run.run_id):
                return self._execute(
                    run.run_id,
                    execute_external=execute_external,
                    confirm_sha=confirm_sha,
                    approve_candidate=approve_candidate,
                    approval_actor=approval_actor,
                    approval_reason=approval_reason,
                )

    def resume(
        self,
        run_id: str,
        *,
        execute_external: bool = False,
        confirm_sha: str | None = None,
        approve_candidate: str | None = None,
        approval_actor: str | None = None,
        approval_reason: str | None = None,
    ) -> ReleaseRun:
        run = self.ledger.get_run(run_id)
        target_lock = (
            self.ledger.lock_target(
                run.repo_path, f"{run.provider}:{run.destination}"
            )
            if execute_external
            and any(
                step.effect == "external" and step.status != "succeeded"
                for step in run.steps
            )
            else nullcontext()
        )
        with target_lock, self.ledger.lock_run(run_id):
            return self._resume_locked(
                run_id,
                execute_external=execute_external,
                confirm_sha=confirm_sha,
                approve_candidate=approve_candidate,
                approval_actor=approval_actor,
                approval_reason=approval_reason,
            )

    def _resume_locked(
        self,
        run_id: str,
        *,
        execute_external: bool,
        confirm_sha: str | None,
        approve_candidate: str | None,
        approval_actor: str | None,
        approval_reason: str | None,
    ) -> ReleaseRun:
        run = self.ledger.get_run(run_id)
        first_actionable = next(
            (step for step in run.steps if step.status != "succeeded"), None
        )
        if (
            first_actionable is not None
            and first_actionable.effect == "external"
            and first_actionable.status in {"running", "uncertain"}
        ):
            if first_actionable.status == "running":
                self.ledger.finish_step(
                    run_id,
                    first_actionable.ordinal,
                    status="uncertain",
                    exit_code=None,
                    output_sha256=None,
                    output_preview="Interrupted external attempt; provider readback required.",
                )
            self.ledger.set_run_status(run_id, "uncertain")
            raise UncertainOutcomeError(
                f"external step {first_actionable.id} outcome is unknown after an "
                "interrupted or nonzero attempt"
            )
        current = snapshot_repository(run.repo_path)
        if current.sha != run.source.sha:
            raise ProvenanceDriftError(
                f"HEAD changed from {run.source.sha} to {current.sha}"
            )
        if current.dirty and not run.allow_dirty:
            raise ProvenanceDriftError("working tree changed after the run started")
        if run.allow_dirty and current.worktree_digest != run.source.worktree_digest:
            raise ProvenanceDriftError("dirty working tree changed after the run started")
        return self._execute(
            run_id,
            execute_external=execute_external,
            confirm_sha=confirm_sha,
            approve_candidate=approve_candidate,
            approval_actor=approval_actor,
            approval_reason=approval_reason,
        )

    def recover_stale(self, run_id: str) -> ReleaseRun:
        try:
            with self.ledger.lock_run(run_id):
                run = self.ledger.get_run(run_id)
                step = next(
                    (candidate for candidate in run.steps if candidate.status == "running"),
                    None,
                )
                if step is None:
                    return run
                status: StepStatus = (
                    "uncertain" if step.effect == "external" else "failed"
                )
                if step.effect == "external":
                    self.ledger.ensure_adapter_receipt_audit_event(
                        run_id, step.ordinal
                    )
                self.ledger.finish_step(
                    run_id,
                    step.ordinal,
                    status=status,
                    exit_code=None,
                    output_sha256=None,
                    output_preview=(
                        "Recovered a stale running attempt after its process lock was absent; "
                        "no retry was performed."
                    ),
                )
                self.ledger.append_audit_event(
                    run_id,
                    "attempt.recovered_stale",
                    {"ordinal": step.ordinal, "status": status},
                )
                return self.ledger.set_run_status(run_id, status)
        except RunBusyError:
            return self.ledger.get_run(run_id)

    def _authorize(
        self,
        run: ReleaseRun,
        *,
        execute_external: bool,
        confirm_sha: str | None,
        approve_candidate: str | None,
        approval_actor: str | None,
        approval_reason: str | None,
    ) -> None:
        stored_approval = self.ledger.get_approval(run.run_id)
        if (
            stored_approval is not None
            and stored_approval["candidate_digest"] == run.candidate_digest
        ):
            return
        if not execute_external:
            raise AuthorizationError("--execute-external is required")
        if confirm_sha != run.source.sha:
            raise AuthorizationError(
                f"--confirm-sha must equal exact source SHA {run.source.sha}"
            )
        if not run.candidate_digest or approve_candidate != run.candidate_digest:
            raise AuthorizationError(
                "--approve-candidate must equal the persisted release candidate digest"
            )
        if not approval_actor or not approval_reason:
            raise AuthorizationError("approval actor and reason are required")
        self.ledger.record_approval(
            run.run_id,
            run.candidate_digest,
            actor=approval_actor,
            reason=approval_reason,
        )

    def _verify_source(self, run: ReleaseRun, step: StepRun) -> None:
        current = snapshot_repository(run.repo_path)
        source_dirty = current.dirty and not run.allow_dirty
        dirty_source_drift = (
            run.allow_dirty and current.worktree_digest != run.source.worktree_digest
        )
        if current.sha == run.source.sha and not source_dirty and not dirty_source_drift:
            return
        detail = (
            "Source provenance drift detected before step "
            f"{step.id}: expected {run.source.sha}, current {current.sha}, "
            f"dirty={current.dirty}."
        )
        self.ledger.finish_step(
            run.run_id,
            step.ordinal,
            status="blocked",
            exit_code=None,
            output_sha256=None,
            output_preview=detail,
        )
        self.ledger.set_run_status(run.run_id, "failed")
        raise ProvenanceDriftError(detail)

    def _execute(
        self,
        run_id: str,
        *,
        execute_external: bool,
        confirm_sha: str | None,
        approve_candidate: str | None,
        approval_actor: str | None,
        approval_reason: str | None,
    ) -> ReleaseRun:
        run = self.ledger.get_run(run_id)
        for step in run.steps:
            if step.status == "succeeded":
                continue
            self._verify_source(run, step)
            dispatch_run = run
            if step.effect == "external":
                if (
                    not step.action
                    and os.environ.get("SHIPYARD_ENABLE_LEGACY_EXTERNAL") != "1"
                ):
                    raise AuthorizationError(
                        "legacy raw external commands are disabled; use a schema_version 2 "
                        "typed adapter action"
                    )
                candidate = build_candidate(self.ledger.get_run(run_id))
                current_run = self.ledger.get_run(run_id)
                if current_run.candidate_digest is None:
                    self.ledger.store_candidate(run_id, candidate.digest, candidate.payload)
                    self.ledger.finish_step(
                        run_id,
                        step.ordinal,
                        status="blocked",
                        exit_code=None,
                        output_sha256=None,
                        output_preview=(
                            "Release candidate prepared; approve digest "
                            f"{candidate.digest}."
                        ),
                    )
                    return self.ledger.set_run_status(
                        run_id, "awaiting_authorization"
                    )
                if candidate.digest != current_run.candidate_digest:
                    raise ProvenanceDriftError(
                        "release candidate changed after it was prepared; create a new run"
                    )
                self._authorize(
                    current_run,
                    execute_external=execute_external,
                    confirm_sha=confirm_sha,
                    approve_candidate=approve_candidate,
                    approval_actor=approval_actor,
                    approval_reason=approval_reason,
                )
                revalidated = build_candidate(self.ledger.get_run(run_id))
                if revalidated.digest != current_run.candidate_digest:
                    raise ProvenanceDriftError(
                        "release candidate changed immediately before external execution"
                    )
                if step.action:
                    try:
                        dispatch_run = prepare_execution_snapshot(
                            self.ledger.state_dir, current_run, revalidated
                        )
                        if current_run.provider == "buzz-git":
                            remote = step.config.get("remote")
                            if not isinstance(remote, str):
                                raise ProvenanceDriftError("Buzz Git remote is malformed")
                            readiness = inspect_buzz_git_auth(dispatch_run.repo_path, remote)
                            if not bool(readiness["ready"]):
                                raise ProvenanceDriftError(
                                    "Buzz Git authentication readiness changed before execution"
                                )
                        snapshot_candidate = build_candidate(dispatch_run)
                        if snapshot_candidate.digest != current_run.candidate_digest:
                            raise ProvenanceDriftError(
                                "immutable execution snapshot does not match the approved candidate"
                            )
                        freeze_execution_snapshot(dispatch_run.repo_path)
                    except ExecutionSnapshotError as exc:
                        raise ProvenanceDriftError(str(exc)) from exc
                    except ProvenanceDriftError:
                        self._cleanup_snapshot_with_audit(run_id)
                        raise
            try:
                if step.action:
                    step_status, exit_code, output_digest, output_preview = (
                        self._run_adapter_step(dispatch_run, step)
                    )
                else:
                    outcome = self._run_step(
                        run_id, dispatch_run.repo_path, dispatch_run.source.sha, step
                    )
                    step_status = (
                        "succeeded"
                        if outcome[0] == 0
                        else "uncertain"
                        if step.effect == "external"
                        else "failed"
                    )
                    exit_code, output_digest, output_preview = outcome
            except BaseException:
                interrupted_status = "uncertain" if step.effect == "external" else "failed"
                self.ledger.finish_step(
                    run_id,
                    step.ordinal,
                    status=interrupted_status,
                    exit_code=None,
                    output_sha256=None,
                    output_preview="Execution interrupted; descendants terminated.",
                )
                self.ledger.set_run_status(run_id, interrupted_status)
                raise
            self.ledger.finish_step(
                run_id,
                step.ordinal,
                status=step_status,
                exit_code=exit_code,
                output_sha256=output_digest,
                output_preview=output_preview,
            )
            if step_status != "succeeded":
                run_status = "uncertain" if step_status == "uncertain" else "failed"
                return self.ledger.set_run_status(run_id, run_status)
        completed = self.ledger.set_run_status(run_id, "succeeded")
        self._cleanup_snapshot_with_audit(run_id)
        return completed

    def _cleanup_snapshot_with_audit(self, run_id: str) -> None:
        try:
            cleanup_execution_snapshot(self.ledger.state_dir, run_id)
        except (ExecutionSnapshotError, OSError) as exc:
            self.ledger.append_audit_event(
                run_id,
                "snapshot.cleanup_failed",
                {
                    "message": redact(str(exc)),
                    "manual_cleanup_required": True,
                    "snapshot_run_id": run_id,
                },
            )

    def _run_step(
        self,
        run_id: str,
        repo_path: Path,
        source_sha: str,
        step: StepRun,
    ) -> tuple[int, str, str]:
        command = tuple(part.replace("{sha}", source_sha) for part in step.command)
        self.ledger.begin_step(run_id, step.ordinal)
        try:
            result = _run_process(command, repo_path, step.timeout_seconds)
            exit_code = result.returncode
            output = result.output_tail
            digest = result.output_sha256
            truncated = result.truncated
        except OSError as exc:
            exit_code = 127
            output = str(exc)
            digest = hashlib.sha256(output.encode("utf-8")).hexdigest()
            truncated = False
        sanitized = redact(output)
        truncation = "[output truncated to bounded tail]\n" if truncated else ""
        preview = f"{truncation}{sanitized[-4000:]}"
        return exit_code, digest, preview

    def _adapter_context(self, run: ReleaseRun, step: StepRun) -> AdapterContext:
        run = execution_snapshot_run(self.ledger.state_dir, run)
        config = dict(step.config)
        config["repo_path"] = str(run.repo_path)
        return AdapterContext(
            run_id=run.run_id,
            source_sha=run.source.sha,
            provider=run.provider,
            destination=run.destination,
            config=config,
        )

    def _run_adapter_step(
        self, run: ReleaseRun, step: StepRun
    ) -> tuple[StepStatus, int | None, str, str]:
        if step.action is None:
            raise RuntimeError("adapter execution requires an action")
        self.ledger.begin_step(run.run_id, step.ordinal)
        self.ledger.append_audit_event(
            run.run_id,
            "adapter.mutation_started",
            {
                "ordinal": step.ordinal,
                "action": step.action,
                "candidate_digest": run.candidate_digest,
                "source_sha": run.source.sha,
            },
        )
        adapter = self.adapters.get(step.action)
        context = self._adapter_context(run, step)
        try:
            receipt = adapter.execute(context)
            self.ledger.record_adapter_receipt(run.run_id, step.ordinal, receipt)
            readback = adapter.readback(context, receipt)
            self.ledger.record_adapter_readback(run.run_id, step.ordinal, readback)
        except AdapterError as exc:
            message = redact(str(exc))
            self.ledger.append_audit_event(
                run.run_id,
                "adapter.uncertain",
                {"ordinal": step.ordinal, "action": step.action, "message": message},
            )
            digest = hashlib.sha256(message.encode()).hexdigest()
            return "uncertain", None, digest, message[-4000:]
        evidence = json.dumps(
            {
                "receipt": {
                    "operation_id": receipt.operation_id,
                    "submitted_sha": receipt.submitted_sha,
                    "evidence": receipt.evidence,
                },
                "readback": {
                    "status": readback.status,
                    "observed_sha": readback.observed_sha,
                    "evidence": readback.evidence,
                },
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        digest = hashlib.sha256(evidence.encode()).hexdigest()
        if readback.status == "succeeded":
            return "succeeded", 0, digest, evidence[-4000:]
        if readback.status == "failed":
            return "failed", 1, digest, evidence[-4000:]
        return "uncertain", None, digest, evidence[-4000:]

    def readback_once(self, run_id: str) -> ProviderReadback:
        """Perform one authoritative provider read without changing run or audit state."""
        with self.ledger.lock_run(run_id):
            run = self.ledger.get_run(run_id)
            step = next(
                (
                    candidate
                    for candidate in run.steps
                    if candidate.effect == "external" and candidate.status == "uncertain"
                ),
                None,
            )
            if step is None or not step.action:
                raise UncertainOutcomeError(
                    "no typed uncertain adapter operation is available for readback"
                )
            receipt = self.ledger.get_adapter_receipt(run_id, step.ordinal)
            if receipt is None:
                raise UncertainOutcomeError(
                    "adapter operation has no durable receipt; manual provider "
                    "reconciliation is required"
                )
            adapter = self.adapters.get(step.action)
            return adapter.readback(self._adapter_context(run, step), receipt)

    def resolve(self, run_id: str) -> ReleaseRun:
        with self.ledger.lock_run(run_id):
            run = self.ledger.get_run(run_id)
            step = next(
                (
                    candidate
                    for candidate in run.steps
                    if candidate.effect == "external" and candidate.status == "uncertain"
                ),
                None,
            )
            if step is None or not step.action:
                raise UncertainOutcomeError(
                    "no typed uncertain adapter operation is available for readback"
                )
            receipt = self.ledger.get_adapter_receipt(run_id, step.ordinal)
            if receipt is None:
                raise UncertainOutcomeError(
                    "adapter operation has no durable receipt; manual provider "
                    "reconciliation is required"
                )
            self.ledger.ensure_adapter_receipt_audit_event(run_id, step.ordinal)
            adapter = self.adapters.get(step.action)
            readback: ProviderReadback = adapter.readback(
                self._adapter_context(run, step), receipt
            )
            self.ledger.record_adapter_readback(run_id, step.ordinal, readback)
            evidence = json.dumps(
                {
                    "status": readback.status,
                    "observed_sha": readback.observed_sha,
                    "evidence": readback.evidence,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
            digest = hashlib.sha256(evidence.encode()).hexdigest()
            if readback.status in {"pending", "unknown"}:
                return self.ledger.get_run(run_id)
            step_status: StepStatus = (
                "succeeded" if readback.status == "succeeded" else "failed"
            )
            self.ledger.finish_step(
                run_id,
                step.ordinal,
                status=step_status,
                exit_code=0 if step_status == "succeeded" else 1,
                output_sha256=digest,
                output_preview=evidence[-4000:],
            )
            if step_status == "failed":
                return self.ledger.set_run_status(run_id, "failed")
            self.ledger.set_run_status(run_id, "running")
            return self._execute(
                run_id,
                execute_external=True,
                confirm_sha=None,
                approve_candidate=None,
                approval_actor=None,
                approval_reason=None,
            )
