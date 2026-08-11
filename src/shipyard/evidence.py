from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import re
import stat
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, TypedDict

from .ledger import Ledger

_SCHEMA_VERSION = "shipyard.evidence/v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_SHA = re.compile(r"^[0-9a-f]{40}$")
_MAX_BUNDLE_BYTES = 2 * 1024 * 1024 * 1024
_MAX_RECORD_BYTES = 16 * 1024 * 1024
_MAX_BUNDLE_MEMBERS = 10_000
_RUN_STATUSES = {
    "running",
    "succeeded",
    "failed",
    "awaiting_authorization",
    "uncertain",
}
_STEP_STATUSES = {"pending", "running", "succeeded", "failed", "blocked", "uncertain"}
_ADAPTER_STATUSES = {"succeeded", "failed", "pending", "unknown"}
_EXPECTED_PROVIDERS = {
    "buzz.workflow": frozenset({"buzz"}),
    "github.workflow": frozenset({"github-actions"}),
    "git.ref": frozenset({"git", "github", "buzz-git"}),
    "render.deploy": frozenset({"render"}),
}


class EvidenceError(ValueError):
    pass


class _ArtifactEvidence(TypedDict):
    path: str
    size: int
    sha256: str


def _canonical_bytes(payload: object) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _sha256_bytes(payload: object) -> str:
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _sha256_stream(source: Any) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while chunk := source.read(1024 * 1024):
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


def _safe_artifact_path(value: object) -> str | None:
    if not isinstance(value, str) or not value or "\\" in value:
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value:
        return None
    if any(part in {"", ".", ".."} for part in path.parts):
        return None
    return value


def _portable_record(payload: dict[str, object]) -> dict[str, object]:
    record = copy.deepcopy(payload)
    source = record.get("source")
    if isinstance(source, dict):
        source.pop("path", None)
    steps = record.get("steps")
    if isinstance(steps, list):
        for step in steps:
            if not isinstance(step, dict):
                continue
            step.pop("output_preview", None)
            attempts = step.get("attempt_history")
            if isinstance(attempts, list):
                for attempt in attempts:
                    if isinstance(attempt, dict):
                        attempt.pop("output_preview", None)
    return record


def _candidate_artifacts(record: dict[str, object]) -> list[_ArtifactEvidence]:
    candidate = record.get("candidate")
    if not isinstance(candidate, dict):
        raise EvidenceError("run has no candidate record")
    payload = candidate.get("payload")
    if not isinstance(payload, dict):
        raise EvidenceError("run has no prepared candidate")
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):
        raise EvidenceError("candidate artifacts must be a list")
    parsed: list[_ArtifactEvidence] = []
    seen: set[str] = set()
    for item in artifacts:
        if not isinstance(item, dict):
            raise EvidenceError("candidate artifact entry must be an object")
        path = _safe_artifact_path(item.get("path"))
        size = item.get("size")
        digest = item.get("sha256")
        if path is None:
            raise EvidenceError("candidate artifact path is unsafe")
        if path in seen:
            raise EvidenceError(f"duplicate candidate artifact: {path}")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise EvidenceError(f"candidate artifact size is invalid: {path}")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise EvidenceError(f"candidate artifact digest is invalid: {path}")
        seen.add(path)
        parsed.append({"path": path, "size": size, "sha256": digest})
    return parsed


def _open_artifact_descriptor(repo_root: Path, relative: str) -> int:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise EvidenceError("platform lacks safe artifact-path traversal")
    parts = PurePosixPath(relative).parts
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        directory_descriptor = os.open(repo_root, directory_flags)
    except OSError as exc:
        raise EvidenceError("cannot bind the repository directory") from exc
    try:
        for part in parts[:-1]:
            try:
                metadata = os.stat(
                    part, dir_fd=directory_descriptor, follow_symlinks=False
                )
            except OSError as exc:
                raise EvidenceError(
                    f"approved artifact is unavailable: {relative}"
                ) from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise EvidenceError(
                    f"artifact path cannot contain symlinks: {relative}"
                )
            if not stat.S_ISDIR(metadata.st_mode):
                raise EvidenceError(
                    f"artifact parent is not a directory: {relative}"
                )
            try:
                next_descriptor = os.open(
                    part, directory_flags, dir_fd=directory_descriptor
                )
            except OSError as exc:
                raise EvidenceError(
                    f"artifact path cannot be opened safely: {relative}"
                ) from exc
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        filename = parts[-1]
        try:
            metadata = os.stat(
                filename, dir_fd=directory_descriptor, follow_symlinks=False
            )
        except OSError as exc:
            raise EvidenceError(f"approved artifact is unavailable: {relative}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise EvidenceError(
                f"artifact path cannot contain symlinks: {relative}"
            )
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceError(
                f"approved artifact is not a regular file: {relative}"
            )
        try:
            descriptor = os.open(
                filename,
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=directory_descriptor,
            )
        except OSError as exc:
            raise EvidenceError(
                f"artifact path cannot be opened safely: {relative}"
            ) from exc
        opened_metadata = os.fstat(descriptor)
        if not stat.S_ISREG(opened_metadata.st_mode):
            os.close(descriptor)
            raise EvidenceError(
                f"approved artifact is not a regular file: {relative}"
            )
        return descriptor
    finally:
        os.close(directory_descriptor)


def _tar_info(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o600
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def export_evidence_bundle(
    ledger: Ledger, run_id: str, output: str | Path
) -> Path:
    run = ledger.get_run(run_id)
    if not ledger.verify_audit_chain(run_id):
        raise EvidenceError("refusing to export an invalid audit chain")
    record = _portable_record(ledger.manifest_payload(run))
    candidate = record.get("candidate")
    if not isinstance(candidate, dict) or not isinstance(candidate.get("payload"), dict):
        raise EvidenceError("run has no prepared candidate")
    if not isinstance(candidate.get("approval"), dict):
        raise EvidenceError("run has no candidate approval")
    digest = candidate.get("digest")
    if not isinstance(digest, str) or digest != _sha256_bytes(candidate["payload"]):
        raise EvidenceError("stored candidate digest is invalid")
    artifacts = _candidate_artifacts(record)
    declared_artifact_bytes = sum(artifact["size"] for artifact in artifacts)
    if len(artifacts) + 1 > _MAX_BUNDLE_MEMBERS:
        raise EvidenceError("candidate declares too many artifacts")

    destination = Path(output).expanduser()
    if destination.name in {"", ".", ".."}:
        raise EvidenceError("output must name a bundle file")
    try:
        parent = destination.parent.resolve(strict=True)
    except OSError as exc:
        raise EvidenceError(f"cannot open output directory: {destination.parent}") from exc
    destination = parent / destination.name
    if os.path.lexists(destination):
        raise EvidenceError(f"refusing to overwrite existing file: {destination}")

    envelope = {
        "schema_version": _SCHEMA_VERSION,
        "record_sha256": _sha256_bytes(record),
        "run": record,
    }
    evidence_bytes = (json.dumps(envelope, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(evidence_bytes) > _MAX_RECORD_BYTES:
        raise EvidenceError("evidence record exceeds the size limit")
    if len(evidence_bytes) + declared_artifact_bytes > _MAX_BUNDLE_BYTES:
        raise EvidenceError("evidence bundle contents exceed the size limit")
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".shipyard-evidence-", dir=parent
        )
    except OSError as exc:
        raise EvidenceError(f"cannot write evidence bundle: {exc}") from exc
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w+b", closefd=False) as raw_bundle:
            with tarfile.open(
                fileobj=raw_bundle, mode="w", format=tarfile.GNU_FORMAT
            ) as archive:
                archive.addfile(
                    _tar_info("evidence.json", len(evidence_bytes)),
                    io.BytesIO(evidence_bytes),
                )
                repo_root = run.repo_path.resolve()
                for artifact in artifacts:
                    relative = str(artifact["path"])
                    source_descriptor = _open_artifact_descriptor(
                        repo_root, relative
                    )
                    try:
                        metadata = os.fstat(source_descriptor)
                        if not stat.S_ISREG(metadata.st_mode):
                            raise EvidenceError(
                                f"approved artifact is not a regular file: {relative}"
                            )
                        with os.fdopen(
                            source_descriptor, "rb", closefd=False
                        ) as source:
                            digest, size = _sha256_stream(source)
                            if size != artifact["size"] or digest != artifact["sha256"]:
                                raise EvidenceError(
                                    f"approved artifact changed: {relative}"
                                )
                            source.seek(0)
                            archive.addfile(
                                _tar_info(f"artifacts/{relative}", size), source
                            )
                    finally:
                        os.close(source_descriptor)
            raw_bundle.flush()
            os.fsync(descriptor)
        report = verify_evidence_bundle(temporary)
        if not report["valid"]:
            failures = report.get("errors")
            detail = (
                "; ".join(str(error) for error in failures)
                if isinstance(failures, list)
                else "unknown verification failure"
            )
            raise EvidenceError(
                "generated evidence bundle failed verification: " + detail
            )
        try:
            os.link(temporary, destination)
        except FileExistsError as exc:
            raise EvidenceError(f"refusing to overwrite existing file: {destination}") from exc
        directory_flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        directory_descriptor = os.open(parent, directory_flags)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        return destination
    except EvidenceError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise EvidenceError(f"cannot write evidence bundle: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _invalid_report(errors: list[str]) -> dict[str, object]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "valid": False,
        "run_id": None,
        "status": None,
        "source_sha": None,
        "candidate_digest": None,
        "record_sha256_valid": False,
        "audit_chain_valid": False,
        "artifacts_declared": 0,
        "artifacts_verified": 0,
        "receipts_verified": 0,
        "approval_present": False,
        "errors": errors,
    }


def _load_json(content: bytes) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise EvidenceError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise EvidenceError(f"non-finite JSON constant: {value}")

    return json.loads(
        content,
        object_pairs_hook=reject_duplicates,
        parse_constant=reject_constant,
    )


def _verify_audit_chain(run_id: str, events: object) -> tuple[bool, list[str]]:
    if not isinstance(events, list):
        return False, ["audit events must be a list"]
    if not events:
        return False, ["audit chain is empty"]
    previous_hash = "0" * 64
    previous_sequence = -1
    for event in events:
        if not isinstance(event, dict):
            return False, ["audit event must be an object"]
        sequence = event.get("sequence")
        event_type = event.get("event_type")
        payload = event.get("payload")
        created_at = event.get("created_at")
        recorded_previous = event.get("previous_hash")
        event_hash = event.get("event_hash")
        if (
            not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or sequence <= previous_sequence
        ):
            return False, ["audit event sequence is not strictly increasing"]
        if not isinstance(event_type, str) or not isinstance(payload, dict) or not isinstance(
            created_at, str
        ):
            return False, ["audit event fields are invalid"]
        canonical_payload = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        material = "\0".join(
            (run_id, event_type, canonical_payload, created_at, previous_hash)
        )
        expected = hashlib.sha256(material.encode()).hexdigest()
        if recorded_previous != previous_hash or event_hash != expected:
            return False, [f"audit chain mismatch at sequence {sequence}"]
        previous_sequence = sequence
        previous_hash = expected
    return True, []


@dataclass(frozen=True)
class _RecordIdentity:
    record_sha256_valid: bool
    run_id: object
    run_id_for_chain: str
    status: object
    source_sha: object
    candidate_digest: object
    approval: object


@dataclass(frozen=True)
class _AuditEvidence:
    audit_valid: bool
    receipts: dict[str, dict[str, object]]
    readbacks: dict[str, list[dict[str, object]]]


def _verify_record_identity(
    record: dict[str, object], record_digest: object
) -> tuple[_RecordIdentity, list[str]]:
    errors: list[str] = []
    actual_record_digest = _sha256_bytes(record)
    record_sha256_valid = (
        isinstance(record_digest, str)
        and _SHA256.fullmatch(record_digest) is not None
        and record_digest == actual_record_digest
    )
    if not record_sha256_valid:
        errors.append("record digest does not match canonical run record")

    run_id = record.get("run_id")
    status = record.get("status")
    source = record.get("source")
    source_sha = source.get("sha") if isinstance(source, dict) else None
    if not isinstance(run_id, str) or not run_id:
        errors.append("run id is invalid")
        run_id_for_chain = ""
    else:
        run_id_for_chain = run_id
    if not isinstance(source_sha, str) or not _SOURCE_SHA.fullmatch(source_sha):
        errors.append("run source SHA is invalid")
    if not isinstance(status, str) or status not in _RUN_STATUSES:
        errors.append("run status is invalid")

    candidate = record.get("candidate")
    candidate_digest = candidate.get("digest") if isinstance(candidate, dict) else None
    candidate_payload = candidate.get("payload") if isinstance(candidate, dict) else None
    approval = candidate.get("approval") if isinstance(candidate, dict) else None
    if not isinstance(candidate_digest, str) or not _SHA256.fullmatch(candidate_digest):
        errors.append("candidate digest is invalid")
    if not isinstance(candidate_payload, dict):
        errors.append("candidate payload is missing")
    elif candidate_digest != _sha256_bytes(candidate_payload):
        errors.append("candidate digest does not match candidate payload")
    candidate_source = (
        candidate_payload.get("source") if isinstance(candidate_payload, dict) else None
    )
    candidate_source_sha = (
        candidate_source.get("sha") if isinstance(candidate_source, dict) else None
    )
    if candidate_source_sha != source_sha:
        errors.append("candidate source SHA does not match run source SHA")
    if approval is not None and (
        not isinstance(approval, dict)
        or approval.get("candidate_digest") != candidate_digest
    ):
        errors.append("approval does not match candidate digest")
    if isinstance(approval, dict):
        if approval.get("run_id") != run_id:
            errors.append("approval does not match run id")
        if not isinstance(approval.get("actor"), str) or not approval["actor"].strip():
            errors.append("approval actor is invalid")
        if not isinstance(approval.get("reason"), str) or not approval["reason"].strip():
            errors.append("approval reason is invalid")
        if not isinstance(approval.get("approved_at"), str) or not approval["approved_at"]:
            errors.append("approval timestamp is invalid")
    if approval is None:
        errors.append("evidence lacks candidate approval")

    return (
        _RecordIdentity(
            record_sha256_valid=record_sha256_valid,
            run_id=run_id,
            run_id_for_chain=run_id_for_chain,
            status=status,
            source_sha=source_sha,
            candidate_digest=candidate_digest,
            approval=approval,
        ),
        errors,
    )


def _collect_audit_evidence(
    record: dict[str, object], identity: _RecordIdentity
) -> tuple[_AuditEvidence, list[str]]:
    errors: list[str] = []
    events = record.get("audit_events")
    audit_valid, audit_errors = _verify_audit_chain(identity.run_id_for_chain, events)
    errors.extend(audit_errors)
    readbacks: dict[str, list[dict[str, object]]] = {}
    receipts: dict[str, dict[str, object]] = {}
    run_created_events = 0
    candidate_prepared_events = 0
    candidate_approved_events = 0
    if isinstance(events, list):
        for event in events:
            if not isinstance(event, dict) or not isinstance(event.get("payload"), dict):
                continue
            payload = event["payload"]
            if event.get("event_type") == "run.created":
                run_created_events += 1
                if payload.get("source_sha") != identity.source_sha:
                    errors.append("run-created event does not match source SHA")
            elif event.get("event_type") == "candidate.prepared":
                candidate_prepared_events += 1
                if payload.get("candidate_digest") != identity.candidate_digest:
                    errors.append(
                        "prepared-candidate event does not match candidate digest"
                    )
            elif event.get("event_type") == "candidate.approved":
                candidate_approved_events += 1
                if payload.get("candidate_digest") != identity.candidate_digest:
                    errors.append("approval event does not match candidate digest")
            elif event.get("event_type") == "adapter.receipt":
                operation_id = payload.get("operation_id")
                if not isinstance(operation_id, str) or not operation_id:
                    errors.append("adapter receipt operation id is invalid")
                elif operation_id in receipts:
                    errors.append(
                        f"duplicate adapter receipt operation id: {operation_id}"
                    )
                else:
                    receipts[operation_id] = payload
            elif event.get("event_type") == "adapter.readback":
                operation_id = payload.get("operation_id")
                if not isinstance(operation_id, str) or not operation_id:
                    errors.append("adapter readback operation id is invalid")
                else:
                    readbacks.setdefault(operation_id, []).append(payload)
    if audit_valid:
        if run_created_events != 1:
            errors.append("run-created audit event is missing or duplicated")
        if candidate_prepared_events == 0:
            errors.append("candidate prepared audit event is missing")
        elif candidate_prepared_events > 1:
            errors.append("candidate prepared audit event is duplicated")
        if identity.approval is not None and candidate_approved_events != 1:
            errors.append("candidate approval audit event is missing or duplicated")
    return (
        _AuditEvidence(
            audit_valid=audit_valid,
            receipts=receipts,
            readbacks=readbacks,
        ),
        errors,
    )


def _collect_steps(
    record: dict[str, object], status: object
) -> tuple[dict[str, dict[str, object]], list[str]]:
    errors: list[str] = []
    steps = record.get("steps")
    steps_by_operation: dict[str, dict[str, object]] = {}
    if not isinstance(steps, list):
        errors.append("steps must be a list")
        return steps_by_operation, errors
    if status == "succeeded" and any(
        not isinstance(step, dict) or step.get("status") != "succeeded"
        for step in steps
    ):
        errors.append("successful run contains a non-successful step")
    for step in steps:
        if not isinstance(step, dict):
            continue
        step_status = step.get("status")
        if not isinstance(step_status, str) or step_status not in _STEP_STATUSES:
            errors.append("step status is invalid")
        operation_id = step.get("operation_id")
        if not isinstance(operation_id, str):
            if status == "succeeded" and step.get("effect") == "external":
                errors.append(
                    f"successful external step lacks operation id: {step.get('id')}"
                )
            continue
        if operation_id in steps_by_operation:
            errors.append(f"duplicate step operation id: {operation_id}")
        else:
            steps_by_operation[operation_id] = step
    return steps_by_operation, errors


def _verify_readback_histories(
    readbacks: dict[str, list[dict[str, object]]],
    source_sha: object,
) -> list[str]:
    errors: list[str] = []
    for operation_id, history in readbacks.items():
        terminal_seen = False
        for readback in history:
            readback_status = readback.get("status")
            if (
                not isinstance(readback_status, str)
                or readback_status not in _ADAPTER_STATUSES
            ):
                errors.append(f"adapter readback status is invalid: {operation_id}")
            if terminal_seen:
                errors.append(f"adapter readback follows terminal state: {operation_id}")
                break
            observed_sha = readback.get("observed_sha")
            if observed_sha is not None and observed_sha != source_sha:
                errors.append(f"provider readback SHA mismatch: {operation_id}")
            if isinstance(readback_status, str) and readback_status in {
                "succeeded",
                "failed",
            }:
                terminal_seen = True
    return errors


def _verify_receipts(
    *,
    status: object,
    source_sha: object,
    receipts: dict[str, dict[str, object]],
    readbacks: dict[str, list[dict[str, object]]],
    steps_by_operation: dict[str, dict[str, object]],
) -> tuple[int, list[str]]:
    errors: list[str] = []
    receipts_verified = 0
    for operation_id, receipt in receipts.items():
        receipt_valid = True
        if receipt.get("submitted_sha") != source_sha:
            errors.append(f"adapter receipt source SHA mismatch: {operation_id}")
            receipt_valid = False
        step = steps_by_operation.get(operation_id)
        if step is None:
            errors.append(f"adapter receipt has no matching step: {operation_id}")
            continue
        receipt_ordinal = receipt.get("ordinal")
        if receipt_ordinal is not None and (
            type(receipt_ordinal) is not int
            or receipt_ordinal != step.get("ordinal")
        ):
            errors.append(
                f"adapter receipt ordinal does not match step: {operation_id}"
            )
            receipt_valid = False
        action = step.get("action")
        if receipt.get("action") != action:
            errors.append(f"adapter receipt action does not match step: {operation_id}")
            receipt_valid = False
        else:
            expected_providers = _EXPECTED_PROVIDERS.get(str(action))
            receipt_provider = receipt.get("provider")
            if (
                expected_providers is not None
                and (
                    not isinstance(receipt_provider, str)
                    or receipt_provider not in expected_providers
                )
            ):
                errors.append(
                    f"adapter receipt provider does not match action: {operation_id}"
                )
                receipt_valid = False
        readback_history = readbacks.get(operation_id, [])
        readback = readback_history[-1] if readback_history else None
        if status == "succeeded":
            if readback is None or readback.get("status") != "succeeded":
                errors.append(f"successful run lacks successful readback: {operation_id}")
                receipt_valid = False
            elif readback.get("observed_sha") != source_sha:
                errors.append(f"provider readback SHA mismatch: {operation_id}")
                receipt_valid = False
        if readback is not None:
            if step.get("readback") != readback:
                errors.append(
                    f"step readback does not match its audit event: {operation_id}"
                )
                receipt_valid = False
            if step.get("provider_status") != readback.get("status"):
                errors.append(
                    f"step provider status does not match readback: {operation_id}"
                )
                receipt_valid = False
        if receipt_valid:
            receipts_verified += 1
    return receipts_verified, errors


def _verify_provider_evidence(
    record: dict[str, object],
    identity: _RecordIdentity,
    audit: _AuditEvidence,
) -> tuple[int, list[str]]:
    errors: list[str] = []
    steps_by_operation, step_errors = _collect_steps(record, identity.status)
    errors.extend(step_errors)
    errors.extend(_verify_readback_histories(audit.readbacks, identity.source_sha))
    receipts_verified, receipt_errors = _verify_receipts(
        status=identity.status,
        source_sha=identity.source_sha,
        receipts=audit.receipts,
        readbacks=audit.readbacks,
        steps_by_operation=steps_by_operation,
    )
    errors.extend(receipt_errors)
    for operation_id in steps_by_operation:
        if operation_id not in audit.receipts:
            errors.append(f"step operation is missing its audit receipt: {operation_id}")
    for operation_id in audit.readbacks:
        if operation_id not in audit.receipts:
            errors.append(f"adapter readback has no matching receipt: {operation_id}")
    return receipts_verified, errors


def _verify_record(record: dict[str, object], record_digest: object) -> dict[str, object]:
    identity, errors = _verify_record_identity(record, record_digest)
    audit, audit_errors = _collect_audit_evidence(record, identity)
    errors.extend(audit_errors)
    receipts_verified, provider_errors = _verify_provider_evidence(
        record, identity, audit
    )
    errors.extend(provider_errors)
    try:
        artifacts = _candidate_artifacts(record)
    except EvidenceError as exc:
        artifacts = []
        errors.append(str(exc))
    return {
        "schema_version": _SCHEMA_VERSION,
        "valid": not errors,
        "run_id": identity.run_id if isinstance(identity.run_id, str) else None,
        "status": identity.status if isinstance(identity.status, str) else None,
        "source_sha": (
            identity.source_sha if isinstance(identity.source_sha, str) else None
        ),
        "candidate_digest": (
            identity.candidate_digest
            if isinstance(identity.candidate_digest, str)
            else None
        ),
        "record_sha256_valid": identity.record_sha256_valid,
        "audit_chain_valid": audit.audit_valid,
        "artifacts_declared": len(artifacts),
        "artifacts_verified": 0,
        "receipts_verified": receipts_verified,
        "approval_present": identity.approval is not None,
        "errors": errors,
        "_artifacts": artifacts,
    }


def verify_evidence_bundle(bundle: str | Path) -> dict[str, object]:
    path = Path(bundle).expanduser()
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        return _invalid_report([f"cannot open evidence bundle: {exc.strerror}"])
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            return _invalid_report(["evidence bundle must be a regular file"])
        if metadata.st_size > _MAX_BUNDLE_BYTES:
            return _invalid_report(["evidence bundle exceeds the size limit"])
        with os.fdopen(descriptor, "rb", closefd=False) as raw:
            try:
                with tarfile.open(fileobj=raw, mode="r:") as archive:
                    members: list[tarfile.TarInfo] = []
                    for member in archive:
                        if len(members) >= _MAX_BUNDLE_MEMBERS:
                            return _invalid_report(["bundle contains too many members"])
                        members.append(member)
                    by_name: dict[str, tarfile.TarInfo] = {}
                    unsafe_members: list[str] = []
                    total_size = 0
                    for member in members:
                        total_size += member.size
                        name = member.name
                        path_parts = PurePosixPath(name)
                        safe = (
                            member.isreg()
                            and not path_parts.is_absolute()
                            and all(part not in {"", ".", ".."} for part in path_parts.parts)
                            and name not in by_name
                        )
                        if not safe:
                            unsafe_members.append(name)
                        else:
                            by_name[name] = member
                    if total_size > _MAX_BUNDLE_BYTES:
                        return _invalid_report(["bundle contents exceed the size limit"])
                    evidence_member = by_name.get("evidence.json")
                    if evidence_member is None:
                        return _invalid_report(["bundle is missing evidence.json"])
                    if evidence_member.size > _MAX_RECORD_BYTES:
                        return _invalid_report(["evidence record exceeds the size limit"])
                    evidence_file = archive.extractfile(evidence_member)
                    if evidence_file is None:
                        return _invalid_report(["cannot read evidence.json"])
                    try:
                        envelope = _load_json(evidence_file.read())
                    except (EvidenceError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                        return _invalid_report([f"invalid evidence JSON: {exc}"])
                    if not isinstance(envelope, dict):
                        return _invalid_report(["evidence JSON must be an object"])
                    if set(envelope) != {"schema_version", "record_sha256", "run"}:
                        return _invalid_report(["evidence envelope fields are invalid"])
                    if envelope.get("schema_version") != _SCHEMA_VERSION:
                        return _invalid_report(["unsupported evidence schema version"])
                    record = envelope.get("run")
                    if not isinstance(record, dict):
                        return _invalid_report(["evidence run record must be an object"])
                    report = _verify_record(record, envelope.get("record_sha256"))
                    artifacts = report.pop("_artifacts")
                    assert isinstance(artifacts, list)
                    expected_names = {"evidence.json"}
                    expected_names.update(
                        f"artifacts/{artifact['path']}" for artifact in artifacts
                    )
                    errors = report["errors"]
                    assert isinstance(errors, list)
                    for name in unsafe_members:
                        if name in expected_names:
                            errors.append(f"duplicate or unsafe bundle member: {name}")
                        else:
                            errors.append(f"unsafe or undeclared bundle member: {name}")
                    for name in by_name:
                        if name in expected_names:
                            continue
                        errors.append(f"unsafe or undeclared bundle member: {name}")
                    verified = 0
                    for artifact in artifacts:
                        relative = str(artifact["path"])
                        member = by_name.get(f"artifacts/{relative}")
                        if member is None:
                            errors.append(f"bundle artifact is missing: {relative}")
                            continue
                        artifact_file = archive.extractfile(member)
                        if artifact_file is None:
                            errors.append(f"cannot read bundle artifact: {relative}")
                            continue
                        digest, size = _sha256_stream(artifact_file)
                        if size != artifact["size"]:
                            errors.append(f"artifact size mismatch: {relative}")
                        elif digest != artifact["sha256"]:
                            errors.append(f"artifact hash mismatch: {relative}")
                        else:
                            verified += 1
                    report["artifacts_verified"] = verified
                    report["valid"] = not errors
                    return report
            except (tarfile.TarError, OSError) as exc:
                return _invalid_report([f"invalid evidence archive: {exc}"])
    finally:
        os.close(descriptor)
