from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import io
import json
import os
import subprocess
import sys
import tarfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import shipyard.evidence as evidence_module
from shipyard.adapters.base import MutationReceipt, ProviderReadback
from shipyard.candidate import build_candidate
from shipyard.evidence import (
    EvidenceError,
    export_evidence_bundle,
    verify_evidence_bundle,
)
from shipyard.executor import ReleaseExecutor
from shipyard.ledger import Ledger
from shipyard.playbook import load_playbook


def _canonical_sha256(payload: object) -> str:
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(canonical).hexdigest()


def _rehash_audit_events(run_id: str, events: list[dict[str, object]]) -> None:
    previous = "0" * 64
    for event in events:
        event["previous_hash"] = previous
        material = "\0".join(
            (
                run_id,
                str(event["event_type"]),
                json.dumps(event["payload"], separators=(",", ":"), sort_keys=True),
                str(event["created_at"]),
                previous,
            )
        )
        previous = hashlib.sha256(material.encode()).hexdigest()
        event["event_hash"] = previous


def _completed_run(git_repo: Path, tmp_path: Path):
    artifact = git_repo / "dist" / "release.bin"
    artifact.parent.mkdir()
    artifact.write_bytes(b"approved release artifact\n")
    subprocess.run(["git", "add", "dist/release.bin"], cwd=git_repo, check=True)
    subprocess.run(["git", "commit", "-qm", "add release artifact"], cwd=git_repo, check=True)
    playbook_path = tmp_path / "shipyard.toml"
    playbook_path.write_text(
        '''schema_version = 1
name = "portable-evidence"
target = "local"

[[artifacts]]
path = "dist/release.bin"

[[steps]]
id = "verify"
name = "Verify source"
effect = "verify"
command = ["git", "status", "--short"]
''',
        encoding="utf-8",
    )
    ledger = Ledger(tmp_path / "state")
    run = ReleaseExecutor(ledger).start(git_repo, load_playbook(playbook_path))
    candidate = build_candidate(run)
    ledger.store_candidate(run.run_id, candidate.digest, candidate.payload)
    ledger.record_approval(
        run.run_id,
        candidate.digest,
        actor="release-reviewer",
        reason="approved exact candidate",
    )
    return ledger, ledger.get_run(run.run_id)


def _completed_provider_run(
    git_repo: Path,
    tmp_path: Path,
    *,
    observed_sha: str | None = None,
    approve: bool = True,
    pending_before_terminal: bool = False,
    terminal_before_terminal: bool = False,
    pending_observed_sha: str | None = None,
    pending_status: Any = "pending",
):
    artifact = git_repo / "dist" / "release.bin"
    artifact.parent.mkdir()
    artifact.write_bytes(b"approved provider artifact\n")
    subprocess.run(["git", "add", "dist/release.bin"], cwd=git_repo, check=True)
    subprocess.run(["git", "commit", "-qm", "add provider artifact"], cwd=git_repo, check=True)
    subprocess.run(
        ["git", "remote", "add", "origin", "git@github.com:example/project.git"],
        cwd=git_repo,
        check=True,
    )
    playbook_path = tmp_path / "provider.toml"
    playbook_path.write_text(
        '''schema_version = 2
name = "portable-provider-evidence"
target = "sandbox"
provider = "git"
destination = "origin:refs/heads/release"

[[artifacts]]
path = "dist/release.bin"

[[steps]]
id = "verify"
name = "Verify source"
effect = "verify"
command = ["git", "status", "--short"]

[[steps]]
id = "publish"
name = "Publish exact ref"
effect = "external"
action = "git.ref"

[steps.config]
remote = "origin"
ref = "refs/heads/release"
''',
        encoding="utf-8",
    )
    ledger = Ledger(tmp_path / "state")
    run = ReleaseExecutor(ledger).start(git_repo, load_playbook(playbook_path))
    assert run.candidate_digest is not None
    if not approve:
        return ledger, run
    ledger.record_approval(
        run.run_id,
        run.candidate_digest,
        actor="release-reviewer",
        reason="approved exact provider candidate",
    )
    operation_id = "git-123456789"
    ledger.begin_step(run.run_id, 1)
    ledger.record_adapter_receipt(
        run.run_id,
        1,
        MutationReceipt(
            provider="git",
            action="git.ref",
            operation_id=operation_id,
            submitted_sha=run.source_sha,
            evidence={"ref": "refs/heads/release", "remote": "origin"},
        ),
    )
    if pending_before_terminal:
        ledger.record_adapter_readback(
            run.run_id,
            1,
            ProviderReadback(
                status=pending_status,
                operation_id=operation_id,
                observed_sha=pending_observed_sha or run.source_sha,
                evidence={"provider_status": "queued"},
            ),
        )
    if terminal_before_terminal:
        ledger.record_adapter_readback(
            run.run_id,
            1,
            ProviderReadback(
                status="succeeded",
                operation_id=operation_id,
                observed_sha=run.source_sha,
                evidence={"provider_status": "completed"},
            ),
        )
    ledger.record_adapter_readback(
        run.run_id,
        1,
        ProviderReadback(
            status="succeeded",
            operation_id=operation_id,
            observed_sha=observed_sha or run.source_sha,
            evidence={"ref": "refs/heads/release", "remote": "origin"},
        ),
    )
    ledger.finish_step(
        run.run_id,
        1,
        status="succeeded",
        exit_code=0,
        output_sha256=hashlib.sha256(b"provider succeeded").hexdigest(),
        output_preview="provider succeeded",
    )
    return ledger, ledger.set_run_status(run.run_id, "succeeded")


def _rewrite_bundle(
    source: Path,
    destination: Path,
    transform: Callable[[list[tuple[str, bytes]]], list[tuple[str, bytes]]],
) -> None:
    with tarfile.open(source, "r:") as archive:
        members: list[tuple[str, bytes]] = []
        for member in archive.getmembers():
            extracted = archive.extractfile(member)
            assert extracted is not None
            members.append((member.name, extracted.read()))
    members = transform(members)
    with tarfile.open(destination, "w", format=tarfile.GNU_FORMAT) as archive:
        for name, content in members:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o600
            info.mtime = 0
            archive.addfile(info, io.BytesIO(content))


def _mutate_evidence_record(
    source: Path,
    destination: Path,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    def transform(members: list[tuple[str, bytes]]) -> list[tuple[str, bytes]]:
        rewritten = []
        for name, content in members:
            if name == "evidence.json":
                envelope = json.loads(content)
                record = envelope["run"]
                mutate(record)
                envelope["record_sha256"] = _canonical_sha256(record)
                content = (json.dumps(envelope, indent=2, sort_keys=True) + "\n").encode()
            rewritten.append((name, content))
        return rewritten

    _rewrite_bundle(source, destination, transform)


def _run_cli(args: list[str], *, cwd: Path):
    environment = os.environ.copy()
    source = Path(__file__).parents[1] / "src"
    environment["PYTHONPATH"] = f"{source}{os.pathsep}{environment.get('PYTHONPATH', '')}"
    return subprocess.run(
        [sys.executable, "-m", "shipyard", *args],
        cwd=cwd,
        env=environment,
        text=True,
        capture_output=True,
    )


def test_record_verifier_remains_a_bounded_orchestrator():
    source = inspect.getsource(evidence_module._verify_record)
    function = ast.parse(source).body[0]

    assert isinstance(function, ast.FunctionDef)
    assert function.end_lineno is not None
    assert function.end_lineno <= 50


def test_record_verification_stages_are_behaviorally_isolated(git_repo, tmp_path):
    ledger, run = _completed_provider_run(git_repo, tmp_path)
    bundle = export_evidence_bundle(ledger, run.run_id, tmp_path / "isolation.tar")
    with tarfile.open(bundle, "r:") as archive:
        evidence_file = archive.extractfile("evidence.json")
        assert evidence_file is not None
        envelope = json.load(evidence_file)

    record = envelope["run"]
    record_snapshot = copy.deepcopy(record)
    identity, identity_errors = evidence_module._verify_record_identity(
        record, envelope["record_sha256"]
    )
    audit, audit_errors = evidence_module._collect_audit_evidence(record, identity)
    steps_by_operation, step_errors = evidence_module._collect_steps(
        record, identity.status
    )
    readback_errors = evidence_module._verify_readback_histories(
        audit.readbacks, identity.source_sha
    )
    receipts_verified, receipt_errors = evidence_module._verify_receipts(
        status=identity.status,
        source_sha=identity.source_sha,
        receipts=audit.receipts,
        readbacks=audit.readbacks,
        steps_by_operation=steps_by_operation,
    )
    provider_receipts_verified, provider_errors = (
        evidence_module._verify_provider_evidence(record, identity, audit)
    )
    error_lists = [
        identity_errors,
        audit_errors,
        step_errors,
        readback_errors,
        receipt_errors,
        provider_errors,
    ]

    assert record == record_snapshot
    assert receipts_verified == provider_receipts_verified == 1
    assert all(errors == [] for errors in error_lists)
    assert len({id(errors) for errors in error_lists}) == len(error_lists)

    identity_errors.append("sentinel")
    assert all("sentinel" not in errors for errors in error_lists[1:])


def test_git_ref_receipts_accept_only_supported_provider_identities(git_repo, tmp_path):
    ledger, run = _completed_provider_run(git_repo, tmp_path)
    bundle = export_evidence_bundle(ledger, run.run_id, tmp_path / "providers.tar")
    with tarfile.open(bundle, "r:") as archive:
        evidence_file = archive.extractfile("evidence.json")
        assert evidence_file is not None
        envelope = json.load(evidence_file)

    record = envelope["run"]
    identity, identity_errors = evidence_module._verify_record_identity(
        record, envelope["record_sha256"]
    )
    audit, audit_errors = evidence_module._collect_audit_evidence(record, identity)
    steps_by_operation, step_errors = evidence_module._collect_steps(
        record, identity.status
    )
    assert identity_errors == audit_errors == step_errors == []

    for provider in ("git", "github", "buzz-git"):
        candidate_audit = copy.deepcopy(audit)
        next(iter(candidate_audit.receipts.values()))["provider"] = provider
        verified, errors = evidence_module._verify_receipts(
            status=identity.status,
            source_sha=identity.source_sha,
            receipts=candidate_audit.receipts,
            readbacks=candidate_audit.readbacks,
            steps_by_operation=steps_by_operation,
        )
        assert verified == 1
        assert errors == []

    for invalid_provider in ("render", [], {}):
        invalid_audit = copy.deepcopy(audit)
        operation_id = next(iter(invalid_audit.receipts))
        invalid_audit.receipts[operation_id]["provider"] = invalid_provider
        verified, errors = evidence_module._verify_receipts(
            status=identity.status,
            source_sha=identity.source_sha,
            receipts=invalid_audit.receipts,
            readbacks=invalid_audit.readbacks,
            steps_by_operation=steps_by_operation,
        )
        assert verified == 0
        assert errors == [f"adapter receipt provider does not match action: {operation_id}"]


def test_exported_bundle_is_deterministic_and_verifies_offline(git_repo, tmp_path):
    ledger, run = _completed_run(git_repo, tmp_path)
    first = export_evidence_bundle(ledger, run.run_id, tmp_path / "first.tar")
    second = export_evidence_bundle(ledger, run.run_id, tmp_path / "second.tar")

    assert first.read_bytes() == second.read_bytes()
    report = verify_evidence_bundle(first)
    assert report == {
        "schema_version": "shipyard.evidence/v1",
        "valid": True,
        "run_id": run.run_id,
        "status": "succeeded",
        "source_sha": run.source_sha,
        "candidate_digest": run.candidate_digest,
        "record_sha256_valid": True,
        "audit_chain_valid": True,
        "artifacts_declared": 1,
        "artifacts_verified": 1,
        "receipts_verified": 0,
        "approval_present": True,
        "errors": [],
    }
    with tarfile.open(first, "r:") as archive:
        assert archive.getnames() == ["evidence.json", "artifacts/dist/release.bin"]
        evidence_file = archive.extractfile("evidence.json")
        assert evidence_file is not None
        payload = json.load(evidence_file)
    assert "path" not in payload["run"]["source"]
    assert "output_preview" not in payload["run"]["steps"][0]


def test_bundle_verifies_provider_receipt_and_exact_sha_readback(git_repo, tmp_path):
    ledger, run = _completed_provider_run(git_repo, tmp_path)

    bundle = export_evidence_bundle(ledger, run.run_id, tmp_path / "receipt.tar")
    report = verify_evidence_bundle(bundle)

    assert report["valid"] is True
    assert report["receipts_verified"] == 1


def test_bundle_accepts_pending_readback_before_terminal_success(git_repo, tmp_path):
    ledger, run = _completed_provider_run(
        git_repo,
        tmp_path,
        pending_before_terminal=True,
    )

    bundle = export_evidence_bundle(ledger, run.run_id, tmp_path / "receipt-history.tar")
    report = verify_evidence_bundle(bundle)

    assert report["valid"] is True
    assert report["receipts_verified"] == 1
    assert report["errors"] == []


def test_export_rejects_readback_after_terminal_state(git_repo, tmp_path):
    ledger, run = _completed_provider_run(
        git_repo,
        tmp_path,
        terminal_before_terminal=True,
    )

    try:
        export_evidence_bundle(ledger, run.run_id, tmp_path / "invalid-history.tar")
    except ValueError as exc:
        assert "adapter readback follows terminal state" in str(exc)
    else:
        raise AssertionError("terminal readback transition was exported")


def test_export_rejects_source_drift_in_pending_readback_history(git_repo, tmp_path):
    ledger, run = _completed_provider_run(
        git_repo,
        tmp_path,
        pending_before_terminal=True,
        pending_observed_sha="0" * 40,
    )

    try:
        export_evidence_bundle(ledger, run.run_id, tmp_path / "drifted-history.tar")
    except ValueError as exc:
        assert "provider readback SHA mismatch" in str(exc)
    else:
        raise AssertionError("drifted pending readback was exported")


def test_export_rejects_invalid_provider_status_in_readback_history(git_repo, tmp_path):
    ledger, run = _completed_provider_run(
        git_repo,
        tmp_path,
        pending_before_terminal=True,
        pending_status="bogus",
    )

    try:
        export_evidence_bundle(ledger, run.run_id, tmp_path / "invalid-status.tar")
    except ValueError as exc:
        assert "adapter readback status is invalid" in str(exc)
    else:
        raise AssertionError("invalid provider status was exported")


def test_export_fails_closed_on_successful_readback_sha_drift(git_repo, tmp_path):
    ledger, run = _completed_provider_run(
        git_repo, tmp_path, observed_sha="0" * 40
    )

    try:
        export_evidence_bundle(ledger, run.run_id, tmp_path / "drift.tar")
    except ValueError as exc:
        assert "provider readback SHA mismatch" in str(exc)
    else:
        raise AssertionError("drifted provider readback was exported")


@pytest.mark.parametrize("malformed_status", [[], {}])
def test_verifier_rejects_unhashable_readback_status(
    git_repo, tmp_path, malformed_status
):
    ledger, run = _completed_provider_run(git_repo, tmp_path)
    bundle = export_evidence_bundle(ledger, run.run_id, tmp_path / "evidence.tar")
    malformed = tmp_path / "unhashable-readback-status.tar"

    def alter_readback_status(record):
        record["status"] = "failed"
        events = record["audit_events"]
        readback = next(
            event for event in events if event["event_type"] == "adapter.readback"
        )
        readback["payload"]["status"] = malformed_status
        _rehash_audit_events(record["run_id"], events)
        provider_step = next(
            step for step in record["steps"] if step["effect"] == "external"
        )
        provider_step["readback"]["status"] = malformed_status
        provider_step["provider_status"] = malformed_status

    _mutate_evidence_record(bundle, malformed, alter_readback_status)
    report = verify_evidence_bundle(malformed)

    assert report["valid"] is False
    assert report["errors"] == [
        "adapter readback status is invalid: git-123456789"
    ]


@pytest.mark.parametrize("malformed_status", [[], {}])
def test_verifier_rejects_unhashable_step_status(git_repo, tmp_path, malformed_status):
    ledger, run = _completed_provider_run(git_repo, tmp_path)
    bundle = export_evidence_bundle(ledger, run.run_id, tmp_path / "evidence.tar")
    malformed = tmp_path / "unhashable-step-status.tar"

    def alter_step_status(record):
        record["status"] = "failed"
        record["steps"][0]["status"] = malformed_status

    _mutate_evidence_record(bundle, malformed, alter_step_status)
    report = verify_evidence_bundle(malformed)

    assert report["valid"] is False
    assert report["errors"] == ["step status is invalid"]


def test_verifier_requires_step_receipt_and_readback_in_audit_chain(git_repo, tmp_path):
    ledger, run = _completed_provider_run(git_repo, tmp_path)
    bundle = export_evidence_bundle(ledger, run.run_id, tmp_path / "evidence.tar")
    stripped = tmp_path / "stripped-receipts.tar"

    def remove_receipt_events(members):
        rewritten = []
        for name, content in members:
            if name == "evidence.json":
                payload = json.loads(content)
                events = [
                    event
                    for event in payload["run"]["audit_events"]
                    if event["event_type"]
                    not in {"adapter.receipt", "adapter.readback"}
                ]
                _rehash_audit_events(payload["run"]["run_id"], events)
                payload["run"]["audit_events"] = events
                payload["record_sha256"] = _canonical_sha256(payload["run"])
                content = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
            rewritten.append((name, content))
        return rewritten

    _rewrite_bundle(bundle, stripped, remove_receipt_events)
    report = verify_evidence_bundle(stripped)

    assert report["valid"] is False
    assert report["errors"] == [
        "step operation is missing its audit receipt: git-123456789"
    ]


def test_verifier_requires_candidate_prepared_audit_event(git_repo, tmp_path):
    ledger, run = _completed_run(git_repo, tmp_path)
    bundle = export_evidence_bundle(ledger, run.run_id, tmp_path / "evidence.tar")
    stripped = tmp_path / "stripped-candidate-event.tar"

    def remove_candidate_event(members):
        rewritten = []
        for name, content in members:
            if name == "evidence.json":
                payload = json.loads(content)
                events = [
                    event
                    for event in payload["run"]["audit_events"]
                    if event["event_type"] != "candidate.prepared"
                ]
                _rehash_audit_events(payload["run"]["run_id"], events)
                payload["run"]["audit_events"] = events
                payload["record_sha256"] = _canonical_sha256(payload["run"])
                content = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
            rewritten.append((name, content))
        return rewritten

    _rewrite_bundle(bundle, stripped, remove_candidate_event)
    report = verify_evidence_bundle(stripped)

    assert report["valid"] is False
    assert report["errors"] == ["candidate prepared audit event is missing"]


def test_verifier_rejects_duplicate_provider_receipts(git_repo, tmp_path):
    ledger, run = _completed_provider_run(git_repo, tmp_path)
    bundle = export_evidence_bundle(ledger, run.run_id, tmp_path / "evidence.tar")
    duplicated = tmp_path / "duplicate-receipt.tar"

    def duplicate_receipt(members):
        rewritten = []
        for name, content in members:
            if name == "evidence.json":
                payload = json.loads(content)
                events = payload["run"]["audit_events"]
                receipt = next(
                    event for event in events if event["event_type"] == "adapter.receipt"
                )
                copy = dict(receipt)
                copy["sequence"] = events[-1]["sequence"] + 1
                events.append(copy)
                _rehash_audit_events(payload["run"]["run_id"], events)
                payload["record_sha256"] = _canonical_sha256(payload["run"])
                content = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
            rewritten.append((name, content))
        return rewritten

    _rewrite_bundle(bundle, duplicated, duplicate_receipt)
    report = verify_evidence_bundle(duplicated)

    assert report["valid"] is False
    assert report["errors"] == [
        "duplicate adapter receipt operation id: git-123456789"
    ]


def test_verifier_rejects_receipt_action_mismatch(git_repo, tmp_path):
    ledger, run = _completed_provider_run(git_repo, tmp_path)
    bundle = export_evidence_bundle(ledger, run.run_id, tmp_path / "evidence.tar")
    mismatched = tmp_path / "mismatched-action.tar"

    def change_receipt_action(members):
        rewritten = []
        for name, content in members:
            if name == "evidence.json":
                payload = json.loads(content)
                events = payload["run"]["audit_events"]
                receipt = next(
                    event for event in events if event["event_type"] == "adapter.receipt"
                )
                receipt["payload"]["action"] = "github.workflow"
                _rehash_audit_events(payload["run"]["run_id"], events)
                payload["record_sha256"] = _canonical_sha256(payload["run"])
                content = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
            rewritten.append((name, content))
        return rewritten

    _rewrite_bundle(bundle, mismatched, change_receipt_action)
    report = verify_evidence_bundle(mismatched)

    assert report["valid"] is False
    assert report["errors"] == [
        "adapter receipt action does not match step: git-123456789"
    ]


def test_verifier_rejects_receipt_ordinal_mismatch(git_repo, tmp_path):
    ledger, run = _completed_provider_run(git_repo, tmp_path)
    bundle = export_evidence_bundle(ledger, run.run_id, tmp_path / "evidence.tar")
    mismatched = tmp_path / "mismatched-ordinal.tar"

    def change_receipt_ordinal(members):
        rewritten = []
        for name, content in members:
            if name == "evidence.json":
                payload = json.loads(content)
                events = payload["run"]["audit_events"]
                receipt = next(
                    event for event in events if event["event_type"] == "adapter.receipt"
                )
                receipt["payload"]["ordinal"] = 999
                _rehash_audit_events(payload["run"]["run_id"], events)
                payload["record_sha256"] = _canonical_sha256(payload["run"])
                content = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
            rewritten.append((name, content))
        return rewritten

    _rewrite_bundle(bundle, mismatched, change_receipt_ordinal)
    report = verify_evidence_bundle(mismatched)

    assert report["valid"] is False
    assert report["errors"] == [
        "adapter receipt ordinal does not match step: git-123456789"
    ]


def test_offline_verifier_detects_tampered_artifact(git_repo, tmp_path):
    ledger, run = _completed_run(git_repo, tmp_path)
    bundle = export_evidence_bundle(ledger, run.run_id, tmp_path / "evidence.tar")
    tampered = tmp_path / "tampered.tar"

    def replace_artifact(members):
        return [
            (name, b"x" * len(content) if name == "artifacts/dist/release.bin" else content)
            for name, content in members
        ]

    _rewrite_bundle(bundle, tampered, replace_artifact)
    report = verify_evidence_bundle(tampered)

    assert report["valid"] is False
    assert report["artifacts_verified"] == 0
    assert report["errors"] == ["artifact hash mismatch: dist/release.bin"]


def test_offline_verifier_detects_candidate_identity_tampering(git_repo, tmp_path):
    ledger, run = _completed_run(git_repo, tmp_path)
    bundle = export_evidence_bundle(ledger, run.run_id, tmp_path / "evidence.tar")
    tampered = tmp_path / "tampered-record.tar"

    def alter_record(members):
        rewritten = []
        for name, content in members:
            if name == "evidence.json":
                payload = json.loads(content)
                payload["run"]["candidate"]["payload"]["source"]["sha"] = "0" * 40
                payload["record_sha256"] = _canonical_sha256(payload["run"])
                content = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
            rewritten.append((name, content))
        return rewritten

    _rewrite_bundle(bundle, tampered, alter_record)
    report = verify_evidence_bundle(tampered)

    assert report["valid"] is False
    assert "candidate digest does not match candidate payload" in report["errors"]
    assert "candidate source SHA does not match run source SHA" in report["errors"]


def test_offline_verifier_rejects_undeclared_or_unsafe_members(git_repo, tmp_path):
    ledger, run = _completed_run(git_repo, tmp_path)
    bundle = export_evidence_bundle(ledger, run.run_id, tmp_path / "evidence.tar")
    tampered = tmp_path / "unsafe.tar"

    def append_traversal(members):
        return [*members, ("../escape", b"unsafe")]

    _rewrite_bundle(bundle, tampered, append_traversal)
    report = verify_evidence_bundle(tampered)

    assert report["valid"] is False
    assert report["errors"] == ["unsafe or undeclared bundle member: ../escape"]


def test_offline_verifier_rejects_duplicate_bundle_members(git_repo, tmp_path):
    ledger, run = _completed_run(git_repo, tmp_path)
    bundle = export_evidence_bundle(ledger, run.run_id, tmp_path / "evidence.tar")
    duplicated = tmp_path / "duplicate.tar"

    def duplicate_evidence(members):
        evidence = next(content for name, content in members if name == "evidence.json")
        return [*members, ("evidence.json", evidence)]

    _rewrite_bundle(bundle, duplicated, duplicate_evidence)
    report = verify_evidence_bundle(duplicated)

    assert report["valid"] is False
    assert report["errors"] == ["duplicate or unsafe bundle member: evidence.json"]


def test_offline_verifier_rejects_empty_audit_chain(git_repo, tmp_path):
    ledger, run = _completed_run(git_repo, tmp_path)
    bundle = export_evidence_bundle(ledger, run.run_id, tmp_path / "evidence.tar")
    emptied = tmp_path / "empty-audit.tar"

    def remove_audit_events(members):
        rewritten = []
        for name, content in members:
            if name == "evidence.json":
                payload = json.loads(content)
                payload["run"]["audit_events"] = []
                payload["record_sha256"] = _canonical_sha256(payload["run"])
                content = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
            rewritten.append((name, content))
        return rewritten

    _rewrite_bundle(bundle, emptied, remove_audit_events)
    report = verify_evidence_bundle(emptied)

    assert report["valid"] is False
    assert report["audit_chain_valid"] is False
    assert report["errors"] == ["audit chain is empty"]


def test_offline_verifier_requires_approval_for_success(git_repo, tmp_path):
    ledger, run = _completed_run(git_repo, tmp_path)
    bundle = export_evidence_bundle(ledger, run.run_id, tmp_path / "evidence.tar")
    unapproved = tmp_path / "unapproved.tar"

    def remove_approval(members):
        rewritten = []
        for name, content in members:
            if name == "evidence.json":
                payload = json.loads(content)
                payload["run"]["candidate"]["approval"] = None
                payload["record_sha256"] = _canonical_sha256(payload["run"])
                content = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
            rewritten.append((name, content))
        return rewritten

    _rewrite_bundle(bundle, unapproved, remove_approval)
    report = verify_evidence_bundle(unapproved)

    assert report["valid"] is False
    assert report["errors"] == ["evidence lacks candidate approval"]


def test_export_requires_an_approved_candidate(git_repo, tmp_path):
    ledger, run = _completed_provider_run(git_repo, tmp_path, approve=False)

    try:
        export_evidence_bundle(ledger, run.run_id, tmp_path / "unapproved.tar")
    except EvidenceError as exc:
        assert str(exc) == "run has no candidate approval"
    else:
        raise AssertionError("unapproved evidence export unexpectedly succeeded")


def test_offline_verifier_rejects_unknown_run_status(git_repo, tmp_path):
    ledger, run = _completed_run(git_repo, tmp_path)
    bundle = export_evidence_bundle(ledger, run.run_id, tmp_path / "evidence.tar")
    unknown = tmp_path / "unknown-status.tar"

    def alter_status(members):
        rewritten = []
        for name, content in members:
            if name == "evidence.json":
                payload = json.loads(content)
                payload["run"]["status"] = "invented"
                payload["record_sha256"] = _canonical_sha256(payload["run"])
                content = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
            rewritten.append((name, content))
        return rewritten

    _rewrite_bundle(bundle, unknown, alter_status)
    report = verify_evidence_bundle(unknown)

    assert report["valid"] is False
    assert report["errors"] == ["run status is invalid"]


@pytest.mark.parametrize("malformed_status", [[], {}])
def test_offline_verifier_rejects_unhashable_run_status(
    git_repo, tmp_path, malformed_status
):
    ledger, run = _completed_run(git_repo, tmp_path)
    bundle = export_evidence_bundle(ledger, run.run_id, tmp_path / "evidence.tar")
    malformed = tmp_path / "unhashable-status.tar"

    def alter_status(record):
        record["status"] = malformed_status

    _mutate_evidence_record(bundle, malformed, alter_status)
    report = verify_evidence_bundle(malformed)

    assert report["valid"] is False
    assert report["errors"] == ["run status is invalid"]


def test_offline_verifier_caps_archive_member_count(tmp_path):
    oversized = tmp_path / "too-many-members.tar"
    with tarfile.open(oversized, "w", format=tarfile.GNU_FORMAT) as archive:
        for index in range(10_001):
            archive.addfile(tarfile.TarInfo(f"empty/{index}"), io.BytesIO())

    report = verify_evidence_bundle(oversized)

    assert report["valid"] is False
    assert report["errors"] == ["bundle contains too many members"]


def test_offline_verifier_rejects_nonstandard_json_constants(tmp_path):
    invalid = tmp_path / "nonfinite.tar"
    content = (
        b'{"schema_version":"shipyard.evidence/v1",'
        b'"record_sha256":"0000000000000000000000000000000000000000000000000000000000000000",'
        b'"run":{"value":NaN}}'
    )
    with tarfile.open(invalid, "w", format=tarfile.GNU_FORMAT) as archive:
        info = tarfile.TarInfo("evidence.json")
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))

    report = verify_evidence_bundle(invalid)

    assert report["valid"] is False
    assert report["errors"] == ["invalid evidence JSON: non-finite JSON constant: NaN"]


def test_export_refuses_overwrite_and_changed_approved_artifact(git_repo, tmp_path):
    ledger, run = _completed_run(git_repo, tmp_path)
    output = export_evidence_bundle(ledger, run.run_id, tmp_path / "evidence.tar")

    try:
        export_evidence_bundle(ledger, run.run_id, output)
    except ValueError as exc:
        assert "refusing to overwrite" in str(exc)
    else:
        raise AssertionError("existing bundle was overwritten")

    (git_repo / "dist" / "release.bin").write_bytes(b"changed after approval\n")
    try:
        export_evidence_bundle(ledger, run.run_id, tmp_path / "changed.tar")
    except ValueError as exc:
        assert "approved artifact changed" in str(exc)
    else:
        raise AssertionError("changed approved artifact was exported")


def test_export_rejects_same_content_artifact_symlink(git_repo, tmp_path):
    ledger, run = _completed_run(git_repo, tmp_path)
    artifact = git_repo / "dist" / "release.bin"
    replacement = git_repo / "dist" / "replacement.bin"
    replacement.write_bytes(artifact.read_bytes())
    artifact.unlink()
    artifact.symlink_to(replacement.name)

    try:
        export_evidence_bundle(ledger, run.run_id, tmp_path / "symlink.tar")
    except EvidenceError as exc:
        assert str(exc) == "artifact path cannot contain symlinks: dist/release.bin"
    else:
        raise AssertionError("symlinked artifact was exported")


def test_export_rejects_symlinked_artifact_directory(git_repo, tmp_path):
    ledger, run = _completed_run(git_repo, tmp_path)
    artifact_directory = git_repo / "dist"
    replacement = git_repo / "approved-files"
    artifact_directory.rename(replacement)
    artifact_directory.symlink_to(replacement.name, target_is_directory=True)

    try:
        export_evidence_bundle(ledger, run.run_id, tmp_path / "directory-link.tar")
    except EvidenceError as exc:
        assert str(exc) == "artifact path cannot contain symlinks: dist/release.bin"
    else:
        raise AssertionError("artifact through a symlinked directory was exported")


def test_export_opens_artifact_components_through_bound_directory_descriptors(
    git_repo, tmp_path, monkeypatch
):
    ledger, run = _completed_run(git_repo, tmp_path)
    original_open = os.open
    observed: list[tuple[object, int | None]] = []

    def tracking_open(path, flags, mode=0o777, *, dir_fd=None):
        observed.append((path, dir_fd))
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(evidence_module.os, "open", tracking_open)

    export_evidence_bundle(ledger, run.run_id, tmp_path / "bound-open.tar")

    assert any(path == "dist" and dir_fd is not None for path, dir_fd in observed)
    assert any(
        path == "release.bin" and dir_fd is not None for path, dir_fd in observed
    )


def test_export_reports_output_filesystem_errors_as_evidence_errors(
    git_repo, tmp_path
):
    ledger, run = _completed_run(git_repo, tmp_path)
    not_a_directory = tmp_path / "not-a-directory"
    not_a_directory.write_text("file\n", encoding="utf-8")

    try:
        export_evidence_bundle(
            ledger, run.run_id, not_a_directory / "evidence.tar"
        )
    except EvidenceError as exc:
        assert str(exc).startswith("cannot write evidence bundle:")
    else:
        raise AssertionError("output filesystem error escaped evidence handling")


def test_cli_exports_and_verifies_bundle_without_ledger_access(git_repo, tmp_path):
    ledger, run = _completed_run(git_repo, tmp_path)
    bundle = tmp_path / "portable.tar"

    exported = _run_cli(
        [
            "evidence",
            "export",
            run.run_id,
            "--state-dir",
            str(ledger.state_dir),
            "--output",
            str(bundle),
            "--json",
        ],
        cwd=git_repo,
    )
    assert exported.returncode == 0, exported.stderr
    exported_payload = json.loads(exported.stdout)["data"]
    assert exported_payload["bundle"] == str(bundle)
    assert exported_payload["run_id"] == run.run_id
    assert bundle.stat().st_mode & 0o777 == 0o600

    verified = _run_cli(
        ["evidence", "verify", str(bundle), "--json"], cwd=tmp_path
    )
    assert verified.returncode == 0, verified.stderr
    verified_payload = json.loads(verified.stdout)["data"]
    assert verified_payload["valid"] is True
    assert verified_payload["source_sha"] == run.source_sha
