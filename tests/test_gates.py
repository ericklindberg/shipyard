from __future__ import annotations

import json
import stat

import pytest

from shipyard.gates import GateAttestation, GateError, GateStore

SHA = "a" * 40


def test_physical_device_gate_requires_complete_identity_and_evidence(tmp_path) -> None:
    evidence = tmp_path / "iphone-build-609.txt"
    evidence.write_text(
        "Meridian 1.1 (609): launch pass; Add a task focuses quick entry; first capture pass\n",
        encoding="utf-8",
    )

    gate = GateAttestation.create(
        gate="physical-device",
        project_digest="b" * 64,
        source_sha=SHA,
        status="passed",
        actor="Erick Lindberg",
        reason="Observed enrolled iPhone TestFlight behavior",
        apple_observation_digest="c" * 64,
        app_version="1.1",
        build_number="609",
        device="Erick's iPhone",
        os_version="iOS 26.0",
        checks=("launch", "empty-tasks-cta", "quick-entry-focus", "first-task-capture"),
        evidence_paths=(evidence,),
        observed_at="2026-08-12T12:00:00Z",
    )

    assert gate.status == "passed"
    assert gate.build_number == "609"
    assert gate.evidence[0]["sha256"]
    assert gate.digest


def test_physical_device_gate_rejects_pass_without_evidence() -> None:
    with pytest.raises(GateError, match="requires Apple observation"):
        GateAttestation.create(
            gate="physical-device",
            project_digest="b" * 64,
            source_sha=SHA,
            status="passed",
            actor="operator",
            reason="trust me",
        )


def test_gate_store_is_private_immutable_and_tamper_evident(tmp_path) -> None:
    evidence = tmp_path / "device.txt"
    evidence.write_text("build 609 passed", encoding="utf-8")
    gate = GateAttestation.create(
        gate="physical-device",
        project_digest="b" * 64,
        source_sha=SHA,
        status="passed",
        actor="operator",
        reason="tested",
        apple_observation_digest="c" * 64,
        app_version="1.1",
        build_number="609",
        device="iPhone",
        os_version="iOS 26",
        checks=("launch",),
        evidence_paths=(evidence,),
        observed_at="2026-08-12T12:00:00Z",
    )
    store = GateStore(tmp_path / "state")

    path = store.save(gate)
    loaded = store.load(path)

    assert loaded.payload() == gate.payload()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["build_number"] = "610"
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(GateError, match="digest"):
        store.load(path)


def test_pending_physical_gate_is_honest_without_fabricated_device_evidence() -> None:
    gate = GateAttestation.create(
        gate="physical-device",
        project_digest="b" * 64,
        source_sha=SHA,
        status="pending",
        actor="Shipyard",
        reason="No enrolled device session has been recorded",
        observed_at="2026-08-12T12:00:00Z",
    )

    assert gate.status == "pending"
    assert gate.evidence == ()


def test_gate_store_rejects_nested_project_symlink_without_outside_write(tmp_path) -> None:
    gate = GateAttestation.create(
        gate="physical-device",
        project_digest="b" * 64,
        source_sha=SHA,
        status="pending",
        actor="Shipyard",
        reason="No enrolled device session has been recorded",
        observed_at="2026-08-12T12:00:00Z",
    )
    store = GateStore(tmp_path / "state")
    root = store._root()
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    (root / gate.project_digest).symlink_to(outside, target_is_directory=True)

    with pytest.raises(GateError, match="persist release gate"):
        store.save(gate)

    assert list(outside.iterdir()) == []
