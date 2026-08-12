from __future__ import annotations

import hashlib
import io
import json
import stat
import tarfile
import tempfile
from pathlib import Path

import pytest

from shipyard.adapters.base import ProviderReadback
from shipyard.dossier import DossierError, export_release_dossier, verify_release_dossier
from shipyard.gates import GateAttestation, GateStore
from shipyard.observations import ObservationStore, ReleaseObservation
from shipyard.quickstart import run_quickstart
from shipyard.release_project import load_release_project


def _project(path: Path) -> Path:
    path.write_text(
        '''schema_version = 1
name = "dossier-test"
source_remote = "https://github.com/example/example.git"

[github]
owner = "example"
repo = "example"
repository_id = "1234"
required_workflow_ids = ["101"]
token_env = "GITHUB_ACTIONS_TOKEN"

[apple]
workflow_id = "workflow-1"
source_remote = "https://github.com/example/example.git"
source_git_remote = "origin"
bundle_id = "com.example.app"
beta_group_name = "Testing"
expected_marketing_version = "1.1"
token_env = "APPLE_ASC_TOKEN"

[[gates]]
name = "physical-device"
required_for = ["external", "production"]
''',
        encoding="utf-8",
    )
    path.chmod(0o644)
    return path


def _rewrite(
    source: Path,
    destination: Path,
    transform,
) -> None:
    with tarfile.open(source, "r:") as archive:
        members: list[tuple[str, bytes]] = []
        for member in archive:
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


def _inputs(tmp_path: Path):
    quickstart = run_quickstart(tmp_path / "quickstart")
    project = load_release_project(_project(tmp_path / "shipyard.release.toml"))
    state = tmp_path / "release-state"
    apple = ReleaseObservation.create(
        "apple",
        project.digest,
        quickstart.source_sha,
        ProviderReadback(
            "succeeded",
            "run-609",
            quickstart.source_sha,
            {
                "run_id": "run-609",
                "build_id": "build-609",
                "build_number": "609",
                "marketing_version": "1.1",
                "read_only": True,
            },
        ),
        observed_at="2026-08-12T12:00:00Z",
    )
    observation_path = ObservationStore(state).save(apple)
    device_evidence = tmp_path / "device.txt"
    device_evidence.write_text("build 609 physical iPhone pass", encoding="utf-8")
    gate = GateAttestation.create(
        gate="physical-device",
        project_digest=project.digest,
        source_sha=quickstart.source_sha,
        status="passed",
        actor="operator",
        reason="physical iPhone verified",
        apple_observation_digest=apple.digest,
        app_version="1.1",
        build_number="609",
        device="iPhone",
        os_version="iOS 26",
        checks=("launch", "first-capture"),
        evidence_paths=(device_evidence,),
        observed_at="2026-08-12T12:05:00Z",
    )
    gate_path = GateStore(state).save(gate)
    native_log = tmp_path / "native.txt"
    native_log.write_text("30 passed, 0 failed", encoding="utf-8")
    return quickstart, project, observation_path, gate_path, native_log


def test_release_dossier_aggregates_real_run_observation_gate_and_artifact(tmp_path) -> None:
    quickstart, project, observation, gate, artifact = _inputs(tmp_path)

    dossier = export_release_dossier(
        project=project,
        source_sha=quickstart.source_sha,
        release_scope="external",
        run_bundles=(("candidate", quickstart.evidence_path),),
        observations=(("apple", observation),),
        gates=(gate,),
        artifacts=(("native-validation", artifact),),
        output=tmp_path / "release-dossier.tar",
    )
    report = verify_release_dossier(dossier)

    assert report["valid"] is True
    assert report["source_sha"] == quickstart.source_sha
    assert report["release_scope"] == "external"
    assert report["runs_verified"] == 1
    assert report["observations_verified"] == 1
    assert report["gates_verified"] == 1
    assert report["artifacts_verified"] == 2
    assert stat.S_IMODE(dossier.stat().st_mode) == 0o600


def test_release_dossier_refuses_external_scope_with_pending_device_gate(tmp_path) -> None:
    quickstart, project, observation, _gate, artifact = _inputs(tmp_path)
    pending = GateAttestation.create(
        gate="physical-device",
        project_digest=project.digest,
        source_sha=quickstart.source_sha,
        status="pending",
        actor="Shipyard",
        reason="not tested",
        observed_at="2026-08-12T12:05:00Z",
    )
    pending_path = GateStore(tmp_path / "pending-state").save(pending)

    with pytest.raises(DossierError, match="has not passed"):
        export_release_dossier(
            project=project,
            source_sha=quickstart.source_sha,
            release_scope="external",
            run_bundles=(("candidate", quickstart.evidence_path),),
            observations=(("apple", observation),),
            gates=(pending_path,),
            artifacts=(("native-validation", artifact),),
            output=tmp_path / "blocked.tar",
        )


def test_release_dossier_verifier_rejects_tampered_child_bundle(tmp_path) -> None:
    quickstart, project, observation, gate, artifact = _inputs(tmp_path)
    dossier = export_release_dossier(
        project=project,
        source_sha=quickstart.source_sha,
        release_scope="external",
        run_bundles=(("candidate", quickstart.evidence_path),),
        observations=(("apple", observation),),
        gates=(gate,),
        artifacts=(("native-validation", artifact),),
        output=tmp_path / "release-dossier.tar",
    )
    tampered = tmp_path / "tampered.tar"

    def transform(members):
        return [
            (name, content + b"tamper" if name == "runs/candidate.tar" else content)
            for name, content in members
        ]

    _rewrite(dossier, tampered, transform)
    report = verify_release_dossier(tampered)

    assert report["valid"] is False
    errors = report["errors"]
    assert isinstance(errors, list)
    assert any("hash mismatch" in str(error) for error in errors)


def test_release_dossier_verifier_rejects_undeclared_member(tmp_path) -> None:
    quickstart, project, observation, gate, artifact = _inputs(tmp_path)
    dossier = export_release_dossier(
        project=project,
        source_sha=quickstart.source_sha,
        release_scope="external",
        run_bundles=(("candidate", quickstart.evidence_path),),
        observations=(("apple", observation),),
        gates=(gate,),
        artifacts=(("native-validation", artifact),),
        output=tmp_path / "release-dossier.tar",
    )
    injected = tmp_path / "injected.tar"
    _rewrite(dossier, injected, lambda members: [*members, ("extra.txt", b"hidden")])

    report = verify_release_dossier(injected)

    assert report["valid"] is False
    errors = report["errors"]
    assert isinstance(errors, list)
    assert any("undeclared member" in str(error) for error in errors)


def test_release_dossier_verifier_recomputes_required_gates_from_project(tmp_path) -> None:
    quickstart, project, observation, gate, artifact = _inputs(tmp_path)
    dossier = export_release_dossier(
        project=project,
        source_sha=quickstart.source_sha,
        release_scope="external",
        run_bundles=(("candidate", quickstart.evidence_path),),
        observations=(("apple", observation),),
        gates=(gate,),
        artifacts=(("native-validation", artifact),),
        output=tmp_path / "release-dossier.tar",
    )
    bypass = tmp_path / "policy-bypass.tar"

    def remove_required_gate(members):
        rewritten = []
        for name, content in members:
            if name == "dossier.json":
                record = json.loads(content)
                record["required_gates"] = []
                record.pop("record_sha256")
                record["record_sha256"] = hashlib.sha256(
                    json.dumps(record, separators=(",", ":"), sort_keys=True).encode()
                ).hexdigest()
                content = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
            rewritten.append((name, content))
        return rewritten

    _rewrite(dossier, bypass, remove_required_gate)
    report = verify_release_dossier(bypass)

    assert report["valid"] is False
    errors = report["errors"]
    assert isinstance(errors, list)
    assert any("required gate policy" in str(error) for error in errors)


def test_release_dossier_verifier_requires_hash_bound_project_document(tmp_path) -> None:
    quickstart, project, observation, gate, artifact = _inputs(tmp_path)
    dossier = export_release_dossier(
        project=project,
        source_sha=quickstart.source_sha,
        release_scope="external",
        run_bundles=(("candidate", quickstart.evidence_path),),
        observations=(("apple", observation),),
        gates=(gate,),
        artifacts=(("native-validation", artifact),),
        output=tmp_path / "release-dossier.tar",
    )
    missing = tmp_path / "missing-project.tar"
    _rewrite(
        dossier,
        missing,
        lambda members: [(name, content) for name, content in members if name != "project.toml"],
    )

    report = verify_release_dossier(missing)

    assert report["valid"] is False
    errors = report["errors"]
    assert isinstance(errors, list)
    assert any("project" in str(error) for error in errors)


def test_release_dossier_rejects_child_run_from_different_sha(tmp_path) -> None:
    quickstart = run_quickstart(tmp_path / "quickstart")
    project = load_release_project(_project(tmp_path / "shipyard.release.toml"))
    different_sha = "f" * 40
    assert quickstart.source_sha != different_sha

    with pytest.raises(DossierError, match="source SHA differs"):
        export_release_dossier(
            project=project,
            source_sha=different_sha,
            release_scope="internal",
            run_bundles=(("wrong", quickstart.evidence_path),),
            observations=(),
            gates=(),
            artifacts=(),
            output=tmp_path / "wrong.tar",
        )


def test_release_dossier_verifier_canonicalizes_symlink_spelled_temp_root(
    tmp_path, monkeypatch
) -> None:
    quickstart, project, observation, gate, artifact = _inputs(tmp_path)
    dossier = export_release_dossier(
        project=project,
        source_sha=quickstart.source_sha,
        release_scope="internal",
        run_bundles=(),
        observations=(("apple", observation),),
        gates=(gate,),
        artifacts=(("native-validation", artifact),),
        output=tmp_path / "release-dossier.tar",
    )
    real_temp = tmp_path / "private-temp"
    real_temp.mkdir(mode=0o700)
    alias = tmp_path / "temp-alias"
    alias.symlink_to(real_temp, target_is_directory=True)
    monkeypatch.setattr(tempfile, "tempdir", str(alias))

    report = verify_release_dossier(dossier)

    assert report["valid"] is True
