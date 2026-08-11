from pathlib import Path

import pytest

from shipyard import evidence
from shipyard.quickstart import QuickstartError, QuickstartSummary, run_quickstart


def test_quickstart_uses_governed_release_and_portable_evidence(tmp_path: Path):
    destination = tmp_path / "demo"
    summary = run_quickstart(destination)
    report = evidence.verify_evidence_bundle(summary.evidence_path)

    assert isinstance(summary, QuickstartSummary)
    assert summary.status == "succeeded"
    assert summary.run_id == report["run_id"]
    assert summary.candidate_digest == report["candidate_digest"]
    assert summary.source_sha == summary.remote_sha == report["source_sha"]
    assert summary.remote_url.startswith("file://")
    assert report["schema_version"] == "shipyard.evidence/v1"
    assert report["valid"] is True
    assert report["approval_present"] is True
    assert report["receipts_verified"] == 1
    assert summary.evidence_verified is True
    assert not (destination / "state" / "snapshots" / summary.run_id).exists()


def test_quickstart_uses_sanitized_git_environment(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("GIT_INDEX_FILE", "/dev/null")

    assert run_quickstart(tmp_path / "sanitized").status == "succeeded"


def test_quickstart_toml_quotes_unusual_local_paths(tmp_path: Path):
    summary = run_quickstart(tmp_path / "quote's-demo")

    assert summary.status == "succeeded"


def test_quickstart_rejects_unsafe_destinations(tmp_path: Path):
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "keep").write_text("do not touch", encoding="utf-8")
    with pytest.raises(QuickstartError, match="non-empty"):
        run_quickstart(occupied)
    assert (occupied / "keep").read_text(encoding="utf-8") == "do not touch"

    symlink = tmp_path / "link"
    symlink.symlink_to(occupied, target_is_directory=True)
    with pytest.raises(QuickstartError, match="directory"):
        run_quickstart(symlink)


def test_quickstart_failure_preserves_preexisting_empty_destination(
    tmp_path: Path, monkeypatch
):
    destination = tmp_path / "existing"
    destination.mkdir()

    def fail_export(*args, **kwargs):
        raise RuntimeError("injected export failure")

    monkeypatch.setattr(evidence, "export_evidence_bundle", fail_export)
    with pytest.raises(QuickstartError, match="injected export failure"):
        run_quickstart(destination)
    assert destination.exists()
    assert not any(destination.iterdir())


def test_quickstart_failure_removes_new_destination(tmp_path: Path, monkeypatch):
    def fail_export(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(evidence, "export_evidence_bundle", fail_export)
    destination = tmp_path / "new"
    with pytest.raises(QuickstartError, match="boom"):
        run_quickstart(destination)
    assert not destination.exists()
