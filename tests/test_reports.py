from pathlib import Path

import pytest

from shipyard.quickstart import run_quickstart
from shipyard.reports import render_html, render_markdown, render_report


def _verified_record() -> dict[str, object]:
    return {
        "valid": True,
        "status": "succeeded",
        "source_sha": "abc",
        "candidate_digest": "def",
        "approval_present": True,
        "artifacts_declared": 1,
        "artifacts_verified": 1,
        "receipts_verified": 1,
        "audit_chain_valid": True,
        "run_id": "r1",
        "errors": [],
        "record": {
            "destination": "prod",
            "steps": [{"name": "<deploy>", "status": "succeeded"}],
        },
    }


def test_report_renders_verified_markdown_with_escaped_timeline():
    output = render_markdown(_verified_record())

    assert "# Shipyard evidence report" in output
    assert "VERIFIED" in output
    assert "&lt;deploy&gt;" in output
    assert "prod" in output


def test_report_fails_closed_for_invalid_evidence():
    output = render_html({"valid": False, "errors": ["bad <data>"]})

    assert "INVALID" in output
    assert "bad &lt;data&gt;" in output
    assert "SUCCESS" not in output


def test_html_is_self_contained_and_escapes_content():
    output = render_html(
        {"valid": True, "status": "succeeded", "run_id": "<x>", "errors": []}
    )

    assert "<style>" in output
    assert "&lt;x&gt;" in output
    assert "http://" not in output
    assert "https://" not in output


def test_render_report_verifies_a_real_bundle_snapshot(tmp_path: Path):
    summary = run_quickstart(tmp_path / "demo")

    output = render_report(summary.evidence_path, format="markdown")

    assert "**Verdict:** VERIFIED" in output
    assert summary.source_sha in output
    assert summary.candidate_digest in output


def test_render_report_rejects_unverified_dictionary_input():
    with pytest.raises(ValueError, match="bundle path"):
        render_report({"valid": True})  # type: ignore[arg-type]


def test_render_report_rejects_symlink_bundle(tmp_path: Path):
    target = tmp_path / "evidence.tar"
    target.write_bytes(b"not evidence")
    link = tmp_path / "link.tar"
    link.symlink_to(target)

    assert "INVALID" in render_report(link)


def test_unknown_format_rejected(tmp_path: Path):
    with pytest.raises(ValueError, match="format"):
        render_report(tmp_path / "unused", format="pdf")
