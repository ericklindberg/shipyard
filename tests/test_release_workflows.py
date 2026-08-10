from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_ci_covers_linux_and_macos_with_locked_security_gates():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "ubuntu-latest" in workflow
    assert "macos-14" in workflow
    assert 'python-version: "3.11"' in workflow
    assert 'python-version: "3.13"' in workflow
    assert "uv sync --extra dev --locked" in workflow
    assert "uv run pip-audit" in workflow
    assert "scripts/scan_tracked_secrets.py" in workflow
    assert "uv run cyclonedx-py" in workflow
    assert "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" in workflow
    assert "git diff --exit-code" in workflow


def test_release_evidence_workflow_attests_without_publishing():
    workflow_path = ROOT / ".github/workflows/release-evidence.yml"
    assert workflow_path.exists()
    workflow = workflow_path.read_text(encoding="utf-8")

    assert "workflow_dispatch:" in workflow
    assert "id-token: write" in workflow
    assert "attestations: write" in workflow
    assert "actions/attest-build-provenance@43d14bc2b83dec42d39ecae14e916627a18bb661" in workflow
    assert "scripts/write_checksums.py" in workflow
    assert "uv run cyclonedx-py" in workflow
    assert "twine upload" not in workflow
    assert "uv publish" not in workflow
    assert "gh release create" not in workflow
