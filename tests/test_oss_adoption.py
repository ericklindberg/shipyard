from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_public_adoption_governance_files_are_present() -> None:
    required = (
        "ROADMAP.md",
        "docs/ADOPTION.md",
        ".github/ISSUE_TEMPLATE/bug.yml",
        ".github/ISSUE_TEMPLATE/feature.yml",
        ".github/ISSUE_TEMPLATE/adapter.yml",
    )

    for relative in required:
        path = ROOT / relative
        assert path.is_file(), f"missing public adoption file: {relative}"
        assert path.read_text(encoding="utf-8").strip(), f"empty public adoption file: {relative}"


def test_roadmap_preserves_shipyards_explicit_control_boundary() -> None:
    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")

    for commitment in (
        "credential-free quickstart",
        "portable signed approvals",
        "Apple release adoption",
        "OCI and Kubernetes",
        "No hosted control plane",
        "No automatic provider retries",
    ):
        assert commitment in roadmap


def test_issue_forms_route_security_reports_privately() -> None:
    for name in ("bug.yml", "feature.yml", "adapter.yml"):
        text = (ROOT / ".github" / "ISSUE_TEMPLATE" / name).read_text(encoding="utf-8")
        assert "contact_links" not in text
        assert "private vulnerability" in text.lower()


def test_adoption_guide_covers_current_operator_surface() -> None:
    guide = (ROOT / "docs" / "ADOPTION.md").read_text(encoding="utf-8")

    for contract in (
        "shipyard quickstart",
        "shipyard bootstrap github-actions",
        "shipyard evidence report",
        "shipyard wait",
        "shipyard approval export",
        "approval_quorum",
        "xcodecloud.build",
        "appstoreconnect.testflight",
        "oci.promote",
        "kubernetes.deploy",
        "org.opencontainers.image.revision",
        "No live provider validation",
    ):
        assert contract in guide
