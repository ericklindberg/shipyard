from __future__ import annotations

import json
from pathlib import Path

from shipyard.cli import main


def _manifest(**overrides: object) -> dict[str, object]:
    manifest: dict[str, object] = {
        "schema_version": "shipyard.app-review-preflight/v1",
        "app": {
            "name": "Example",
            "bundle_id": "com.example.app",
            "version": "1.0",
            "build_number": "1",
        },
        "submission": {
            "metadata_complete": True,
            "screenshots_current": True,
            "known_crashes": False,
            "placeholder_content": False,
            "broken_links": False,
        },
        "review_access": {
            "requires_login": False,
            "demo_account_available": False,
            "review_notes_complete": True,
            "requires_special_hardware": False,
            "hardware_instructions_complete": False,
        },
        "privacy": {
            "privacy_policy_url": "https://example.com/privacy",
            "support_url": "https://example.com/support",
            "data_collection_disclosed": True,
            "privacy_manifest_present": True,
            "account_creation": False,
            "account_deletion_available": False,
        },
        "commerce": {
            "digital_goods": False,
            "uses_in_app_purchase": False,
            "restore_purchases_available": False,
        },
        "authentication": {
            "third_party_login": False,
            "sign_in_with_apple_available": False,
        },
        "compliance": {
            "uses_encryption": False,
            "export_compliance_documented": False,
            "user_generated_content": False,
            "moderation_controls_available": False,
        },
    }
    for key, value in overrides.items():
        manifest[key] = value
    return manifest


def _run(tmp_path: Path, capsys, manifest: dict[str, object]) -> tuple[int, dict[str, object]]:
    path = tmp_path / "app-review.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    code = main(["app-review", "preflight", str(path), "--json"])
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["api_version"] == "shipyard.cli/v1"
    return code, envelope["data"]


def test_app_review_preflight_blocks_high_confidence_rejection_risks(tmp_path, capsys):
    manifest = _manifest(
        review_access={
            "requires_login": True,
            "demo_account_available": False,
            "review_notes_complete": False,
            "requires_special_hardware": True,
            "hardware_instructions_complete": False,
        },
        privacy={
            "privacy_policy_url": "",
            "support_url": "",
            "data_collection_disclosed": False,
            "privacy_manifest_present": False,
            "account_creation": True,
            "account_deletion_available": False,
        },
        commerce={
            "digital_goods": True,
            "uses_in_app_purchase": False,
            "restore_purchases_available": False,
        },
        authentication={
            "third_party_login": True,
            "sign_in_with_apple_available": False,
        },
    )

    code, result = _run(tmp_path, capsys, manifest)

    assert code == 1
    assert result["status"] == "blocked"
    ids = {finding["id"] for finding in result["findings"]}
    assert {
        "review-login-access",
        "privacy-policy-url",
        "support-url",
        "account-deletion",
        "digital-goods-iap",
        "sign-in-with-apple",
        "special-hardware-review",
    } <= ids
    assert result["read_only"] is True
    assert result["network_access"] is False
    assert result["provider_mutations"] == 0
    assert result["assurance"] == "risk-screening-only"


def test_app_review_preflight_reports_review_risks_without_claiming_approval(tmp_path, capsys):
    manifest = _manifest(
        compliance={
            "uses_encryption": True,
            "export_compliance_documented": False,
            "user_generated_content": True,
            "moderation_controls_available": False,
        }
    )

    code, result = _run(tmp_path, capsys, manifest)

    assert code == 0
    assert result["status"] == "review"
    assert result["approval_guaranteed"] is False
    assert {finding["id"] for finding in result["findings"]} == {
        "export-compliance",
        "user-generated-content-moderation",
    }
    assert all(finding["severity"] == "warning" for finding in result["findings"])


def test_app_review_preflight_ready_is_advisory_and_deterministic(tmp_path, capsys):
    code, first = _run(tmp_path, capsys, _manifest())
    capsys.readouterr()
    code_again, second = _run(tmp_path, capsys, _manifest())

    assert code == code_again == 0
    assert first == second
    assert first["status"] == "ready"
    assert first["findings"] == []
    assert first["approval_guaranteed"] is False
    assert len(first["manifest_sha256"]) == 64


def test_app_review_preflight_rejects_secret_fields(tmp_path, capsys):
    manifest = _manifest()
    manifest["review_password"] = "do-not-store-this"
    path = tmp_path / "app-review.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    code = main(["app-review", "preflight", str(path), "--json"])
    captured = capsys.readouterr()

    assert code == 2
    assert captured.out == ""
    error = json.loads(captured.err)
    assert "credential values" in error["error"]["message"]
    assert "do-not-store-this" not in captured.err
