from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import stat
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlsplit

_SCHEMA = "shipyard.app-review-preflight/v1"
_MAX_BYTES = 1024 * 1024
_SECRET_KEY_PARTS = ("password", "token", "secret", "private_key", "api_key", "credential")
_SECTIONS: dict[str, dict[str, type]] = {
    "app": {"name": str, "bundle_id": str, "version": str, "build_number": str},
    "submission": {
        "metadata_complete": bool,
        "screenshots_current": bool,
        "known_crashes": bool,
        "placeholder_content": bool,
        "broken_links": bool,
    },
    "review_access": {
        "requires_login": bool,
        "demo_account_available": bool,
        "review_notes_complete": bool,
        "requires_special_hardware": bool,
        "hardware_instructions_complete": bool,
    },
    "privacy": {
        "privacy_policy_url": str,
        "support_url": str,
        "data_collection_disclosed": bool,
        "privacy_manifest_present": bool,
        "account_creation": bool,
        "account_deletion_available": bool,
    },
    "commerce": {
        "digital_goods": bool,
        "uses_in_app_purchase": bool,
        "restore_purchases_available": bool,
    },
    "authentication": {
        "third_party_login": bool,
        "sign_in_with_apple_available": bool,
    },
    "compliance": {
        "uses_encryption": bool,
        "export_compliance_documented": bool,
        "user_generated_content": bool,
        "moderation_controls_available": bool,
    },
}


class AppReviewPreflightError(ValueError):
    pass


def app_review_manifest_template() -> dict[str, object]:
    """Return a fresh, secret-free scaffold that remains blocked until reviewed."""
    return {
        "schema_version": _SCHEMA,
        "app": {
            "name": "REPLACE_WITH_APP_NAME",
            "bundle_id": "com.example.replace",
            "version": "0.0",
            "build_number": "0",
        },
        "submission": {
            "metadata_complete": False,
            "screenshots_current": False,
            "known_crashes": False,
            "placeholder_content": False,
            "broken_links": False,
        },
        "review_access": {
            "requires_login": False,
            "demo_account_available": False,
            "review_notes_complete": False,
            "requires_special_hardware": False,
            "hardware_instructions_complete": False,
        },
        "privacy": {
            "privacy_policy_url": "",
            "support_url": "",
            "data_collection_disclosed": False,
            "privacy_manifest_present": False,
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


def render_app_review_manifest_template() -> str:
    return json.dumps(app_review_manifest_template(), indent=2, sort_keys=True) + "\n"


def _reject_secret_keys(value: object) -> None:
    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            key = str(raw_key).lower().replace("-", "_")
            if any(part in key for part in _SECRET_KEY_PARTS):
                raise AppReviewPreflightError(
                    "app review manifest must not contain credential values or secret fields"
                )
            _reject_secret_keys(child)
    elif isinstance(value, list):
        for child in value:
            _reject_secret_keys(child)


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AppReviewPreflightError("app review manifest contains duplicate keys")
        result[key] = value
    return result


def _read_manifest(path: str | Path) -> bytes:
    candidate = Path(path).expanduser()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as exc:
        raise AppReviewPreflightError(f"app review manifest cannot be opened: {candidate}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise AppReviewPreflightError("app review manifest must be a regular file")
        if metadata.st_size > _MAX_BYTES:
            raise AppReviewPreflightError("app review manifest exceeds the 1 MiB limit")
        chunks: list[bytes] = []
        remaining = _MAX_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > _MAX_BYTES:
            raise AppReviewPreflightError("app review manifest exceeds the 1 MiB limit")
        return data
    finally:
        os.close(descriptor)


def load_app_review_manifest(path: str | Path) -> dict[str, object]:
    raw = _read_manifest(path)
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AppReviewPreflightError("app review manifest must be valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise AppReviewPreflightError("app review manifest root must be an object")
    _reject_secret_keys(value)
    expected_top = {"schema_version", *_SECTIONS}
    if set(value) != expected_top:
        missing = sorted(expected_top - set(value))
        unknown = sorted(set(value) - expected_top)
        detail = f"missing={missing}, unknown={unknown}"
        raise AppReviewPreflightError(f"app review manifest fields are invalid: {detail}")
    if value["schema_version"] != _SCHEMA:
        raise AppReviewPreflightError(f"app review manifest schema_version must be {_SCHEMA}")
    for section_name, fields in _SECTIONS.items():
        section = value[section_name]
        if not isinstance(section, dict):
            raise AppReviewPreflightError(f"app review manifest {section_name} must be an object")
        if set(section) != set(fields):
            missing = sorted(set(fields) - set(section))
            unknown = sorted(set(section) - set(fields))
            raise AppReviewPreflightError(
                f"app review manifest {section_name} fields are invalid: "
                f"missing={missing}, unknown={unknown}"
            )
        for field, expected_type in fields.items():
            if type(section[field]) is not expected_type:
                raise AppReviewPreflightError(
                    f"app review manifest {section_name}.{field} has invalid type"
                )
    app = value["app"]
    assert isinstance(app, dict)
    for field in ("name", "bundle_id", "version", "build_number"):
        if not str(app[field]).strip():
            raise AppReviewPreflightError(f"app review manifest app.{field} must not be empty")
    privacy = value["privacy"]
    assert isinstance(privacy, dict)
    for field in ("privacy_policy_url", "support_url"):
        url = str(privacy[field])
        if url and not _valid_public_https_url(url):
            raise AppReviewPreflightError(
                f"app review manifest privacy.{field} must be an HTTPS URL without credentials"
            )
    return value


def _valid_public_https_url(value: str) -> bool:
    if not value or any(character.isspace() or ord(character) < 32 for character in value):
        return False
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
        username = parsed.username
        password = parsed.password
    except ValueError:
        return False
    if parsed.scheme != "https" or not hostname or port is None and ":" in parsed.netloc:
        return False
    if username is not None or password is not None or parsed.query or parsed.fragment:
        return False
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
    if address is not None:
        return not (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_unspecified
            or address.is_multicast
        )
    return "." in hostname and not hostname.lower().endswith(".local")


def _finding(
    identifier: str,
    severity: str,
    title: str,
    evidence: str,
    recommendation: str,
) -> dict[str, object]:
    return {
        "id": identifier,
        "severity": severity,
        "title": title,
        "evidence": [evidence],
        "recommendation": recommendation,
    }


def assess_app_review_manifest(manifest: Mapping[str, object]) -> dict[str, object]:
    submission = manifest["submission"]
    access = manifest["review_access"]
    privacy = manifest["privacy"]
    commerce = manifest["commerce"]
    authentication = manifest["authentication"]
    compliance = manifest["compliance"]
    assert isinstance(submission, dict)
    assert isinstance(access, dict)
    assert isinstance(privacy, dict)
    assert isinstance(commerce, dict)
    assert isinstance(authentication, dict)
    assert isinstance(compliance, dict)

    findings: list[dict[str, object]] = []

    def add(
        condition: bool,
        identifier: str,
        severity: str,
        title: str,
        evidence: str,
        recommendation: str,
    ) -> None:
        if condition:
            findings.append(_finding(identifier, severity, title, evidence, recommendation))

    add(
        not submission["metadata_complete"],
        "submission-metadata",
        "blocker",
        "Submission metadata is incomplete",
        "submission.metadata_complete=false",
        "Complete all required version metadata before submission.",
    )
    add(
        not submission["screenshots_current"],
        "current-screenshots",
        "blocker",
        "Screenshots do not represent the submitted build",
        "submission.screenshots_current=false",
        "Capture current, truthful screenshots for every submitted device family.",
    )
    add(
        bool(submission["known_crashes"]),
        "known-crashes",
        "blocker",
        "The candidate has known crashes",
        "submission.known_crashes=true",
        "Resolve known launch or core-flow crashes before review.",
    )
    add(
        bool(submission["placeholder_content"]),
        "placeholder-content",
        "blocker",
        "Placeholder or unfinished content remains",
        "submission.placeholder_content=true",
        "Remove placeholder, test, and unfinished content from the submitted build and metadata.",
    )
    add(
        bool(submission["broken_links"]),
        "broken-links",
        "blocker",
        "The candidate has broken links",
        "submission.broken_links=true",
        "Repair support, privacy, legal, purchase, and in-app links.",
    )
    add(
        bool(access["requires_login"]) and not access["demo_account_available"],
        "review-login-access",
        "blocker",
        "App Review cannot access login-gated functionality",
        "review_access.requires_login=true and demo_account_available=false",
        "Provide a durable review account or an approved fully functional review "
        "path; never store its password in this manifest.",
    )
    add(
        not access["review_notes_complete"],
        "review-notes",
        "warning",
        "Review notes are incomplete",
        "review_access.review_notes_complete=false",
        "Document non-obvious flows, entitlements, hardware, and reviewer steps.",
    )
    add(
        bool(access["requires_special_hardware"]) and not access["hardware_instructions_complete"],
        "special-hardware-review",
        "blocker",
        "Special hardware cannot be evaluated from the review notes",
        "review_access.requires_special_hardware=true and hardware_instructions_complete=false",
        "Provide complete hardware access, setup, fallback, and contact instructions.",
    )
    add(
        not bool(privacy["privacy_policy_url"]),
        "privacy-policy-url",
        "blocker",
        "Privacy policy URL is missing",
        "privacy.privacy_policy_url is empty",
        "Provide a public HTTPS privacy policy matching actual data practices.",
    )
    add(
        not bool(privacy["support_url"]),
        "support-url",
        "blocker",
        "Support URL is missing",
        "privacy.support_url is empty",
        "Provide a working public HTTPS support page.",
    )
    add(
        not privacy["data_collection_disclosed"],
        "privacy-disclosures",
        "blocker",
        "Data collection disclosures are incomplete",
        "privacy.data_collection_disclosed=false",
        "Reconcile App Privacy answers with the submitted app and third-party SDK behavior.",
    )
    add(
        not privacy["privacy_manifest_present"],
        "privacy-manifest",
        "warning",
        "Privacy manifest evidence is absent",
        "privacy.privacy_manifest_present=false",
        "Verify the built archive contains required privacy manifests and "
        "required-reason API declarations.",
    )
    add(
        bool(privacy["account_creation"]) and not privacy["account_deletion_available"],
        "account-deletion",
        "blocker",
        "Account creation has no in-app deletion path",
        "privacy.account_creation=true and account_deletion_available=false",
        "Provide an in-app account-deletion initiation path and verify durable "
        "backend deletion handling.",
    )
    add(
        bool(commerce["digital_goods"]) and not commerce["uses_in_app_purchase"],
        "digital-goods-iap",
        "blocker",
        "Digital goods are not using In-App Purchase",
        "commerce.digital_goods=true and uses_in_app_purchase=false",
        "Use Apple's In-App Purchase path unless a documented guideline exception applies.",
    )
    add(
        bool(commerce["uses_in_app_purchase"]) and not commerce["restore_purchases_available"],
        "restore-purchases",
        "blocker",
        "Restorable purchases have no restore path",
        "commerce.uses_in_app_purchase=true and restore_purchases_available=false",
        "Provide and test a visible Restore Purchases action where restoration applies.",
    )
    add(
        bool(authentication["third_party_login"])
        and not authentication["sign_in_with_apple_available"],
        "sign-in-with-apple",
        "blocker",
        "Third-party login lacks Sign in with Apple parity",
        "authentication.third_party_login=true and sign_in_with_apple_available=false",
        "Add and entitlement-test Sign in with Apple unless a documented guideline "
        "exception applies.",
    )
    add(
        bool(compliance["uses_encryption"]) and not compliance["export_compliance_documented"],
        "export-compliance",
        "warning",
        "Encryption export-compliance answers are not documented",
        "compliance.uses_encryption=true and export_compliance_documented=false",
        "Document the submitted binary's encryption use and the corresponding "
        "export-compliance answer/evidence.",
    )
    add(
        bool(compliance["user_generated_content"])
        and not compliance["moderation_controls_available"],
        "user-generated-content-moderation",
        "warning",
        "User-generated content safeguards are unverified",
        "compliance.user_generated_content=true and moderation_controls_available=false",
        "Verify reporting, blocking, moderation, and contact controls appropriate to the product.",
    )

    blocker_count = sum(finding["severity"] == "blocker" for finding in findings)
    warning_count = sum(finding["severity"] == "warning" for finding in findings)
    status = "blocked" if blocker_count else "review" if warning_count else "ready"
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "schema_version": _SCHEMA,
        "status": status,
        "assurance": "risk-screening-only",
        "approval_guaranteed": False,
        "read_only": True,
        "network_access": False,
        "provider_mutations": 0,
        "manifest_sha256": hashlib.sha256(canonical).hexdigest(),
        "summary": {
            "blockers": blocker_count,
            "warnings": warning_count,
            "findings": len(findings),
        },
        "findings": findings,
        "limitations": [
            "This deterministic preflight cannot predict every App Review decision "
            "or guarantee approval.",
            "It evaluates operator-supplied facts and does not inspect a binary, "
            "App Store Connect metadata, legal obligations, or live reviewer access.",
            "Reconcile findings against the current Apple App Review Guidelines before submission.",
        ],
    }


def run_app_review_preflight(path: str | Path) -> dict[str, object]:
    return assess_app_review_manifest(load_app_review_manifest(path))
