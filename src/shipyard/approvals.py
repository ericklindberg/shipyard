from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any

from .models import ReleaseRun

_REVIEW_API = "shipyard.candidate-review/v1"
_APPROVAL_API = "shipyard.approval/v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class ApprovalPacketError(ValueError):
    pass


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ApprovalPacketError("approval packet must contain canonical JSON values") from exc


def _candidate_digest(payload: dict[str, object]) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _require_string(mapping: dict[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise ApprovalPacketError(f"{key} must be a non-empty string")
    return value


def _validate_review(packet: dict[str, object]) -> None:
    if packet.get("api_version") != _REVIEW_API:
        raise ApprovalPacketError(f"api_version must be {_REVIEW_API}")
    run_id = _require_string(packet, "run_id")
    if "/" in run_id or "\\" in run_id or run_id in {".", ".."}:
        raise ApprovalPacketError("run_id is invalid")
    digest = _require_string(packet, "candidate_digest")
    if _SHA256.fullmatch(digest) is None:
        raise ApprovalPacketError("candidate_digest must be a lowercase SHA-256 digest")
    source_sha = _require_string(packet, "source_sha")
    if _GIT_SHA.fullmatch(source_sha) is None:
        raise ApprovalPacketError("source_sha must be a lowercase 40-character Git SHA")
    provider = _require_string(packet, "provider")
    destination = _require_string(packet, "destination")
    candidate = packet.get("candidate")
    if not isinstance(candidate, dict):
        raise ApprovalPacketError("candidate must be an object")
    if _candidate_digest(candidate) != digest:
        raise ApprovalPacketError("candidate digest does not match candidate payload")
    source = candidate.get("source")
    target = candidate.get("destination")
    if not isinstance(source, dict) or source.get("sha") != source_sha:
        raise ApprovalPacketError("candidate source does not match review source")
    if (
        not isinstance(target, dict)
        or target.get("provider") != provider
        or target.get("identity") != destination
    ):
        raise ApprovalPacketError("candidate destination does not match review destination")


def build_candidate_review(run: ReleaseRun) -> dict[str, object]:
    digest = run.candidate_digest
    candidate = run.candidate_payload
    if digest is None or candidate is None:
        raise ApprovalPacketError("run does not have a prepared release candidate")
    if not isinstance(candidate, dict) or _candidate_digest(candidate) != digest:
        raise ApprovalPacketError("stored candidate digest does not match candidate payload")
    packet: dict[str, object] = {
        "api_version": _REVIEW_API,
        "run_id": run.run_id,
        "candidate_digest": digest,
        "source_sha": run.source.sha,
        "provider": run.provider,
        "destination": run.destination,
        "candidate": candidate,
    }
    _validate_review(packet)
    return packet


def canonical_packet_bytes(packet: dict[str, object]) -> bytes:
    _validate_review(packet)
    return _canonical_json(packet)


def _canonical_utc_timestamp(value: str) -> str:
    if _UTC_TIMESTAMP.fullmatch(value) is None:
        raise ApprovalPacketError("approved_at must be a canonical UTC timestamp ending in Z")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ApprovalPacketError("approved_at must be a valid canonical UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ApprovalPacketError("approved_at must be a canonical UTC timestamp ending in Z")
    return value


def build_approval_statement(
    review: dict[str, object], *, actor: str, reason: str, approved_at: str
) -> dict[str, str]:
    encoded = canonical_packet_bytes(review)
    actor = actor.strip()
    reason = reason.strip()
    if not actor:
        raise ApprovalPacketError("approval actor is required")
    if not reason:
        raise ApprovalPacketError("approval reason is required")
    approved_at = _canonical_utc_timestamp(approved_at)
    return {
        "api_version": _APPROVAL_API,
        "review_sha256": hashlib.sha256(encoded).hexdigest(),
        "candidate_digest": _require_string(review, "candidate_digest"),
        "source_sha": _require_string(review, "source_sha"),
        "provider": _require_string(review, "provider"),
        "destination": _require_string(review, "destination"),
        "actor": actor,
        "reason": reason,
        "approved_at": approved_at,
    }
