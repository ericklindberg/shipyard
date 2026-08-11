from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from shipyard.approvals import (
    ApprovalPacketError,
    build_approval_statement,
    build_candidate_review,
    canonical_packet_bytes,
    sign_approval_ssh,
    verify_signed_approval_ssh,
)
from shipyard.executor import ReleaseExecutor
from shipyard.ledger import Ledger
from shipyard.playbook import load_playbook


def _prepared_run(git_repo: Path, tmp_path: Path):
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    subprocess.run(["git", "remote", "add", "origin", str(remote)], cwd=git_repo, check=True)
    playbook = tmp_path / "shipyard.toml"
    playbook.write_text(
        '''schema_version = 2
name = "review-packet"
target = "sandbox"
provider = "github"
destination = "local-sandbox:refs/heads/release"

[[steps]]
id = "publish"
name = "Publish exact candidate"
effect = "external"
action = "git.ref"

[steps.config]
remote = "origin"
ref = "refs/heads/release"
''',
        encoding="utf-8",
    )
    ledger = Ledger(tmp_path / "state")
    run = ReleaseExecutor(ledger).start(git_repo, load_playbook(playbook))
    assert run.status == "awaiting_authorization"
    assert run.candidate_digest is not None
    assert run.candidate_payload is not None
    return run


def test_candidate_review_packet_is_deterministic_and_digest_bound(git_repo, tmp_path):
    run = _prepared_run(git_repo, tmp_path)

    first = build_candidate_review(run)
    second = build_candidate_review(run)
    encoded = canonical_packet_bytes(first)

    assert first == second
    assert first["api_version"] == "shipyard.candidate-review/v1"
    assert first["candidate_digest"] == run.candidate_digest
    assert first["source_sha"] == run.source.sha
    assert first["destination"] == run.destination
    assert encoded == canonical_packet_bytes(second)
    assert json.loads(encoded) == first
    assert b"approved_at" not in encoded


def test_candidate_review_rejects_tampered_stored_candidate(git_repo, tmp_path):
    run = _prepared_run(git_repo, tmp_path)
    assert run.candidate_payload is not None
    run.candidate_payload["destination"] = {"provider": "github", "identity": "other"}

    with pytest.raises(ApprovalPacketError, match="candidate digest"):
        build_candidate_review(run)


def test_approval_statement_binds_review_actor_reason_and_canonical_utc_time(git_repo, tmp_path):
    review = build_candidate_review(_prepared_run(git_repo, tmp_path))

    statement = build_approval_statement(
        review,
        actor="alice@example.test",
        reason="Promote reviewed candidate",
        approved_at="2026-08-10T18:30:00Z",
    )

    assert statement == {
        "api_version": "shipyard.approval/v1",
        "review_sha256": hashlib.sha256(canonical_packet_bytes(review)).hexdigest(),
        "candidate_digest": review["candidate_digest"],
        "source_sha": review["source_sha"],
        "provider": review["provider"],
        "destination": review["destination"],
        "actor": "alice@example.test",
        "reason": "Promote reviewed candidate",
        "approved_at": "2026-08-10T18:30:00Z",
    }


@pytest.mark.parametrize(
    ("actor", "reason", "approved_at", "message"),
    [
        ("", "reason", "2026-08-10T18:30:00Z", "actor"),
        ("alice", "", "2026-08-10T18:30:00Z", "reason"),
        ("alice", "reason", "2026-08-10 18:30:00", "UTC"),
        ("alice", "reason", "2026-08-10T18:30:00+01:00", "UTC"),
    ],
)
def test_approval_statement_rejects_ambiguous_identity_or_time(
    git_repo, tmp_path, actor, reason, approved_at, message
):
    review = build_candidate_review(_prepared_run(git_repo, tmp_path))

    with pytest.raises(ApprovalPacketError, match=message):
        build_approval_statement(
            review,
            actor=actor,
            reason=reason,
            approved_at=approved_at,
        )


def _ssh_identity(tmp_path: Path) -> tuple[Path, Path]:
    key = tmp_path / "approval-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    allowed = tmp_path / "allowed-signers"
    public_key = key.with_suffix(".pub").read_text(encoding="utf-8").strip()
    allowed.write_text(f"alice@example.test {public_key}\n", encoding="utf-8")
    return key, allowed


def test_ssh_signed_approval_verifies_against_review_and_allowed_signer(
    git_repo, tmp_path
):
    review = build_candidate_review(_prepared_run(git_repo, tmp_path))
    statement = build_approval_statement(
        review,
        actor="alice@example.test",
        reason="Reviewed exact candidate",
        approved_at="2026-08-10T18:30:00Z",
    )
    key, allowed = _ssh_identity(tmp_path)

    signed = sign_approval_ssh(statement, key_path=key)
    verified = verify_signed_approval_ssh(signed, review=review, allowed_signers=allowed)

    assert verified == statement
    assert signed["api_version"] == "shipyard.signed-approval/v1"
    assert signed["signature"]["kind"] == "ssh"
    assert "PRIVATE" not in json.dumps(signed)


def test_ssh_approval_rejects_tampered_statement(git_repo, tmp_path):
    review = build_candidate_review(_prepared_run(git_repo, tmp_path))
    statement = build_approval_statement(
        review,
        actor="alice@example.test",
        reason="Reviewed exact candidate",
        approved_at="2026-08-10T18:30:00Z",
    )
    key, allowed = _ssh_identity(tmp_path)
    signed = sign_approval_ssh(statement, key_path=key)
    signed["statement"]["reason"] = "tampered"

    with pytest.raises(ApprovalPacketError, match="signature verification failed"):
        verify_signed_approval_ssh(signed, review=review, allowed_signers=allowed)


def test_ssh_approval_rejects_signer_not_allowed_for_actor(git_repo, tmp_path):
    review = build_candidate_review(_prepared_run(git_repo, tmp_path))
    statement = build_approval_statement(
        review,
        actor="mallory@example.test",
        reason="Not an allowed signer",
        approved_at="2026-08-10T18:30:00Z",
    )
    key, allowed = _ssh_identity(tmp_path)
    signed = sign_approval_ssh(statement, key_path=key)

    with pytest.raises(ApprovalPacketError, match="signature verification failed"):
        verify_signed_approval_ssh(signed, review=review, allowed_signers=allowed)


def test_ssh_approval_rejects_mismatched_review(git_repo, tmp_path):
    first = build_candidate_review(_prepared_run(git_repo, tmp_path))
    second = dict(first)
    second["run_id"] = "different-run"
    statement = build_approval_statement(
        first,
        actor="alice@example.test",
        reason="Reviewed exact candidate",
        approved_at="2026-08-10T18:30:00Z",
    )
    key, allowed = _ssh_identity(tmp_path)
    signed = sign_approval_ssh(statement, key_path=key)

    with pytest.raises(ApprovalPacketError, match="review"):
        verify_signed_approval_ssh(signed, review=second, allowed_signers=allowed)
