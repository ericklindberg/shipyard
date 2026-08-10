#!/usr/bin/env python3
"""Run an explicitly targeted provider sandbox check and optional gated mutation."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from shipyard.adapters.base import AdapterError
from shipyard.candidate import CandidateError
from shipyard.connections import (
    ConnectionError,
    ConnectionStore,
    render_playbook,
    verify_connection,
)
from shipyard.executor import (
    AuthorizationError,
    ProvenanceDriftError,
    ReleaseExecutor,
    UncertainOutcomeError,
)
from shipyard.gitops import GitError, snapshot_repository
from shipyard.ledger import Ledger, LedgerError
from shipyard.playbook import PlaybookError, load_playbook
from shipyard.redact import redact


def _load_generated_playbook(profile, state_dir: Path):
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix="sandbox-", suffix=".toml", dir=state_dir)
    path = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(render_playbook(profile, target="sandbox"))
            handle.flush()
            os.fsync(handle.fileno())
        return load_playbook(path)
    finally:
        path.unlink(missing_ok=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate one explicitly confirmed sandbox connection"
    )
    parser.add_argument("profile")
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--config-dir", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--confirm-destination", required=True)
    parser.add_argument("--execute-mutation", action="store_true")
    parser.add_argument("--confirm-sha")
    parser.add_argument("--approval-actor")
    parser.add_argument("--approval-reason")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.execute_mutation and not all(
        (args.confirm_sha, args.approval_actor, args.approval_reason)
    ):
        parser.error(
            "--execute-mutation requires --confirm-sha, --approval-actor, and --approval-reason"
        )
    try:
        profile = ConnectionStore(args.config_dir).get(args.profile)
        if args.confirm_destination != profile.destination:
            raise AuthorizationError("confirmed destination does not match connection profile")
        repo = args.repo.expanduser().resolve()
        snapshot = snapshot_repository(repo)
        if args.execute_mutation and args.confirm_sha != snapshot.sha:
            raise AuthorizationError("confirmed SHA does not match repository HEAD")

        check = verify_connection(profile, repo, allow_network=True)
        if check["status"] != "verified":
            raise AuthorizationError(
                "sandbox connection did not pass read-only identity verification"
            )

        payload: dict[str, object] = {
            "schema_version": 1,
            "profile": profile.name,
            "provider": profile.provider,
            "destination": profile.destination,
            "candidate_sha": snapshot.sha,
            "check": check,
            "mutation_executed": False,
        }
        if not args.execute_mutation:
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 0

        ledger = Ledger(args.state_dir)
        playbook = _load_generated_playbook(profile, args.state_dir)
        executor = ReleaseExecutor(ledger)
        prepared = executor.start(repo, playbook)
        if prepared.candidate_digest is None:
            raise CandidateError("sandbox run did not produce a candidate digest")
        completed = executor.resume(
            prepared.run_id,
            execute_external=True,
            confirm_sha=snapshot.sha,
            approve_candidate=prepared.candidate_digest,
            approval_actor=args.approval_actor,
            approval_reason=args.approval_reason,
        )
        payload.update(
            {
                "mutation_executed": True,
                "candidate_digest": prepared.candidate_digest,
                "run_id": completed.run_id,
                "run_status": completed.status,
                "readback_status": completed.steps[-1].provider_status,
            }
        )
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if completed.status == "succeeded" else 1
    except (
        AdapterError,
        AuthorizationError,
        CandidateError,
        ConnectionError,
        GitError,
        LedgerError,
        OSError,
        PlaybookError,
        ProvenanceDriftError,
        UncertainOutcomeError,
        ValueError,
    ) as exc:
        print(f"sandbox validation failed: {redact(str(exc))}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
