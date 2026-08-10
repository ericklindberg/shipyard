from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import sqlite3
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from .adapters.base import MutationReceipt, ProviderReadback
from .models import (
    ArtifactSpec,
    Effect,
    Playbook,
    ReleaseRun,
    RepositorySnapshot,
    RunStatus,
    StepRun,
    StepStatus,
)
from .redact import redact


class LedgerError(RuntimeError):
    pass


class RunBusyError(LedgerError):
    pass


_RUN_ID = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{8}$")
_SCHEMA_VERSION = 4


def _now() -> str:
    return datetime.now(UTC).isoformat()


class Ledger:
    def __init__(self, state_dir: str | Path):
        self.state_dir = Path(state_dir).expanduser().resolve()
        self.runs_dir = self.state_dir / "runs"
        self.runs_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.locks_dir = self.state_dir / "locks"
        self.locks_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state_dir, 0o700)
        os.chmod(self.runs_dir, 0o700)
        os.chmod(self.locks_dir, 0o700)
        self.database_path = self.state_dir / "shipyard.sqlite3"
        self._prepare_migration()
        self._initialize()
        os.chmod(self.database_path, 0o600)

    def _prepare_migration(self) -> None:
        if not self.database_path.exists() or self.database_path.stat().st_size == 0:
            return
        with sqlite3.connect(self.database_path) as source:
            version = int(source.execute("PRAGMA user_version").fetchone()[0])
            if version > _SCHEMA_VERSION:
                raise LedgerError(
                    f"ledger schema {version} is newer than supported {_SCHEMA_VERSION}"
                )
            has_tables = source.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' LIMIT 1"
            ).fetchone()
            if version == _SCHEMA_VERSION or has_tables is None:
                return
            backup_directory = self.state_dir / "backups"
            backup_directory.mkdir(mode=0o700, exist_ok=True)
            os.chmod(backup_directory, 0o700)
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            backup_path = backup_directory / (
                f"shipyard-v{version}-{stamp}-{uuid.uuid4().hex[:8]}.sqlite3"
            )
            with sqlite3.connect(backup_path) as destination:
                source.backup(destination)
            os.chmod(backup_path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @contextmanager
    def _governed_transaction(self) -> Iterator[sqlite3.Connection]:
        """Serialize one governed state change with its audit event."""
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            yield connection

    @contextmanager
    def lock_run(self, run_id: str) -> Iterator[None]:
        if not _RUN_ID.fullmatch(run_id):
            raise LedgerError(f"invalid run id: {run_id}")
        lock_path = self.locks_dir / f"{run_id}.lock"
        with lock_path.open("a+", encoding="utf-8") as lock_file:
            os.chmod(lock_path, 0o600)
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RunBusyError(f"run {run_id} is already executing") from exc
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    @contextmanager
    def lock_target(self, repo_path: Path, target: str) -> Iterator[None]:
        del repo_path  # destination identity, not clone location, is the fence key
        lock_directory = self._global_target_lock_directory()
        digest = hashlib.sha256(target.encode()).hexdigest()
        lock_path = lock_directory / f"target-{digest}.lock"
        with lock_path.open("a+", encoding="utf-8") as lock_file:
            os.chmod(lock_path, 0o600)
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RunBusyError(f"target {redact(target)} is already executing") from exc
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _global_target_lock_directory() -> Path:
        configured = os.environ.get("SHIPYARD_GLOBAL_LOCK_DIR")
        if configured:
            lock_directory = Path(configured).expanduser().resolve()
        else:
            runtime = os.environ.get("XDG_RUNTIME_DIR")
            base = Path(runtime).resolve() if runtime else Path(tempfile.gettempdir()).resolve()
            lock_directory = base / f"shipyard-{os.getuid()}-target-locks"
        lock_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = lock_directory.stat()
        if metadata.st_uid != os.getuid():
            raise LedgerError(f"target lock directory has wrong owner: {lock_directory}")
        os.chmod(lock_directory, 0o700)
        return lock_directory

    @staticmethod
    def _repository_lock_directory(repo_path: Path) -> Path:
        dot_git = repo_path.resolve() / ".git"
        if dot_git.is_dir():
            git_directory = dot_git
        elif dot_git.is_file():
            declaration = dot_git.read_text(encoding="utf-8").strip()
            if not declaration.startswith("gitdir:"):
                raise LedgerError(f"invalid Git control file: {dot_git}")
            configured = Path(declaration.removeprefix("gitdir:").strip())
            git_directory = (
                configured if configured.is_absolute() else (dot_git.parent / configured)
            ).resolve()
        else:
            raise LedgerError(f"Git control directory not found: {dot_git}")
        common_directory = git_directory / "commondir"
        if common_directory.is_file():
            configured = Path(common_directory.read_text(encoding="utf-8").strip())
            git_directory = (
                configured
                if configured.is_absolute()
                else (common_directory.parent / configured)
            ).resolve()
        lock_directory = git_directory / "shipyard-locks"
        lock_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(lock_directory, 0o700)
        return lock_directory

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    repo_path TEXT NOT NULL,
                    playbook_path TEXT NOT NULL,
                    playbook_name TEXT NOT NULL,
                    playbook_digest TEXT NOT NULL,
                    target TEXT NOT NULL,
                    allow_dirty INTEGER NOT NULL,
                    source_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS steps (
                    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                    ordinal INTEGER NOT NULL,
                    step_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    effect TEXT NOT NULL,
                    command_json TEXT NOT NULL,
                    timeout_seconds INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    exit_code INTEGER,
                    output_sha256 TEXT,
                    output_preview TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (run_id, ordinal),
                    UNIQUE (run_id, step_id)
                );
                CREATE TABLE IF NOT EXISTS step_attempts (
                    run_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL,
                    attempt_number INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    exit_code INTEGER,
                    output_sha256 TEXT,
                    output_preview TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (run_id, ordinal, attempt_number),
                    FOREIGN KEY (run_id, ordinal)
                        REFERENCES steps(run_id, ordinal) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS approvals (
                    run_id TEXT PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
                    candidate_digest TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    approved_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS adapter_receipts (
                    run_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL,
                    operation_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    action TEXT NOT NULL,
                    submitted_sha TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    readback_json TEXT,
                    provider_status TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (run_id, ordinal),
                    FOREIGN KEY (run_id, ordinal)
                        REFERENCES steps(run_id, ordinal) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                );
                """
            )
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(runs)").fetchall()
            }
            migrations = {
                "provider": "TEXT NOT NULL DEFAULT 'raw'",
                "destination": "TEXT NOT NULL DEFAULT ''",
                "artifacts_json": "TEXT NOT NULL DEFAULT '[]'",
                "candidate_digest": "TEXT",
                "candidate_json": "TEXT",
                "manifest_revision": "INTEGER NOT NULL DEFAULT 0",
                "playbook_schema": "INTEGER NOT NULL DEFAULT 1",
            }
            for column, declaration in migrations.items():
                if column not in columns:
                    connection.execute(
                        f"ALTER TABLE runs ADD COLUMN {column} {declaration}"
                    )
            step_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(steps)").fetchall()
            }
            step_migrations = {
                "action": "TEXT",
                "config_json": "TEXT NOT NULL DEFAULT '{}'",
            }
            for column, declaration in step_migrations.items():
                if column not in step_columns:
                    connection.execute(
                        f"ALTER TABLE steps ADD COLUMN {column} {declaration}"
                    )
            connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")

    def create_run(self, snapshot: RepositorySnapshot, playbook: Playbook) -> ReleaseRun:
        run_id = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
        timestamp = _now()
        source_json = json.dumps(
            {
                "path": str(snapshot.path),
                "sha": snapshot.sha,
                "branch": snapshot.branch,
                "dirty": snapshot.dirty,
                "changed_paths": list(snapshot.changed_paths),
                "remote_url": redact(snapshot.remote_url) if snapshot.remote_url else None,
                "upstream_sha": snapshot.upstream_sha,
                "worktree_digest": snapshot.worktree_digest,
            },
            sort_keys=True,
        )
        with self._governed_transaction() as connection:
            connection.execute(
                """
                INSERT INTO runs (
                    run_id, repo_path, playbook_path, playbook_name, playbook_digest,
                    target, allow_dirty, source_json, status, created_at, updated_at,
                    provider, destination, artifacts_json, manifest_revision,
                    playbook_schema
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'running', ?, ?, ?, ?, ?, 1, ?)
                """,
                (
                    run_id,
                    str(snapshot.path),
                    str(playbook.path),
                    playbook.name,
                    playbook.digest,
                    playbook.target,
                    int(playbook.allow_dirty),
                    source_json,
                    timestamp,
                    timestamp,
                    playbook.provider,
                    playbook.destination,
                    json.dumps(
                        [
                            {"path": artifact.path, "required": artifact.required}
                            for artifact in playbook.artifacts
                        ],
                        sort_keys=True,
                    ),
                    playbook.schema_version,
                ),
            )
            connection.executemany(
                """
                INSERT INTO steps (
                    run_id, ordinal, step_id, name, effect, command_json,
                    timeout_seconds, status, action, config_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
                """,
                [
                    (
                        run_id,
                        ordinal,
                        step.id,
                        step.name,
                        step.effect,
                        json.dumps(step.command),
                        step.timeout_seconds,
                        step.action,
                        json.dumps(step.config, sort_keys=True),
                    )
                    for ordinal, step in enumerate(playbook.steps)
                ],
            )
            self._insert_audit_event(
                connection,
                run_id,
                "run.created",
                {
                    "source_sha": snapshot.sha,
                    "playbook_sha256": playbook.digest,
                    "provider": playbook.provider,
                    "destination": playbook.destination,
                },
            )
        return self.get_run(run_id)

    def get_run(self, run_id: str) -> ReleaseRun:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
            if row is None:
                raise LedgerError(f"unknown run: {run_id}")
            step_rows = connection.execute(
                "SELECT * FROM steps WHERE run_id = ? ORDER BY ordinal", (run_id,)
            ).fetchall()
            receipt_rows = connection.execute(
                "SELECT * FROM adapter_receipts WHERE run_id = ?", (run_id,)
            ).fetchall()
        receipts = {receipt["ordinal"]: receipt for receipt in receipt_rows}
        source_data = json.loads(row["source_json"])
        artifact_data = json.loads(row["artifacts_json"])
        source = RepositorySnapshot(
            path=Path(source_data["path"]),
            sha=source_data["sha"],
            branch=source_data["branch"],
            dirty=bool(source_data["dirty"]),
            changed_paths=tuple(source_data["changed_paths"]),
            remote_url=source_data["remote_url"],
            upstream_sha=source_data["upstream_sha"],
            worktree_digest=source_data.get("worktree_digest"),
        )
        steps = tuple(
            StepRun(
                ordinal=step["ordinal"],
                id=step["step_id"],
                name=step["name"],
                effect=cast(Effect, step["effect"]),
                command=tuple(json.loads(step["command_json"])),
                timeout_seconds=step["timeout_seconds"],
                status=cast(StepStatus, step["status"]),
                attempts=step["attempts"],
                exit_code=step["exit_code"],
                output_sha256=step["output_sha256"],
                output_preview=step["output_preview"],
                action=step["action"],
                config=json.loads(step["config_json"]),
                operation_id=(
                    receipts[step["ordinal"]]["operation_id"]
                    if step["ordinal"] in receipts
                    else None
                ),
                provider_status=(
                    receipts[step["ordinal"]]["provider_status"]
                    if step["ordinal"] in receipts
                    else None
                ),
                readback=(
                    json.loads(receipts[step["ordinal"]]["readback_json"])
                    if step["ordinal"] in receipts
                    and receipts[step["ordinal"]]["readback_json"]
                    else None
                ),
            )
            for step in step_rows
        )
        run = ReleaseRun(
            run_id=row["run_id"],
            repo_path=Path(row["repo_path"]),
            playbook_path=Path(row["playbook_path"]),
            playbook_name=row["playbook_name"],
            playbook_digest=row["playbook_digest"],
            target=row["target"],
            allow_dirty=bool(row["allow_dirty"]),
            source=source,
            status=cast(RunStatus, row["status"]),
            steps=steps,
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            provider=row["provider"],
            destination=row["destination"] or row["target"],
            artifacts=tuple(
                ArtifactSpec(path=item["path"], required=bool(item.get("required", True)))
                for item in artifact_data
            ),
            candidate_digest=row["candidate_digest"],
            candidate_payload=(
                json.loads(row["candidate_json"]) if row["candidate_json"] else None
            ),
            manifest_revision=row["manifest_revision"],
            playbook_schema=row["playbook_schema"],
        )
        self.write_manifest(run)
        return run

    def list_runs(self, limit: int = 100) -> list[ReleaseRun]:
        if not 1 <= limit <= 1000:
            raise LedgerError("run list limit must be between 1 and 1000")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT run_id FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self.get_run(row["run_id"]) for row in rows]

    def verify_audit_chain(self, run_id: str) -> bool:
        events = self.list_audit_events(run_id)
        if not events:
            return False
        previous_hash = "0" * 64
        for event in events:
            canonical_payload = json.dumps(
                event["payload"], separators=(",", ":"), sort_keys=True
            )
            material = "\0".join(
                (
                    run_id,
                    str(event["event_type"]),
                    canonical_payload,
                    str(event["created_at"]),
                    previous_hash,
                )
            )
            expected = hashlib.sha256(material.encode()).hexdigest()
            if event["previous_hash"] != previous_hash or event["event_hash"] != expected:
                return False
            previous_hash = str(event["event_hash"])
        return True

    def begin_step(self, run_id: str, ordinal: int) -> None:
        timestamp = _now()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT attempts FROM steps WHERE run_id = ? AND ordinal = ?",
                (run_id, ordinal),
            ).fetchone()
            if row is None:
                raise LedgerError(f"unknown step {ordinal} for run {run_id}")
            attempt_number = row["attempts"] + 1
            connection.execute(
                """
                UPDATE steps
                SET status = 'running', attempts = attempts + 1,
                    exit_code = NULL, output_sha256 = NULL, output_preview = ''
                WHERE run_id = ? AND ordinal = ?
                """,
                (run_id, ordinal),
            )
            connection.execute(
                """
                INSERT INTO step_attempts (
                    run_id, ordinal, attempt_number, status, started_at
                ) VALUES (?, ?, ?, 'running', ?)
                """,
                (run_id, ordinal, attempt_number, timestamp),
            )
            connection.execute(
                """
                UPDATE runs
                SET status = 'running', updated_at = ?,
                    manifest_revision = manifest_revision + 1
                WHERE run_id = ?
                """,
                (timestamp, run_id),
            )
        self.get_run(run_id)

    def finish_step(
        self,
        run_id: str,
        ordinal: int,
        *,
        status: StepStatus,
        exit_code: int | None,
        output_sha256: str | None,
        output_preview: str,
    ) -> None:
        timestamp = _now()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE steps
                SET status = ?, exit_code = ?, output_sha256 = ?, output_preview = ?
                WHERE run_id = ? AND ordinal = ?
                """,
                (status, exit_code, output_sha256, output_preview, run_id, ordinal),
            )
            connection.execute(
                """
                UPDATE step_attempts
                SET status = ?, finished_at = ?, exit_code = ?,
                    output_sha256 = ?, output_preview = ?
                WHERE run_id = ? AND ordinal = ?
                  AND attempt_number = (
                      SELECT attempts FROM steps WHERE run_id = ? AND ordinal = ?
                  )
                """,
                (
                    status,
                    timestamp,
                    exit_code,
                    output_sha256,
                    output_preview,
                    run_id,
                    ordinal,
                    run_id,
                    ordinal,
                ),
            )
            connection.execute(
                """
                UPDATE runs
                SET updated_at = ?, manifest_revision = manifest_revision + 1
                WHERE run_id = ?
                """,
                (timestamp, run_id),
            )
        self.get_run(run_id)

    def set_run_status(self, run_id: str, status: RunStatus) -> ReleaseRun:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE runs
                SET status = ?, updated_at = ?,
                    manifest_revision = manifest_revision + 1
                WHERE run_id = ?
                """,
                (status, _now(), run_id),
            )
        return self.get_run(run_id)

    def store_candidate(
        self, run_id: str, digest: str, payload: dict[str, object]
    ) -> ReleaseRun:
        with self._governed_transaction() as connection:
            connection.execute(
                """
                UPDATE runs
                SET candidate_digest = ?, candidate_json = ?, updated_at = ?,
                    manifest_revision = manifest_revision + 1
                WHERE run_id = ?
                """,
                (digest, json.dumps(payload, sort_keys=True), _now(), run_id),
            )
            self._insert_audit_event(
                connection, run_id, "candidate.prepared", {"candidate_digest": digest}
            )
        return self.get_run(run_id)

    def record_approval(
        self,
        run_id: str,
        candidate_digest: str,
        *,
        actor: str,
        reason: str,
    ) -> None:
        if not actor.strip() or not reason.strip():
            raise LedgerError("approval actor and reason are required")
        with self._governed_transaction() as connection:
            row = connection.execute(
                "SELECT candidate_digest FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if row is None:
                raise LedgerError(f"unknown run: {run_id}")
            if row["candidate_digest"] != candidate_digest:
                raise LedgerError("approval digest does not match the stored candidate")
            connection.execute(
                """
                INSERT INTO approvals (
                    run_id, candidate_digest, actor, reason, approved_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    candidate_digest = excluded.candidate_digest,
                    actor = excluded.actor,
                    reason = excluded.reason,
                    approved_at = excluded.approved_at
                """,
                (run_id, candidate_digest, actor.strip(), reason.strip(), _now()),
            )
            connection.execute(
                """
                UPDATE runs
                SET manifest_revision = manifest_revision + 1, updated_at = ?
                WHERE run_id = ?
                """,
                (_now(), run_id),
            )
            self._insert_audit_event(
                connection,
                run_id,
                "candidate.approved",
                {
                    "candidate_digest": candidate_digest,
                    "actor": actor.strip(),
                    "reason": reason.strip(),
                },
            )

    def get_approval(self, run_id: str) -> dict[str, str] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM approvals WHERE run_id = ?", (run_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    def append_audit_event(
        self, run_id: str, event_type: str, payload: dict[str, object]
    ) -> dict[str, object]:
        with self._governed_transaction() as connection:
            return self._insert_audit_event(connection, run_id, event_type, payload)

    @staticmethod
    def _insert_audit_event(
        connection: sqlite3.Connection,
        run_id: str,
        event_type: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        created_at = _now()
        canonical_payload = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        previous = connection.execute(
            """
            SELECT event_hash FROM audit_events
            WHERE run_id = ? ORDER BY sequence DESC LIMIT 1
            """,
            (run_id,),
        ).fetchone()
        previous_hash = previous["event_hash"] if previous else "0" * 64
        material = "\0".join(
            (run_id, event_type, canonical_payload, created_at, previous_hash)
        )
        event_hash = hashlib.sha256(material.encode()).hexdigest()
        cursor = connection.execute(
            """
            INSERT INTO audit_events (
                run_id, event_type, payload_json, created_at,
                previous_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                event_type,
                canonical_payload,
                created_at,
                previous_hash,
                event_hash,
            ),
        )
        return {
            "sequence": cursor.lastrowid,
            "event_type": event_type,
            "payload": payload,
            "created_at": created_at,
            "previous_hash": previous_hash,
            "event_hash": event_hash,
        }

    def list_audit_events(self, run_id: str) -> list[dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM audit_events WHERE run_id = ? ORDER BY sequence", (run_id,)
            ).fetchall()
        return [
            {
                "sequence": row["sequence"],
                "event_type": row["event_type"],
                "payload": json.loads(row["payload_json"]),
                "created_at": row["created_at"],
                "previous_hash": row["previous_hash"],
                "event_hash": row["event_hash"],
            }
            for row in rows
        ]

    def record_adapter_receipt(
        self, run_id: str, ordinal: int, receipt: MutationReceipt
    ) -> None:
        timestamp = _now()
        payload: dict[str, object] = {
            "ordinal": ordinal,
            "provider": receipt.provider,
            "action": receipt.action,
            "operation_id": receipt.operation_id,
            "submitted_sha": receipt.submitted_sha,
            "evidence": receipt.evidence,
        }
        # An external mutation may already exist before this method is called. Persist the
        # provider operation identity first so a later audit failure cannot destroy the
        # only durable input to read-only reconciliation.
        with self._governed_transaction() as connection:
            connection.execute(
                """
                INSERT INTO adapter_receipts (
                    run_id, ordinal, operation_id, provider, action, submitted_sha,
                    receipt_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id, ordinal) DO UPDATE SET
                    operation_id = excluded.operation_id,
                    provider = excluded.provider,
                    action = excluded.action,
                    submitted_sha = excluded.submitted_sha,
                    receipt_json = excluded.receipt_json,
                    updated_at = excluded.updated_at
                """,
                (
                    run_id,
                    ordinal,
                    receipt.operation_id,
                    receipt.provider,
                    receipt.action,
                    receipt.submitted_sha,
                    json.dumps(payload, sort_keys=True),
                    timestamp,
                    timestamp,
                ),
            )
        try:
            self.append_audit_event(run_id, "adapter.receipt", payload)
        except sqlite3.Error as exc:
            raise LedgerError(
                "adapter receipt is durable but its audit event could not be written; "
                "the provider outcome is uncertain and must be reconciled with resolve"
            ) from exc

    def ensure_adapter_receipt_audit_event(self, run_id: str, ordinal: int) -> bool:
        """Append a missing audit event from a durable provider receipt.

        Returns ``True`` only when recovery appended the event. This is intentionally
        limited to provider receipts: they are the write-ahead record of a mutation
        that may already have succeeded outside Shipyard.
        """
        with self._governed_transaction() as connection:
            row = connection.execute(
                """
                SELECT receipt_json FROM adapter_receipts
                WHERE run_id = ? AND ordinal = ?
                """,
                (run_id, ordinal),
            ).fetchone()
            if row is None:
                return False
            receipt_json = str(row["receipt_json"])
            try:
                payload = json.loads(receipt_json)
            except (json.JSONDecodeError, TypeError) as exc:
                raise LedgerError(
                    "stored adapter receipt is malformed; "
                    "manual ledger reconciliation is required"
                ) from exc
            if not isinstance(payload, dict):
                raise LedgerError(
                    "stored adapter receipt is malformed; "
                    "manual ledger reconciliation is required"
                )
            stored_ordinal = payload.get("ordinal")
            if stored_ordinal is None:
                stored_receipts = connection.execute(
                    """
                    SELECT receipt_json FROM adapter_receipts
                    WHERE run_id = ?
                    """,
                    (run_id,),
                ).fetchall()
                try:
                    duplicate_count = sum(
                        json.loads(str(candidate["receipt_json"])) == payload
                        for candidate in stored_receipts
                    )
                except (json.JSONDecodeError, TypeError) as exc:
                    raise LedgerError(
                        "stored adapter receipt is malformed; "
                        "manual ledger reconciliation is required"
                    ) from exc
                if duplicate_count != 1:
                    raise LedgerError(
                        "legacy adapter receipt audit binding is ambiguous; "
                        "manual ledger reconciliation is required"
                    )
                legacy_payload = json.dumps(
                    payload, separators=(",", ":"), sort_keys=True
                )
                legacy_event = connection.execute(
                    """
                    SELECT 1 FROM audit_events
                    WHERE run_id = ? AND event_type = 'adapter.receipt'
                      AND payload_json = ?
                    LIMIT 1
                    """,
                    (run_id, legacy_payload),
                ).fetchone()
                if legacy_event is not None:
                    return False
                payload["ordinal"] = ordinal
            elif stored_ordinal != ordinal:
                raise LedgerError(
                    "adapter receipt ordinal does not match its ledger step"
                )
            canonical_payload = json.dumps(
                payload, separators=(",", ":"), sort_keys=True
            )
            existing = connection.execute(
                """
                SELECT 1 FROM audit_events
                WHERE run_id = ? AND event_type = 'adapter.receipt'
                  AND payload_json = ?
                LIMIT 1
                """,
                (run_id, canonical_payload),
            ).fetchone()
            if existing is not None:
                return False
            self._insert_audit_event(connection, run_id, "adapter.receipt", payload)
            return True

    def record_adapter_readback(
        self, run_id: str, ordinal: int, readback: ProviderReadback
    ) -> None:
        payload: dict[str, object] = {
            "status": readback.status,
            "operation_id": readback.operation_id,
            "observed_sha": readback.observed_sha,
            "evidence": readback.evidence,
        }
        with self._governed_transaction() as connection:
            connection.execute(
                """
                UPDATE adapter_receipts
                SET readback_json = ?, provider_status = ?, updated_at = ?
                WHERE run_id = ? AND ordinal = ?
                """,
                (
                    json.dumps(payload, sort_keys=True),
                    readback.status,
                    _now(),
                    run_id,
                    ordinal,
                ),
            )
            self._insert_audit_event(connection, run_id, "adapter.readback", payload)

    def get_adapter_receipt(
        self, run_id: str, ordinal: int
    ) -> MutationReceipt | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT receipt_json FROM adapter_receipts
                WHERE run_id = ? AND ordinal = ?
                """,
                (run_id, ordinal),
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(row["receipt_json"])
        return MutationReceipt(
            provider=payload["provider"],
            action=payload["action"],
            operation_id=payload["operation_id"],
            submitted_sha=payload["submitted_sha"],
            evidence=payload["evidence"],
        )

    def manifest_payload(self, run: ReleaseRun) -> dict[str, object]:
        with self._connect() as connection:
            attempt_rows = connection.execute(
                """
                SELECT * FROM step_attempts
                WHERE run_id = ?
                ORDER BY ordinal, attempt_number
                """,
                (run.run_id,),
            ).fetchall()
        attempt_history: dict[int, list[dict[str, object]]] = {}
        for attempt in attempt_rows:
            attempt_history.setdefault(attempt["ordinal"], []).append(
                {
                    "attempt_number": attempt["attempt_number"],
                    "status": attempt["status"],
                    "started_at": attempt["started_at"],
                    "finished_at": attempt["finished_at"],
                    "exit_code": attempt["exit_code"],
                    "output_sha256": attempt["output_sha256"],
                    "output_preview": attempt["output_preview"],
                }
            )
        payload = {
            "schema_version": 1,
            "manifest_revision": run.manifest_revision,
            "run_id": run.run_id,
            "status": run.status,
            "project": {
                "playbook": run.playbook_name,
                "playbook_sha256": run.playbook_digest,
                "target": run.target,
                "provider": run.provider,
                "destination": run.destination,
            },
            "candidate": {
                "digest": run.candidate_digest,
                "payload": run.candidate_payload,
                "approval": self.get_approval(run.run_id),
            },
            "audit_events": self.list_audit_events(run.run_id),
            "source": {
                "path": str(run.source.path),
                "sha": run.source.sha,
                "branch": run.source.branch,
                "dirty": run.source.dirty,
                "changed_paths": list(run.source.changed_paths),
                "remote_url": run.source.remote_url,
                "upstream_sha": run.source.upstream_sha,
                "worktree_digest": run.source.worktree_digest,
            },
            "steps": [
                {
                    "ordinal": step.ordinal,
                    "id": step.id,
                    "name": step.name,
                    "effect": step.effect,
                    "command": list(step.command),
                    "action": step.action,
                    "config": step.config,
                    "operation_id": step.operation_id,
                    "provider_status": step.provider_status,
                    "readback": step.readback,
                    "status": step.status,
                    "attempts": step.attempts,
                    "exit_code": step.exit_code,
                    "output_sha256": step.output_sha256,
                    "output_preview": step.output_preview,
                    "attempt_history": attempt_history.get(step.ordinal, []),
                }
                for step in run.steps
            ],
            "created_at": run.created_at,
            "updated_at": run.updated_at,
        }
        return payload

    def write_manifest(self, run: ReleaseRun) -> Path:
        payload = self.manifest_payload(run)
        destination = self.runs_dir / f"{run.run_id}.json"
        temporary = self.runs_dir / f".{run.run_id}.{uuid.uuid4().hex}.tmp"
        manifest_lock = self.locks_dir / f"manifest-{run.run_id}.lock"
        with manifest_lock.open("a+", encoding="utf-8") as lock_file:
            os.chmod(manifest_lock, 0o600)
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                if destination.is_file():
                    try:
                        existing = json.loads(destination.read_text(encoding="utf-8"))
                        if existing.get("manifest_revision", -1) > run.manifest_revision:
                            return destination
                    except (OSError, json.JSONDecodeError):
                        pass
                temporary.write_text(
                    json.dumps(payload, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                os.chmod(temporary, 0o600)
                os.replace(temporary, destination)
            finally:
                temporary.unlink(missing_ok=True)
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        return destination
