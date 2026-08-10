from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path

import pytest

from shipyard.gitops import snapshot_repository
from shipyard.ledger import Ledger, LedgerError, RunBusyError
from shipyard.playbook import load_playbook


def _local_playbook(path: Path) -> Path:
    path.write_text(
        '''schema_version = 1
name = "ledger"
target = "local"

[[steps]]
id = "verify"
name = "Verify"
effect = "verify"
command = ["git", "status", "--short"]
''',
        encoding="utf-8",
    )
    return path


def test_v1_database_is_transactionally_migrated(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    database = state / "shipyard.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            '''CREATE TABLE runs (
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
            )'''
        )
        connection.execute("PRAGMA user_version = 1")

    ledger = Ledger(state)

    with sqlite3.connect(ledger.database_path) as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(runs)").fetchall()
        }
        approvals = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='approvals'"
        ).fetchone()
    assert version == 4
    assert {
        "provider",
        "destination",
        "artifacts_json",
        "candidate_digest",
        "candidate_json",
        "manifest_revision",
    } <= columns
    assert approvals is not None
    backups = list((state / "backups").glob("shipyard-v1-*.sqlite3"))
    assert len(backups) == 1
    assert backups[0].stat().st_mode & 0o777 == 0o600


def test_newer_database_schema_is_rejected_without_modification(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    database = state / "shipyard.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE sentinel (value TEXT)")
        connection.execute("INSERT INTO sentinel VALUES ('preserve-me')")
        connection.execute("PRAGMA user_version = 99")

    with pytest.raises(LedgerError, match="newer than supported"):
        Ledger(state)

    with sqlite3.connect(database) as connection:
        value = connection.execute("SELECT value FROM sentinel").fetchone()[0]
        version = connection.execute("PRAGMA user_version").fetchone()[0]
    assert value == "preserve-me"
    assert version == 99


def test_stale_manifest_writer_cannot_overwrite_newer_revision(git_repo, tmp_path):
    ledger = Ledger(tmp_path / "state")
    stale = ledger.create_run(
        snapshot_repository(git_repo), load_playbook(_local_playbook(tmp_path / "shipyard.toml"))
    )
    current = ledger.set_run_status(stale.run_id, "failed")
    assert current.manifest_revision > stale.manifest_revision

    ledger.write_manifest(stale)

    payload = json.loads(
        (ledger.runs_dir / f"{stale.run_id}.json").read_text(encoding="utf-8")
    )
    assert payload["status"] == "failed"
    assert payload["manifest_revision"] == current.manifest_revision


def test_canonical_target_lock_fences_independent_clones(git_repo, tmp_path, monkeypatch):
    global_locks = tmp_path / "global-locks"
    monkeypatch.setenv("SHIPYARD_GLOBAL_LOCK_DIR", str(global_locks))
    clone = tmp_path / "clone"
    subprocess.run(
        ["git", "clone", "-q", str(git_repo), str(clone)], check=True
    )
    first = Ledger(tmp_path / "state-a")
    second = Ledger(tmp_path / "state-b")

    with (
        first.lock_target(git_repo, "github:owner/repo:refs/heads/main"),
        pytest.raises(RunBusyError, match="already executing"),
        second.lock_target(clone, "github:owner/repo:refs/heads/main"),
    ):
        pass
