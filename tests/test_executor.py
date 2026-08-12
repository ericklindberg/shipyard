from __future__ import annotations

import json
import os
import signal
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from shipyard.executor import (
    AuthorizationError,
    ProcessInterrupted,
    ProvenanceDriftError,
    ReleaseExecutor,
    UncertainOutcomeError,
    _run_process,
)
from shipyard.gitops import snapshot_repository
from shipyard.ledger import Ledger, LedgerError, RunBusyError
from shipyard.playbook import load_playbook


def make_playbook(path: Path) -> Path:
    playbook = path / "shipyard.toml"
    playbook.write_text(
        '''schema_version = 1
name = "executor-test"
target = "test"
allow_dirty = false

[[steps]]
id = "verify"
name = "Verify"
effect = "verify"
command = ["git", "status", "--short"]

[[steps]]
id = "external"
name = "External"
effect = "external"
command = ["python3", "-c", "from pathlib import Path; Path('released.txt').write_text('released')"]
''',
        encoding="utf-8",
    )
    return playbook


def write_python_script(path: Path, source: str) -> Path:
    path.write_text(source + "\n", encoding="utf-8")
    return path


def approve(executor: ReleaseExecutor, run):
    prepared = executor.ledger.get_run(run.run_id)
    assert prepared.candidate_digest
    return executor.resume(
        prepared.run_id,
        execute_external=True,
        confirm_sha=prepared.source_sha,
        approve_candidate=prepared.candidate_digest,
        approval_actor="pytest",
        approval_reason="exercise candidate-bound release",
    )


def test_run_stops_before_external_side_effect_and_persists_readback(git_repo, tmp_path):
    ledger = Ledger(tmp_path / "state")
    executor = ReleaseExecutor(ledger)

    result = executor.start(git_repo, load_playbook(make_playbook(tmp_path)))

    assert result.status == "awaiting_authorization"
    assert not (git_repo / "released.txt").exists()
    readback = ledger.get_run(result.run_id)
    assert [step.status for step in readback.steps] == ["succeeded", "blocked"]
    manifest = json.loads((tmp_path / "state" / "runs" / f"{result.run_id}.json").read_text())
    assert manifest["source"]["sha"] == result.source_sha
    assert manifest["steps"][0]["output_sha256"]


def test_get_run_rebuilds_stale_manifest_from_sqlite(git_repo, tmp_path):
    ledger = Ledger(tmp_path / "state")
    run = ledger.create_run(
        snapshot_repository(git_repo),
        load_playbook(make_playbook(tmp_path)),
    )
    manifest_path = ledger.runs_dir / f"{run.run_id}.json"
    manifest_path.write_text('{"status":"stale"}\n', encoding="utf-8")

    readback = ledger.get_run(run.run_id)

    rebuilt = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert rebuilt["status"] == readback.status
    assert rebuilt["run_id"] == run.run_id
    assert rebuilt["steps"][0]["status"] == "pending"


def test_concurrent_readback_uses_distinct_manifest_temporaries(
    git_repo, tmp_path, monkeypatch
):
    ledger = Ledger(tmp_path / "state")
    run = ledger.create_run(
        snapshot_repository(git_repo),
        load_playbook(make_playbook(tmp_path)),
    )
    original_replace = os.replace
    sources = []

    def synchronized_replace(source, destination):
        sources.append(source)
        original_replace(source, destination)

    monkeypatch.setattr("shipyard.ledger.os.replace", synchronized_replace)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: ledger.get_run(run.run_id), range(2)))

    assert [result.run_id for result in results] == [run.run_id, run.run_id]
    assert len(sources) == 2
    assert sources[0] != sources[1]


def test_resume_requires_both_external_flag_and_exact_sha(git_repo, tmp_path):
    ledger = Ledger(tmp_path / "state")
    executor = ReleaseExecutor(ledger)
    result = executor.start(git_repo, load_playbook(make_playbook(tmp_path)))

    with pytest.raises(AuthorizationError, match="execute-external"):
        executor.resume(
            result.run_id,
            confirm_sha=result.source_sha,
            approve_candidate=result.candidate_digest,
            approval_actor="pytest",
            approval_reason="test",
        )

    with pytest.raises(AuthorizationError, match="exact source SHA"):
        executor.resume(
            result.run_id,
            execute_external=True,
            confirm_sha="0" * 40,
            approve_candidate=result.candidate_digest,
            approval_actor="pytest",
            approval_reason="test",
        )

    resumed = approve(executor, result)

    assert resumed.status == "succeeded"
    assert (git_repo / "released.txt").read_text() == "released"


def test_persisted_approval_still_requires_per_invocation_external_consent_and_sha(
    git_repo, tmp_path
):
    ledger = Ledger(tmp_path / "state")
    executor = ReleaseExecutor(ledger)
    prepared = executor.start(git_repo, load_playbook(make_playbook(tmp_path)))
    assert prepared.candidate_digest
    ledger.record_approval(
        prepared.run_id,
        prepared.candidate_digest,
        actor="pytest",
        reason="persist approval without granting future mutation consent",
    )

    with pytest.raises(AuthorizationError, match="execute-external"):
        executor.resume(prepared.run_id, confirm_sha=prepared.source_sha)
    assert not (git_repo / "released.txt").exists()
    assert ledger.get_run(prepared.run_id).steps[-1].attempts == 0

    with pytest.raises(AuthorizationError, match="exact source SHA"):
        executor.resume(
            prepared.run_id,
            execute_external=True,
            confirm_sha="0" * 40,
        )
    assert not (git_repo / "released.txt").exists()
    assert ledger.get_run(prepared.run_id).steps[-1].attempts == 0

    completed = executor.resume(
        prepared.run_id,
        execute_external=True,
        confirm_sha=prepared.source_sha,
    )
    assert completed.status == "succeeded"
    assert (git_repo / "released.txt").read_text() == "released"


def test_resume_refuses_when_head_changes(git_repo, tmp_path):
    ledger = Ledger(tmp_path / "state")
    executor = ReleaseExecutor(ledger)
    result = executor.start(git_repo, load_playbook(make_playbook(tmp_path)))
    (git_repo / "README.md").write_text("changed\n", encoding="utf-8")

    with pytest.raises(ProvenanceDriftError, match="working tree"):
        executor.resume(
            result.run_id,
            execute_external=True,
            confirm_sha=result.source_sha,
        )


def test_concurrent_resume_is_rejected(git_repo, tmp_path):
    ledger = Ledger(tmp_path / "state")
    run = ledger.create_run(
        snapshot_repository(git_repo),
        load_playbook(make_playbook(tmp_path)),
    )

    with ledger.lock_run(run.run_id), pytest.raises(
        RunBusyError, match="already executing"
    ):
        ReleaseExecutor(ledger).resume(run.run_id)

    with pytest.raises(LedgerError, match="invalid run id"), ledger.lock_run("../escape"):
        pass


def test_target_lock_is_shared_across_state_directories(git_repo, tmp_path):
    first = Ledger(tmp_path / "state-a")
    second = Ledger(tmp_path / "state-b")

    with (
        first.lock_target(git_repo, "production"),
        pytest.raises(RunBusyError, match="target .* already executing"),
        second.lock_target(git_repo, "production"),
    ):
        pass


def test_concurrent_external_runs_for_same_target_are_rejected(git_repo, tmp_path):
    started = tmp_path / "external-started"
    script = tmp_path / "slow_external.py"
    script.write_text(
        "from pathlib import Path\n"
        "import time\n"
        f"Path({str(started)!r}).write_text('started')\n"
        "time.sleep(1)\n",
        encoding="utf-8",
    )
    playbook_path = tmp_path / "external-lock.toml"
    playbook_path.write_text(
        f'''schema_version = 1
name = "external-lock"
target = "production"

[[steps]]
id = "deploy"
name = "Deploy"
effect = "external"
command = ["python3", {json.dumps(str(script))}]
''',
        encoding="utf-8",
    )
    ledger = Ledger(tmp_path / "state")
    playbook = load_playbook(playbook_path)
    executor = ReleaseExecutor(ledger)
    first_prepared = executor.start(git_repo, playbook)
    second_prepared = executor.start(git_repo, playbook)

    def resume_prepared(run):
        return executor.resume(
            run.run_id,
            execute_external=True,
            confirm_sha=run.source_sha,
            approve_candidate=run.candidate_digest,
            approval_actor="pytest",
            approval_reason="concurrency test",
        )

    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(resume_prepared, first_prepared)
        deadline = time.monotonic() + 2
        while not started.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert started.exists()

        with pytest.raises(RunBusyError, match="target .*production"):
            resume_prepared(second_prepared)

        assert first.result().status == "succeeded"


def test_resume_refuses_an_interrupted_external_step(git_repo, tmp_path):
    ledger = Ledger(tmp_path / "state")
    playbook = load_playbook(make_playbook(tmp_path))
    run = ledger.create_run(snapshot_repository(git_repo), playbook)
    ledger.begin_step(run.run_id, 0)
    ledger.finish_step(
        run.run_id,
        0,
        status="succeeded",
        exit_code=0,
        output_sha256="verified",
        output_preview="",
    )
    ledger.begin_step(run.run_id, 1)
    manifest_path = ledger.runs_dir / f"{run.run_id}.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["steps"][1]["status"] == "running"

    with pytest.raises(UncertainOutcomeError, match="outcome is unknown"):
        ReleaseExecutor(ledger).resume(
            run.run_id,
            execute_external=True,
            confirm_sha=run.source_sha,
        )

    recovered = ledger.get_run(run.run_id)
    assert recovered.status == "uncertain"
    assert recovered.steps[1].status == "uncertain"


def test_external_timeout_terminates_the_entire_process_group(git_repo, tmp_path):
    marker = tmp_path / "orphan-marker"
    child = write_python_script(
        tmp_path / "child.py",
        "from pathlib import Path; import time; "
        f"time.sleep(1.5); Path({str(marker)!r}).write_text('orphan')",
    )
    parent = write_python_script(
        tmp_path / "parent.py",
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, {str(child)!r}]); time.sleep(10)",
    )
    path = tmp_path / "timeout.toml"
    path.write_text(
        f'''schema_version = 1
name = "timeout"
target = "production"

[[steps]]
id = "publish"
name = "Publish"
effect = "external"
command = ["python3", {json.dumps(str(parent))}]
timeout_seconds = 1
''',
        encoding="utf-8",
    )
    executor = ReleaseExecutor(Ledger(tmp_path / "state"))
    prepared = executor.start(git_repo, load_playbook(path))
    run = approve(executor, prepared)
    assert run.status == "uncertain"

    time.sleep(0.75)
    assert not marker.exists()


def test_external_failure_is_uncertain_and_never_auto_retried(git_repo, tmp_path):
    path = tmp_path / "uncertain.toml"
    path.write_text(
        '''schema_version = 1
name = "uncertain"
target = "production"
allow_dirty = false

[[steps]]
id = "publish"
name = "Publish"
effect = "external"
command = ["python3", "-c", "raise SystemExit(7)"]
''',
        encoding="utf-8",
    )
    ledger = Ledger(tmp_path / "state")
    executor = ReleaseExecutor(ledger)

    prepared = executor.start(git_repo, load_playbook(path))
    result = approve(executor, prepared)

    assert result.status == "uncertain"
    assert result.steps[0].status == "uncertain"
    with pytest.raises(UncertainOutcomeError, match="outcome is unknown"):
        executor.resume(
            result.run_id,
            execute_external=True,
            confirm_sha=result.source_sha,
            approve_candidate=result.candidate_digest,
            approval_actor="pytest",
            approval_reason="verify no retry",
        )


def test_dirty_source_fingerprint_detects_changes_between_steps(git_repo, tmp_path):
    (git_repo / "README.md").write_text("initial dirty\n", encoding="utf-8")
    marker = tmp_path / "should-not-run-dirty"
    path = tmp_path / "dirty-drift.toml"
    mutate = write_python_script(
        tmp_path / "mutate_dirty.py",
        "from pathlib import Path; Path('README.md').write_text('changed again')",
    )
    later = write_python_script(
        tmp_path / "later_dirty.py",
        f"from pathlib import Path; Path({str(marker)!r}).write_text('ran')",
    )
    path.write_text(
        f'''schema_version = 1
name = "dirty-drift"
target = "local"
allow_dirty = true

[[steps]]
id = "mutate"
name = "Mutate dirty source"
effect = "build"
command = ["python3", {json.dumps(str(mutate))}]

[[steps]]
id = "later"
name = "Later"
effect = "verify"
command = ["python3", {json.dumps(str(later))}]
''',
        encoding="utf-8",
    )

    with pytest.raises(ProvenanceDriftError, match="Source provenance drift"):
        ReleaseExecutor(Ledger(tmp_path / "state")).start(git_repo, load_playbook(path))

    assert not marker.exists()


def test_resume_allows_unchanged_explicitly_dirty_source(git_repo, tmp_path):
    (git_repo / "README.md").write_text("intentional dirty\n", encoding="utf-8")
    marker = tmp_path / "allow-dirty-success"
    probe = write_python_script(
        tmp_path / "dirty_probe.py",
        "from pathlib import Path; import sys; "
        f"sys.exit(0 if Path({str(marker)!r}).exists() else 7)",
    )
    playbook_path = tmp_path / "dirty-retry.toml"
    playbook_path.write_text(
        f'''schema_version = 1
name = "dirty-retry"
target = "local"
allow_dirty = true

[[steps]]
id = "flaky"
name = "Flaky"
effect = "verify"
command = ["python3", {json.dumps(str(probe))}]
''',
        encoding="utf-8",
    )
    executor = ReleaseExecutor(Ledger(tmp_path / "state"))
    first = executor.start(git_repo, load_playbook(playbook_path))
    assert first.status == "failed"

    marker.touch()
    resumed = executor.resume(first.run_id)

    assert resumed.status == "succeeded"


def test_source_drift_blocks_later_local_steps(git_repo, tmp_path):
    marker = tmp_path / "should-not-run"
    mutate = write_python_script(
        tmp_path / "mutate_clean.py",
        "from pathlib import Path; Path('README.md').write_text('changed')",
    )
    later = write_python_script(
        tmp_path / "later_clean.py",
        f"from pathlib import Path; Path({str(marker)!r}).write_text('ran')",
    )
    path = tmp_path / "local-drift.toml"
    path.write_text(
        f'''schema_version = 1
name = "local-drift"
target = "local"
allow_dirty = false

[[steps]]
id = "mutate"
name = "Mutate source"
effect = "build"
command = ["python3", {json.dumps(str(mutate))}]

[[steps]]
id = "later"
name = "Later"
effect = "verify"
command = ["python3", {json.dumps(str(later))}]
''',
        encoding="utf-8",
    )

    with pytest.raises(ProvenanceDriftError, match="Source provenance drift"):
        ReleaseExecutor(Ledger(tmp_path / "state")).start(git_repo, load_playbook(path))

    assert not marker.exists()


def test_external_boundary_rechecks_source_after_local_steps(git_repo, tmp_path):
    playbook_path = tmp_path / "drift.toml"
    mutate = write_python_script(
        tmp_path / "mutate_before_external.py",
        "from pathlib import Path; Path('README.md').write_text('mutated')",
    )
    playbook_path.write_text(
        f'''schema_version = 1
name = "drift-test"
target = "test"

[[steps]]
id = "mutate"
name = "Mutate source"
effect = "build"
command = ["python3", {json.dumps(str(mutate))}]

[[steps]]
id = "external"
name = "External"
effect = "external"
command = ["python3", "-c", "from pathlib import Path; Path('released.txt').write_text('released')"]
''',
        encoding="utf-8",
    )
    ledger = Ledger(tmp_path / "state")
    executor = ReleaseExecutor(ledger)
    source_sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=git_repo, text=True
    ).strip()

    with pytest.raises(ProvenanceDriftError, match="before step external"):
        executor.start(
            git_repo,
            load_playbook(playbook_path),
            execute_external=True,
            confirm_sha=source_sha,
        )

    assert not (git_repo / "released.txt").exists()


def test_failed_step_stops_following_steps_and_can_retry(git_repo, tmp_path):
    marker = tmp_path / "allow-success"
    probe = (
        "from pathlib import Path; import sys; "
        f"sys.exit(0 if Path({str(marker)!r}).exists() else 7)"
    )
    probe_script = write_python_script(tmp_path / "probe.py", probe)
    playbook_path = tmp_path / "retry.toml"
    playbook_path.write_text(
        f'''schema_version = 1
name = "retry-test"
target = "test"

[[steps]]
id = "flaky"
name = "Flaky"
effect = "verify"
command = ["python3", {json.dumps(str(probe_script))}]

[[steps]]
id = "after"
name = "After"
effect = "verify"
command = ["git", "status", "--short"]
''',
        encoding="utf-8",
    )
    ledger = Ledger(tmp_path / "state")
    executor = ReleaseExecutor(ledger)

    first = executor.start(git_repo, load_playbook(playbook_path))
    assert first.status == "failed"
    assert [step.status for step in ledger.get_run(first.run_id).steps] == ["failed", "pending"]

    marker.touch()
    retried = executor.resume(first.run_id)
    assert retried.status == "succeeded"
    assert [step.status for step in ledger.get_run(first.run_id).steps] == [
        "succeeded",
        "succeeded",
    ]
    manifest = json.loads(
        (tmp_path / "state" / "runs" / f"{first.run_id}.json").read_text()
    )
    assert [
        attempt["status"] for attempt in manifest["steps"][0]["attempt_history"]
    ] == ["failed", "succeeded"]
    assert all(
        attempt["output_sha256"] for attempt in manifest["steps"][0]["attempt_history"]
    )


def test_untrusted_path_cannot_substitute_a_classified_executable(
    git_repo, tmp_path, monkeypatch
):
    malicious_bin = tmp_path / "malicious-bin"
    malicious_bin.mkdir()
    marker = tmp_path / "substituted"
    fake_git = malicious_bin / "git"
    fake_git.write_text(
        f"#!/bin/sh\nprintf substituted > {marker}\n",
        encoding="utf-8",
    )
    fake_git.chmod(0o755)
    monkeypatch.setenv("PATH", f"{malicious_bin}{os.pathsep}{os.environ['PATH']}")
    playbook_path = tmp_path / "trusted-executable.toml"
    playbook_path.write_text(
        '''schema_version = 1
name = "trusted-executable"
target = "local"

[[steps]]
id = "verify"
name = "Verify"
effect = "verify"
command = ["git", "status", "--short"]
''',
        encoding="utf-8",
    )

    run = ReleaseExecutor(Ledger(tmp_path / "state")).start(
        git_repo, load_playbook(playbook_path)
    )

    assert run.status == "succeeded"
    assert not marker.exists()


def test_launch_error_finishes_attempt_instead_of_leaving_running(
    git_repo, tmp_path, monkeypatch
):
    playbook_path = tmp_path / "missing.toml"
    playbook_path.write_text(
        '''schema_version = 1
name = "launch-error"
target = "local"

[[steps]]
id = "verify"
name = "Verify"
effect = "verify"
command = ["git", "status", "--short"]
''',
        encoding="utf-8",
    )
    ledger = Ledger(tmp_path / "state")

    def fail_launch(*_args, **_kwargs):
        raise OSError("executable disappeared before launch")

    monkeypatch.setattr("shipyard.executor._run_process", fail_launch)
    result = ReleaseExecutor(ledger).start(git_repo, load_playbook(playbook_path))

    assert result.status == "failed"
    assert result.steps[0].status == "failed"
    assert result.steps[0].exit_code == 127
    manifest = json.loads(
        (ledger.runs_dir / f"{result.run_id}.json").read_text(encoding="utf-8")
    )
    assert manifest["steps"][0]["attempt_history"][-1]["status"] == "failed"


def test_artifact_change_invalidates_prepared_candidate(git_repo, tmp_path):
    (git_repo / ".gitignore").write_text("release.bin\n", encoding="utf-8")
    subprocess.run(["git", "add", ".gitignore"], cwd=git_repo, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", "ignore release artifact"],
        cwd=git_repo,
        check=True,
    )
    artifact = git_repo / "release.bin"
    artifact.write_bytes(b"approved bytes")
    playbook_path = tmp_path / "artifact.toml"
    playbook_path.write_text(
        '''schema_version = 1
name = "artifact"
target = "production"
provider = "github"
destination = "owner/repo:refs/heads/main"

[[artifacts]]
path = "release.bin"

[[steps]]
id = "push"
name = "Push"
effect = "external"
command = ["git", "push", "origin", "{sha}:refs/heads/main"]
''',
        encoding="utf-8",
    )
    ledger = Ledger(tmp_path / "state")
    executor = ReleaseExecutor(ledger)
    prepared = executor.start(git_repo, load_playbook(playbook_path))
    assert prepared.candidate_digest

    artifact.write_bytes(b"different bytes")

    with pytest.raises(ProvenanceDriftError, match="candidate changed"):
        approve(executor, prepared)
    assert ledger.get_approval(prepared.run_id) is None


def test_candidate_approval_is_persisted_with_actor_and_reason(git_repo, tmp_path):
    ledger = Ledger(tmp_path / "state")
    executor = ReleaseExecutor(ledger)
    prepared = executor.start(git_repo, load_playbook(make_playbook(tmp_path)))

    completed = approve(executor, prepared)

    assert completed.status == "succeeded"
    approval = ledger.get_approval(completed.run_id)
    assert approval is not None
    assert approval["actor"] == "pytest"
    assert approval["candidate_digest"] == prepared.candidate_digest
    manifest = json.loads(
        (ledger.runs_dir / f"{completed.run_id}.json").read_text(encoding="utf-8")
    )
    assert manifest["candidate"]["approval"]["reason"]


def test_output_capture_is_bounded_without_deadlocking(git_repo, tmp_path):
    script = write_python_script(
        tmp_path / "large_output.py",
        "import sys; sys.stdout.write('x' * (2 * 1024 * 1024))",
    )
    playbook_path = tmp_path / "large-output.toml"
    playbook_path.write_text(
        f'''schema_version = 1
name = "large-output"
target = "local"

[[steps]]
id = "output"
name = "Output"
effect = "verify"
command = ["python3", {json.dumps(str(script))}]
''',
        encoding="utf-8",
    )

    result = ReleaseExecutor(Ledger(tmp_path / "state")).start(
        git_repo, load_playbook(playbook_path)
    )

    assert result.status == "succeeded"
    assert result.steps[0].output_preview.startswith("[output truncated")
    assert len(result.steps[0].output_preview) < 4100
    assert result.steps[0].output_sha256


def test_interrupted_external_attempt_is_quarantined(git_repo, tmp_path, monkeypatch):
    ledger = Ledger(tmp_path / "state")
    executor = ReleaseExecutor(ledger)
    prepared = executor.start(git_repo, load_playbook(make_playbook(tmp_path)))

    def interrupt(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("shipyard.executor._run_process", interrupt)
    with pytest.raises(KeyboardInterrupt):
        approve(executor, prepared)

    quarantined = ledger.get_run(prepared.run_id)
    assert quarantined.status == "uncertain"
    assert quarantined.steps[-1].status == "uncertain"
    with pytest.raises(UncertainOutcomeError, match="outcome is unknown"):
        approve(executor, quarantined)


def test_legacy_raw_external_execution_is_disabled_by_default(
    git_repo, tmp_path, monkeypatch
):
    monkeypatch.delenv("SHIPYARD_ENABLE_LEGACY_EXTERNAL")
    executor = ReleaseExecutor(Ledger(tmp_path / "state"))

    with pytest.raises(AuthorizationError, match="legacy raw external"):
        executor.start(git_repo, load_playbook(make_playbook(tmp_path)))


def test_status_recovery_quarantines_stale_attempt_without_retry(git_repo, tmp_path):
    ledger = Ledger(tmp_path / "state")
    playbook_path = tmp_path / "stale.toml"
    playbook_path.write_text(
        '''schema_version = 1
name = "stale"
target = "local"

[[steps]]
id = "verify"
name = "Verify"
effect = "verify"
command = ["git", "status", "--short"]
''',
        encoding="utf-8",
    )
    run = ledger.create_run(
        snapshot_repository(git_repo), load_playbook(playbook_path)
    )
    ledger.begin_step(run.run_id, 0)

    recovered = ReleaseExecutor(ledger).recover_stale(run.run_id)

    assert recovered.status == "failed"
    assert recovered.steps[0].status == "failed"
    assert recovered.steps[0].attempts == 1
    assert "no retry" in recovered.steps[0].output_preview
    assert "attempt.recovered_stale" in {
        event["event_type"] for event in ledger.list_audit_events(run.run_id)
    }


def test_sigterm_terminates_active_process_group(git_repo, tmp_path):
    marker = tmp_path / "child.pid"
    script = tmp_path / "sleeper.py"
    script.write_text(
        "import os, pathlib, time\n"
        f"pathlib.Path({str(marker)!r}).write_text(str(os.getpid()))\n"
        "time.sleep(30)\n",
        encoding="utf-8",
    )

    def send_signal() -> None:
        deadline = time.monotonic() + 5
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        os.kill(os.getpid(), signal.SIGTERM)

    sender = threading.Thread(target=send_signal)
    sender.start()
    with pytest.raises(ProcessInterrupted, match="signal"):
        _run_process(("python3", str(script)), git_repo, 30)
    sender.join(timeout=5)

    child_pid = int(marker.read_text(encoding="utf-8"))
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)
