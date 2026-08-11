from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from . import evidence
from .executor import ReleaseExecutor
from .ledger import Ledger
from .playbook import load_playbook
from .runtime import resolve_executable, sanitized_environment


class QuickstartError(RuntimeError):
    """The disposable local quickstart could not complete safely."""


@dataclass(frozen=True)
class QuickstartSummary:
    destination: Path
    run_id: str
    candidate_digest: str
    source_sha: str
    remote_sha: str
    remote_url: str
    evidence_path: Path
    evidence_verified: bool
    verdict: str
    status: str = "succeeded"


def _git(executable: Path, cwd: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            (str(executable), *args),
            cwd=cwd,
            env=sanitized_environment(),
            stdin=subprocess.DEVNULL,
            text=True,
            capture_output=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise QuickstartError(f"git command could not run: {exc}") from exc
    if result.returncode:
        raise QuickstartError(result.stderr.strip() or "git command failed")
    return result.stdout.strip()


def _remove_created(paths: list[Path]) -> None:
    for path in reversed(paths):
        if path.is_dir() and not path.is_symlink():
            for root, directories, files in os.walk(path, topdown=False, followlinks=False):
                for name in files:
                    candidate = Path(root) / name
                    if not candidate.is_symlink():
                        candidate.chmod(0o600)
                for name in directories:
                    candidate = Path(root) / name
                    if not candidate.is_symlink():
                        candidate.chmod(0o700)
                Path(root).chmod(0o700)
            shutil.rmtree(path)
        elif path.exists() or path.is_symlink():
            path.unlink()


def run_quickstart(destination: str | Path) -> QuickstartSummary:
    """Run a real governed release entirely inside an empty local directory."""
    destination = Path(destination).expanduser()
    if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
        raise QuickstartError("destination must be a directory")
    existed = destination.exists()
    if existed and any(destination.iterdir()):
        raise QuickstartError(
            "destination must be an empty directory; non-empty destinations are rejected"
        )
    if not existed:
        destination.mkdir(parents=True)

    source = destination / "source"
    remote = destination / "remote.git"
    state = destination / "state"
    playbook_path = destination / "quickstart.toml"
    evidence_path = destination / "evidence.tar"
    created = [source, remote, state, playbook_path, evidence_path]
    try:
        git = resolve_executable("git", destination)
        source.mkdir()
        _git(git, source, "init", "-q", "-b", "main")
        (source / "README.md").write_text(
            "Shipyard local quickstart\n", encoding="utf-8"
        )
        _git(git, source, "config", "user.name", "Shipyard Quickstart")
        _git(git, source, "config", "user.email", "quickstart@localhost")
        _git(git, source, "add", "README.md")
        _git(git, source, "commit", "-q", "-m", "quickstart")
        _git(git, destination, "init", "--bare", "-q", str(remote))
        _git(git, source, "remote", "add", "origin", str(remote))
        source_sha = _git(git, source, "rev-parse", "HEAD")

        playbook_path.write_text(
            f'''schema_version = 2
name = "local-quickstart"
target = "local-quickstart"
provider = "git"
destination = "git:origin:refs/heads/main"

[[artifacts]]
path = "README.md"
required = true

[[steps]]
id = "publish"
name = "Publish exact source"
effect = "external"
action = "git.ref"
timeout_seconds = 60

[steps.config]
remote = "origin"
ref = "refs/heads/main"
repo_path = {json.dumps(str(source))}
''',
            encoding="utf-8",
        )
        ledger = Ledger(state)
        executor = ReleaseExecutor(ledger)
        prepared = executor.start(source, load_playbook(playbook_path))
        if prepared.status != "awaiting_authorization" or not prepared.candidate_digest:
            raise QuickstartError("release did not traverse candidate authorization")
        final = executor.resume(
            prepared.run_id,
            confirm_sha=source_sha,
            approve_candidate=prepared.candidate_digest,
            approval_actor="shipyard-quickstart",
            approval_reason="credential-free local governed release demonstration",
            execute_external=True,
        )
        if final.status != "succeeded" or not final.candidate_digest:
            raise QuickstartError(f"governed release ended with status {final.status}")
        step = final.steps[0]
        observed = step.readback.get("observed_sha") if step.readback else None
        if not isinstance(observed, str) or observed != source_sha:
            raise QuickstartError("adapter readback did not match the approved source SHA")

        bundle = evidence.export_evidence_bundle(ledger, final.run_id, evidence_path)
        report = evidence.verify_evidence_bundle(bundle)
        if report.get("valid") is not True:
            raise QuickstartError("portable evidence verification failed")
        return QuickstartSummary(
            destination=destination.resolve(),
            run_id=final.run_id,
            candidate_digest=final.candidate_digest,
            source_sha=source_sha,
            remote_sha=observed,
            remote_url=remote.resolve().as_uri(),
            evidence_path=bundle.resolve(),
            evidence_verified=True,
            verdict=str(report.get("status", final.status)),
            status=final.status,
        )
    except Exception as exc:
        if existed:
            _remove_created(created)
        else:
            _remove_created([destination])
        if isinstance(exc, QuickstartError):
            raise
        raise QuickstartError(str(exc)) from exc
