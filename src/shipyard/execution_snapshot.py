from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import replace
from pathlib import Path

from .candidate import ReleaseCandidate
from .models import ReleaseRun
from .runtime import resolve_executable, sanitized_environment


class ExecutionSnapshotError(RuntimeError):
    pass


_REMOTE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _git(repo: Path, *args: str, timeout: int = 30) -> str:
    git = resolve_executable("git", repo)
    try:
        completed = subprocess.run(  # noqa: S603
            (str(git), *args),
            cwd=repo,
            env=sanitized_environment(),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ExecutionSnapshotError("execution snapshot Git operation failed") from exc
    if completed.returncode != 0:
        raise ExecutionSnapshotError("execution snapshot Git operation failed")
    return completed.stdout.rstrip("\r\n")


def _required_remotes(run: ReleaseRun) -> set[str]:
    names: set[str] = {"origin"} if run.source.remote_url else set()
    for step in run.steps:
        key = {
            "git.ref": "remote",
            "xcodecloud.build": "source_remote",
        }.get(step.action or "")
        if key is None:
            continue
        value = step.config.get(key)
        if (
            not isinstance(value, str)
            or _REMOTE_NAME.fullmatch(value) is None
            or ".." in value
            or value.endswith("/")
        ):
            raise ExecutionSnapshotError("execution snapshot requires a named Git remote")
        names.add(value)
    return names


def _remote_urls(run: ReleaseRun) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in sorted(_required_remotes(run)):
        output = _git(run.repo_path, "remote", "get-url", "--all", name, timeout=10)
        urls = [line for line in output.splitlines() if line]
        if len(urls) != 1:
            raise ExecutionSnapshotError(
                "execution snapshot requires exactly one URL for each named Git remote"
            )
        result[name] = urls[0]
    return result


def _copy_approved_artifact(
    source_root: Path,
    snapshot_root: Path,
    evidence: dict[str, object],
) -> None:
    relative = evidence.get("path")
    expected_size = evidence.get("size")
    expected_digest = evidence.get("sha256")
    if (
        not isinstance(relative, str)
        or not relative
        or Path(relative).is_absolute()
        or not isinstance(expected_size, int)
        or isinstance(expected_size, bool)
        or expected_size < 0
        or not isinstance(expected_digest, str)
        or _SHA256.fullmatch(expected_digest) is None
    ):
        raise ExecutionSnapshotError("candidate artifact evidence is malformed")
    source = source_root / relative
    destination = snapshot_root / relative
    try:
        source.resolve(strict=False).relative_to(source_root)
        destination.resolve(strict=False).relative_to(snapshot_root)
    except ValueError as exc:
        raise ExecutionSnapshotError("candidate artifact escapes execution snapshot") from exc

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise ExecutionSnapshotError("candidate artifact cannot be snapshotted safely") from exc
    temporary_path: Path | None = None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != expected_size:
            raise ExecutionSnapshotError("candidate artifact changed before snapshot")
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            destination.parent.resolve(strict=True).relative_to(snapshot_root)
        except ValueError as exc:
            raise ExecutionSnapshotError(
                "candidate artifact parent escapes execution snapshot"
            ) from exc
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=destination.parent, prefix=".shipyard-artifact-", delete=False
        ) as target:
            temporary_path = Path(target.name)
            digest = hashlib.sha256()
            size = 0
            while chunk := os.read(descriptor, 1024 * 1024):
                target.write(chunk)
                digest.update(chunk)
                size += len(chunk)
            target.flush()
            os.fsync(target.fileno())
        if size != expected_size or digest.hexdigest() != expected_digest:
            raise ExecutionSnapshotError("candidate artifact changed before snapshot")
        os.chmod(temporary_path, 0o400)
        os.replace(temporary_path, destination)
        temporary_path = None
    finally:
        os.close(descriptor)
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def prepare_execution_snapshot(
    state_dir: Path,
    run: ReleaseRun,
    candidate: ReleaseCandidate,
) -> ReleaseRun:
    snapshots = state_dir / "snapshots"
    snapshots.mkdir(mode=0o700, exist_ok=True)
    os.chmod(snapshots, 0o700)
    final = snapshots / run.run_id
    if final.exists():
        if final.is_symlink() or not final.is_dir():
            raise ExecutionSnapshotError("execution snapshot path is unsafe")
        return replace(run, repo_path=final.resolve())

    remotes = _remote_urls(run)
    temporary = Path(tempfile.mkdtemp(prefix=f".{run.run_id}-", dir=snapshots))
    repository = temporary / "repository"
    try:
        _git(
            run.repo_path,
            "clone",
            "--local",
            "--no-hardlinks",
            "--no-checkout",
            "--",
            str(run.repo_path),
            str(repository),
            timeout=60,
        )
        for existing in [line for line in _git(repository, "remote").splitlines() if line]:
            _git(repository, "remote", "remove", existing)
        for name, url in sorted(remotes.items()):
            _git(repository, "remote", "add", name, url)
        _git(repository, "checkout", "--detach", "--force", run.source.sha)

        artifacts = candidate.payload.get("artifacts")
        if not isinstance(artifacts, list):
            raise ExecutionSnapshotError("candidate artifact evidence is malformed")
        source_root = run.repo_path.resolve()
        for item in artifacts:
            if not isinstance(item, dict):
                raise ExecutionSnapshotError("candidate artifact evidence is malformed")
            _copy_approved_artifact(source_root, repository, item)

        os.replace(repository, final)
        return replace(run, repo_path=final.resolve())
    except BaseException:
        if final.exists():
            shutil.rmtree(final, ignore_errors=True)
        raise
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


def execution_snapshot_run(state_dir: Path, run: ReleaseRun) -> ReleaseRun:
    snapshot = state_dir / "snapshots" / run.run_id
    if not snapshot.exists():
        return run
    if snapshot.is_symlink() or not snapshot.is_dir():
        raise ExecutionSnapshotError("execution snapshot path is unsafe")
    resolved = snapshot.resolve()
    try:
        resolved.relative_to((state_dir / "snapshots").resolve())
    except ValueError as exc:
        raise ExecutionSnapshotError("execution snapshot path is unsafe") from exc
    metadata = resolved.stat()
    if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
        raise ExecutionSnapshotError("execution snapshot has an unexpected owner")
    return replace(run, repo_path=resolved)


def freeze_execution_snapshot(snapshot: Path) -> None:
    if snapshot.is_symlink() or not snapshot.is_dir():
        raise ExecutionSnapshotError("execution snapshot path is unsafe")
    for path in sorted(snapshot.rglob("*"), key=lambda value: len(value.parts), reverse=True):
        if path.is_symlink():
            continue
        if path.is_file():
            os.chmod(path, 0o400)
        elif path.is_dir():
            os.chmod(path, 0o500)
    os.chmod(snapshot, 0o500)
