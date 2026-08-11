from __future__ import annotations

import hashlib
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
from contextlib import suppress
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

from .candidate import ReleaseCandidate, canonical_remote
from .models import ReleaseRun
from .runtime import resolve_executable, sanitized_environment
from .safe_files import (
    SafeFileError,
    copy_private_regular,
    open_or_create_relative_parent,
    open_relative_regular,
)


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


def _approved_remote_urls(
    run: ReleaseRun, candidate: ReleaseCandidate
) -> dict[str, str]:
    expected: dict[str, str] = {}
    source = candidate.payload.get("source")
    if run.source.remote_url:
        repository = source.get("repository") if isinstance(source, dict) else None
        if not isinstance(repository, str) or not repository:
            raise ExecutionSnapshotError("candidate source remote evidence is malformed")
        expected["origin"] = repository

    playbook = candidate.payload.get("playbook")
    actions = playbook.get("actions") if isinstance(playbook, dict) else None
    if not isinstance(actions, list):
        raise ExecutionSnapshotError("candidate action evidence is malformed")
    by_id = {
        item.get("id"): item
        for item in actions
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    if len(by_id) != len(actions):
        raise ExecutionSnapshotError("candidate action evidence is malformed")
    for step in run.steps:
        remote_key = {
            "git.ref": "remote",
            "xcodecloud.build": "source_remote",
        }.get(step.action or "")
        if remote_key is None:
            continue
        remote = step.config.get(remote_key)
        item = by_id.get(step.id)
        resolved = item.get("resolved") if isinstance(item, dict) else None
        approved = resolved.get("remote_url") if isinstance(resolved, dict) else None
        if not isinstance(remote, str) or not isinstance(approved, str) or not approved:
            raise ExecutionSnapshotError("candidate action remote evidence is malformed")
        prior = expected.setdefault(remote, approved)
        if prior != approved:
            raise ExecutionSnapshotError("candidate remote evidence is inconsistent")
    return expected


def _remote_urls(run: ReleaseRun, candidate: ReleaseCandidate) -> dict[str, str]:
    expected = _approved_remote_urls(run, candidate)
    result: dict[str, str] = {}
    for name in sorted(_required_remotes(run)):
        output = _git(run.repo_path, "remote", "get-url", "--all", name, timeout=10)
        urls = [line for line in output.splitlines() if line]
        if len(urls) != 1:
            raise ExecutionSnapshotError(
                "execution snapshot requires exactly one URL for each named Git remote"
            )
        if canonical_remote(urls[0]) != expected.get(name):
            raise ExecutionSnapshotError(
                "Git remote changed after candidate approval"
            )
        result[name] = urls[0]
    return result


def _buzz_remote_names(run: ReleaseRun) -> set[str]:
    if run.provider != "buzz-git":
        return set()
    return {
        str(step.config["remote"])
        for step in run.steps
        if step.action == "git.ref" and isinstance(step.config.get("remote"), str)
    }


def _optional_git_config(repo: Path, key: str) -> tuple[str, ...]:
    git = resolve_executable("git", repo)
    completed = subprocess.run(  # noqa: S603
        (str(git), "config", "--get-all", key),
        cwd=repo,
        env=sanitized_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=15,
        check=False,
    )
    if completed.returncode not in {0, 1}:
        raise ExecutionSnapshotError("cannot inspect repository credential configuration")
    return tuple(line.strip() for line in completed.stdout.splitlines() if line.strip())


def _copy_buzz_auth_config(source: Path, snapshot: Path, remote_url: str) -> None:
    parsed = urlsplit(remote_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ExecutionSnapshotError("Buzz snapshot remote must be credential-free HTTPS")
    scope = parsed.netloc
    helper_key = f"credential.https://{scope}.helper"
    path_key = f"credential.https://{scope}.useHttpPath"
    helpers = _optional_git_config(source, helper_key)
    use_path = _optional_git_config(source, path_key)
    if helpers != ("nostr",) or use_path != ("true",):
        raise ExecutionSnapshotError(
            "Buzz snapshot requires host-scoped nostr helper and useHttpPath=true"
        )
    _git(snapshot, "config", "--local", "--add", "credential.helper", "")
    _git(snapshot, "config", "--local", "--add", helper_key, "")
    _git(snapshot, "config", "--local", "--add", helper_key, "nostr")
    _git(snapshot, "config", "--local", path_key, "true")

    keyfiles = _optional_git_config(source, "nostr.keyfile")
    if keyfiles:
        if len(keyfiles) != 1:
            raise ExecutionSnapshotError("Buzz snapshot requires one Nostr keyfile reference")
        keyfile = Path(keyfiles[0]).expanduser()
        if not keyfile.is_absolute():
            raise ExecutionSnapshotError("Buzz Nostr keyfile must be absolute")
        credential_directory = snapshot / ".git" / "shipyard-credentials"
        try:
            credential_directory.mkdir(mode=0o700)
            private_copy = credential_directory / "nostr.key"
            copy_private_regular(keyfile, private_copy)
        except (OSError, SafeFileError) as exc:
            raise ExecutionSnapshotError("Buzz Nostr keyfile is unsafe") from exc
        _git(snapshot, "config", "--local", "nostr.keyfile", str(private_copy))
    elif not os.environ.get("NOSTR_PRIVATE_KEY"):
        raise ExecutionSnapshotError("Buzz Nostr private key source is unavailable")


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
    try:
        descriptor = open_relative_regular(source_root, relative)
    except SafeFileError as exc:
        raise ExecutionSnapshotError("candidate artifact escapes execution snapshot") from exc
    parent_descriptor: int | None = None
    target_descriptor: int | None = None
    temporary_name: str | None = None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != expected_size:
            raise ExecutionSnapshotError("candidate artifact changed before snapshot")
        try:
            parent_descriptor, destination_name = open_or_create_relative_parent(
                snapshot_root, relative
            )
        except SafeFileError as exc:
            raise ExecutionSnapshotError("candidate artifact destination path is unsafe") from exc
        for _attempt in range(16):
            temporary_name = f".shipyard-artifact-{secrets.token_hex(12)}"
            try:
                target_descriptor = os.open(
                    temporary_name,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=parent_descriptor,
                )
                break
            except FileExistsError:
                continue
        if target_descriptor is None:
            raise ExecutionSnapshotError("cannot allocate candidate artifact temporary file")
        target_file = os.fdopen(target_descriptor, "wb")
        target_descriptor = None
        with target_file as target:
            digest = hashlib.sha256()
            size = 0
            while chunk := os.read(descriptor, 1024 * 1024):
                target.write(chunk)
                digest.update(chunk)
                size += len(chunk)
            target.flush()
            os.fsync(target.fileno())
            os.fchmod(target.fileno(), 0o400)
        if size != expected_size or digest.hexdigest() != expected_digest:
            raise ExecutionSnapshotError("candidate artifact changed before snapshot")
        if temporary_name is None:
            raise ExecutionSnapshotError("candidate artifact temporary identity is unavailable")
        os.replace(
            temporary_name,
            destination_name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        temporary_name = None
    finally:
        os.close(descriptor)
        if target_descriptor is not None:
            os.close(target_descriptor)
        if temporary_name is not None and parent_descriptor is not None:
            with suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=parent_descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def prepare_execution_snapshot(
    state_dir: Path,
    run: ReleaseRun,
    candidate: ReleaseCandidate,
) -> ReleaseRun:
    snapshots = state_dir / "snapshots"
    snapshots.mkdir(mode=0o700, exist_ok=True)
    os.chmod(snapshots, 0o700)
    final = snapshots / run.run_id
    if os.path.lexists(final):
        _validate_frozen_snapshot(final, run.source.sha)
        return replace(run, repo_path=final.resolve())

    remotes = _remote_urls(run, candidate)
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
        buzz_remotes = _buzz_remote_names(run)
        for name, url in sorted(remotes.items()):
            _git(repository, "remote", "add", name, url)
            if name in buzz_remotes:
                _copy_buzz_auth_config(run.repo_path, repository, url)
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


def _validate_frozen_snapshot(snapshot: Path, source_sha: str) -> None:
    if snapshot.is_symlink() or not snapshot.is_dir():
        raise ExecutionSnapshotError("execution snapshot path is unsafe")
    metadata = snapshot.stat()
    if (
        (hasattr(os, "geteuid") and metadata.st_uid != os.geteuid())
        or stat.S_IMODE(metadata.st_mode) & 0o222
    ):
        raise ExecutionSnapshotError("pre-existing execution snapshot is not frozen")
    for path in snapshot.rglob("*"):
        item = path.lstat()
        if hasattr(os, "geteuid") and item.st_uid != os.geteuid():
            raise ExecutionSnapshotError("execution snapshot has an unexpected owner")
        if stat.S_ISLNK(item.st_mode):
            raise ExecutionSnapshotError("execution snapshot contains a symlink")
        if stat.S_IMODE(item.st_mode) & 0o222:
            raise ExecutionSnapshotError("pre-existing execution snapshot is not frozen")
    if _git(snapshot, "rev-parse", "HEAD") != source_sha:
        raise ExecutionSnapshotError("execution snapshot source SHA changed")


def execution_snapshot_run(state_dir: Path, run: ReleaseRun) -> ReleaseRun:
    snapshot = state_dir / "snapshots" / run.run_id
    if not os.path.lexists(snapshot):
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
    _validate_frozen_snapshot(resolved, run.source.sha)
    return replace(run, repo_path=resolved)


def cleanup_execution_snapshot(state_dir: Path, run_id: str) -> None:
    snapshots = state_dir / "snapshots"
    snapshot = snapshots / run_id
    if not os.path.lexists(snapshot):
        return
    if snapshot.is_symlink() or not snapshot.is_dir():
        raise ExecutionSnapshotError("execution snapshot path is unsafe")
    resolved_snapshots = snapshots.resolve()
    resolved = snapshot.resolve()
    try:
        resolved.relative_to(resolved_snapshots)
    except ValueError as exc:
        raise ExecutionSnapshotError("execution snapshot path is unsafe") from exc
    paths = [resolved, *resolved.rglob("*")]
    for path in paths:
        metadata = path.lstat()
        if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
            raise ExecutionSnapshotError("execution snapshot has an unexpected owner")
    for path in paths:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            continue
        os.chmod(path, 0o700 if stat.S_ISDIR(metadata.st_mode) else 0o600)
    shutil.rmtree(resolved)


def freeze_execution_snapshot(snapshot: Path) -> None:
    if snapshot.is_symlink() or not snapshot.is_dir():
        raise ExecutionSnapshotError("execution snapshot path is unsafe")
    for path in sorted(snapshot.rglob("*"), key=lambda value: len(value.parts), reverse=True):
        if path.is_symlink():
            raise ExecutionSnapshotError("execution snapshot contains a symlink")
        if path.is_file():
            os.chmod(path, 0o400)
        elif path.is_dir():
            os.chmod(path, 0o500)
    os.chmod(snapshot, 0o500)
