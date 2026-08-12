from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from .identity import runtime_identity
from .models import ReleaseRun
from .runtime import RuntimeIdentityError, resolve_executable, sanitized_environment
from .safe_files import SafeFileError, open_relative_regular, relative_parts

POLICY_VERSION = "shipyard-safety-v1"
_NAMED_GIT_REMOTE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")


class CandidateError(RuntimeError):
    pass


@dataclass(frozen=True)
class ReleaseCandidate:
    digest: str
    payload: dict[str, object]


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _hash_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def canonical_remote(value: str | None) -> str | None:
    if not value:
        return None
    scp = re.fullmatch(r"(?:[^@]+@)?([^:]+):(.+)", value)
    if scp and "://" not in value:
        host, path = scp.groups()
        return f"ssh://{host.lower()}/{path.removesuffix('.git')}"
    parsed = urlsplit(value)
    if parsed.scheme:
        host = parsed.hostname.lower() if parsed.hostname else ""
        port = f":{parsed.port}" if parsed.port else ""
        return urlunsplit(
            (parsed.scheme.lower(), f"{host}{port}", parsed.path.removesuffix(".git"), "", "")
        )
    return value.removesuffix(".git")


def canonical_repository_identity(value: str | None) -> str | None:
    """Normalize HTTPS/SSH clone URLs to a scheme-independent host/path identity."""
    canonical = canonical_remote(value)
    if canonical is None:
        return None
    parsed = urlsplit(canonical)
    if not parsed.scheme or not parsed.hostname or parsed.username or parsed.password:
        return None
    if parsed.query or parsed.fragment:
        return None
    port = parsed.port
    if port in {22, 443}:
        port = None
    authority = parsed.hostname.lower() + (f":{port}" if port else "")
    path = parsed.path.strip("/").removesuffix(".git")
    if not path or any(part in {"", ".", ".."} for part in path.split("/")):
        return None
    return f"{authority}/{path}"


def _artifact_evidence(run: ReleaseRun) -> list[dict[str, object]]:
    root = run.repo_path.resolve()
    evidence: list[dict[str, object]] = []
    for specification in run.artifacts:
        try:
            relative_parts(specification.path)
        except SafeFileError as exc:
            raise CandidateError(
                f"artifact escapes repository: {specification.path}"
            ) from exc
        try:
            descriptor = open_relative_regular(root, specification.path)
        except SafeFileError as exc:
            candidate_path = root / specification.path
            if not os.path.lexists(candidate_path):
                if specification.required:
                    raise CandidateError(
                        f"required artifact is missing: {specification.path}"
                    ) from exc
                continue
            raise CandidateError(
                f"artifact is missing or unsafe: {specification.path}"
            ) from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise CandidateError(
                    f"artifact must be a regular non-symlink file: {specification.path}"
                )
            evidence.append(
                {
                    "path": specification.path,
                    "size": metadata.st_size,
                    "sha256": _hash_descriptor(descriptor),
                }
            )
        finally:
            os.close(descriptor)
    return evidence


def _executable_evidence(run: ReleaseRun) -> list[dict[str, object]]:
    evidence: list[dict[str, object]] = []
    seen: set[str] = set()
    for step in run.steps:
        executable_name = {
            "git.ref": "git",
            "buzz.workflow": "buzz",
        }.get(step.action or "")
        if step.action and executable_name is None:
            continue
        if executable_name is None and not step.command:
            continue
        try:
            executable = resolve_executable(
                executable_name or step.command[0], run.repo_path
            )
        except (FileNotFoundError, RuntimeIdentityError) as exc:
            raise CandidateError(str(exc)) from exc
        key = str(executable)
        if key in seen:
            continue
        seen.add(key)
        metadata = executable.stat()
        evidence.append(
            {
                "path": key,
                "size": metadata.st_size,
                "mode": metadata.st_mode & 0o777,
                "sha256": _hash_file(executable),
            }
        )
    return evidence


def _action_evidence(
    run: ReleaseRun, action: str | None, config: dict[str, object]
) -> dict[str, object]:
    remote_key = {
        "git.ref": "remote",
        "xcodecloud.build": "source_remote",
    }.get(action or "")
    if remote_key is None:
        return {}
    remote = config.get(remote_key, "origin")
    if not isinstance(remote, str):
        raise CandidateError(f"{action} remote must be a string")
    if (
        not _NAMED_GIT_REMOTE.fullmatch(remote)
        or ".." in remote
        or remote.endswith("/")
    ):
        raise CandidateError(f"{action} must use a named Git remote")
    try:
        git = resolve_executable("git", run.repo_path)
        completed = subprocess.run(  # noqa: S603
            (str(git), "remote", "get-url", remote),
            cwd=run.repo_path,
            env=sanitized_environment(),
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CandidateError(f"cannot resolve git remote {remote!r}") from exc
    return {"remote_url": canonical_remote(completed.stdout.strip())}


def build_candidate(run: ReleaseRun) -> ReleaseCandidate:
    """Build the immutable approval object immediately before external mutation."""
    payload: dict[str, object] = {
        "schema_version": 1,
        "policy_version": POLICY_VERSION,
        "source": {
            "sha": run.source.sha,
            "repository": canonical_remote(run.source.remote_url),
            "dirty": run.source.dirty,
            "worktree_sha256": run.source.worktree_digest,
        },
        "playbook": {
            "schema_version": run.playbook_schema,
            "name": run.playbook_name,
            "sha256": run.playbook_digest,
            "actions": [
                {
                    "id": step.id,
                    "effect": step.effect,
                    "command": list(step.command),
                    "action": step.action,
                    "config": step.config,
                    "resolved": _action_evidence(run, step.action, step.config),
                    "timeout_seconds": step.timeout_seconds,
                }
                for step in run.steps
            ],
        },
        "destination": {
            "provider": run.provider,
            "identity": run.destination,
        },
        "approval": {"quorum": run.approval_quorum},
        "artifacts": _artifact_evidence(run),
        "executables": _executable_evidence(run),
        "runtime": {**runtime_identity(), "policy_version": POLICY_VERSION},
    }
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return ReleaseCandidate(digest=hashlib.sha256(canonical).hexdigest(), payload=payload)
