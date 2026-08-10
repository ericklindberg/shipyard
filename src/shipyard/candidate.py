from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from .identity import runtime_identity
from .models import ReleaseRun
from .runtime import RuntimeIdentityError, resolve_executable, sanitized_environment

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


def _canonical_remote(value: str | None) -> str | None:
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



def _artifact_evidence(run: ReleaseRun) -> list[dict[str, object]]:
    root = run.repo_path.resolve()
    evidence: list[dict[str, object]] = []
    for specification in run.artifacts:
        candidate = root / specification.path
        lexical = candidate.resolve(strict=False)
        try:
            lexical.relative_to(root)
        except ValueError as exc:
            raise CandidateError(f"artifact escapes repository: {specification.path}") from exc
        try:
            path = candidate.resolve(strict=True)
        except FileNotFoundError as exc:
            if specification.required:
                raise CandidateError(
                    f"required artifact is missing: {specification.path}"
                ) from exc
            continue
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise CandidateError(f"artifact escapes repository: {specification.path}") from exc
        if candidate.is_symlink() or not path.is_file():
            raise CandidateError(
                f"artifact must be a regular non-symlink file: {specification.path}"
            )
        evidence.append(
            {
                "path": specification.path,
                "size": path.stat().st_size,
                "sha256": _hash_file(path),
            }
        )
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
    if action != "git.ref":
        return {}
    remote = config.get("remote", "origin")
    if not isinstance(remote, str):
        raise CandidateError("git.ref remote must be a string")
    if (
        not _NAMED_GIT_REMOTE.fullmatch(remote)
        or ".." in remote
        or remote.endswith("/")
    ):
        raise CandidateError("git.ref must use a named Git remote")
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
    return {"remote_url": _canonical_remote(completed.stdout.strip())}


def build_candidate(run: ReleaseRun) -> ReleaseCandidate:
    """Build the immutable approval object immediately before external mutation."""
    payload: dict[str, object] = {
        "schema_version": 1,
        "policy_version": POLICY_VERSION,
        "source": {
            "sha": run.source.sha,
            "repository": _canonical_remote(run.source.remote_url),
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
        "artifacts": _artifact_evidence(run),
        "executables": _executable_evidence(run),
        "runtime": {**runtime_identity(), "policy_version": POLICY_VERSION},
    }
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return ReleaseCandidate(digest=hashlib.sha256(canonical).hexdigest(), payload=payload)
