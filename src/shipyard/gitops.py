from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

from .models import RepositorySnapshot
from .runtime import resolve_executable, sanitized_environment


class GitError(RuntimeError):
    pass


def _git(repo: Path, *args: str, required: bool = True) -> str | None:
    git = resolve_executable("git", repo)
    result = subprocess.run(
        [git, *args],
        cwd=repo,
        env=sanitized_environment(),
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode == 0:
        return result.stdout.rstrip("\r\n")
    if required:
        detail = result.stderr.strip() or "git command failed"
        raise GitError(detail)
    return None


def _git_bytes(repo: Path, *args: str) -> bytes:
    git = resolve_executable("git", repo)
    result = subprocess.run(
        [git, *args],
        cwd=repo,
        env=sanitized_environment(),
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip() or "git command failed"
        raise GitError(detail)
    return result.stdout


def _worktree_digest(repo: Path) -> str:
    digest = hashlib.sha256()
    digest.update(_git_bytes(repo, "diff", "--binary", "HEAD", "--"))
    untracked = _git_bytes(repo, "ls-files", "--others", "--exclude-standard", "-z")
    for raw_path in sorted(path for path in untracked.split(b"\0") if path):
        digest.update(b"\0path\0")
        digest.update(raw_path)
        file_path = repo / os.fsdecode(raw_path)
        if file_path.is_symlink():
            digest.update(b"\0symlink\0")
            digest.update(os.fsencode(os.readlink(file_path)))
            continue
        digest.update(b"\0file\0")
        with file_path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    return digest.hexdigest()


def snapshot_repository(path: str | Path) -> RepositorySnapshot:
    repo = Path(path).expanduser().resolve()
    if not repo.is_dir():
        raise GitError(f"repository path does not exist: {repo}")
    top = _git(repo, "rev-parse", "--show-toplevel")
    if top is None:
        raise GitError("git did not return a repository root")
    root = Path(top).resolve()
    sha = _git(root, "rev-parse", "HEAD")
    if sha is None:
        raise GitError("git did not return a source SHA")
    branch = _git(root, "symbolic-ref", "--short", "-q", "HEAD", required=False)
    status = _git(root, "status", "--porcelain=v1", "--untracked-files=all") or ""
    changed_paths = tuple(
        sorted(line[3:] for line in status.splitlines() if len(line) >= 4)
    )
    worktree_digest = _worktree_digest(root) if changed_paths else None
    remote_url = _git(root, "remote", "get-url", "origin", required=False)
    upstream_sha = _git(root, "rev-parse", "@{upstream}", required=False)
    return RepositorySnapshot(
        path=root,
        sha=sha,
        branch=branch,
        dirty=bool(changed_paths),
        changed_paths=changed_paths,
        remote_url=remote_url,
        upstream_sha=upstream_sha,
        worktree_digest=worktree_digest,
    )


def named_remote_url(path: str | Path, remote: str) -> str:
    if not remote or not all(
        character.isalnum() or character in "._-" for character in remote
    ):
        raise GitError("Git remote name is invalid")
    repo = Path(path).expanduser().resolve()
    output = _git(repo, "remote", "get-url", "--all", remote)
    urls = output.splitlines() if isinstance(output, str) else []
    if len(urls) != 1 or not urls[0]:
        raise GitError("Git remote must resolve to exactly one URL")
    return urls[0]
