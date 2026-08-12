from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

_SHA = re.compile(r"^[0-9a-f]{40}$")


class CandidateTagError(RuntimeError):
    """Raised when a hosted candidate tag does not satisfy the exact-SHA contract."""


def _git(repository: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    if executable is None:
        raise CandidateTagError("git is required")
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    try:
        result = subprocess.run(
            [executable, *arguments],
            cwd=repository,
            env=environment,
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CandidateTagError("git candidate-tag query failed") from exc
    if result.returncode != 0:
        raise CandidateTagError("git candidate-tag query failed")
    return result.stdout.strip()


def verify_candidate_tag(
    repository: Path,
    expected_sha: str,
    github_ref: str,
    github_sha: str,
) -> dict[str, str]:
    if not _SHA.fullmatch(expected_sha):
        raise CandidateTagError("expected SHA must be 40 lowercase hexadecimal characters")
    expected_tag = f"shipyard-candidate-{expected_sha}"
    if github_ref != f"refs/tags/{expected_tag}":
        raise CandidateTagError("GitHub ref does not match the exact candidate tag")
    if github_sha != expected_sha:
        raise CandidateTagError("GitHub source SHA does not match the approved candidate")
    candidate_repository = repository.expanduser()
    if candidate_repository.is_symlink() or not candidate_repository.is_dir():
        raise CandidateTagError("repository must be a non-symlink directory")
    candidate_repository = candidate_repository.resolve(strict=True)
    top_level = Path(_git(candidate_repository, "rev-parse", "--show-toplevel")).resolve(
        strict=True
    )
    if top_level != candidate_repository:
        raise CandidateTagError("repository must be the Git worktree root")
    if _git(candidate_repository, "rev-parse", "HEAD") != expected_sha:
        raise CandidateTagError("checked-out source does not match the approved candidate")

    tag_ref = f"refs/tags/{expected_tag}"
    tag_object = _git(candidate_repository, "rev-parse", "--verify", f"{tag_ref}^{{object}}")
    if not _SHA.fullmatch(tag_object):
        raise CandidateTagError("candidate tag object identity is malformed")
    if _git(candidate_repository, "cat-file", "-t", tag_object) != "tag":
        raise CandidateTagError("candidate ref must resolve to an annotated tag object")

    headers: dict[str, str] = {}
    for line in _git(candidate_repository, "cat-file", "-p", tag_object).splitlines():
        if not line:
            break
        key, separator, value = line.partition(" ")
        if not separator or key in headers:
            raise CandidateTagError("annotated tag object header is malformed")
        headers[key] = value
    if headers.get("type") != "commit" or headers.get("object") != expected_sha:
        raise CandidateTagError("annotated tag must directly reference the expected commit")
    if headers.get("tag") != expected_tag:
        raise CandidateTagError("annotated tag object name does not match the candidate ref")
    if _git(candidate_repository, "rev-parse", f"{tag_ref}^{{commit}}") != expected_sha:
        raise CandidateTagError("peeled candidate tag does not match the approved commit")
    if _git(candidate_repository, "status", "--porcelain=v1", "--untracked-files=all"):
        raise CandidateTagError("candidate worktree must be clean")
    return {
        "candidate_sha": expected_sha,
        "candidate_tag": expected_tag,
        "candidate_tag_object": tag_object,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify an exact-SHA annotated Shipyard candidate tag"
    )
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--github-ref", required=True)
    parser.add_argument("--github-sha", required=True)
    args = parser.parse_args(argv)
    try:
        result = verify_candidate_tag(
            args.repository,
            args.expected_sha,
            args.github_ref,
            args.github_sha,
        )
    except CandidateTagError as exc:
        print(f"candidate tag verification failed: {exc}", file=sys.stderr)
        return 2
    for key, value in result.items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
