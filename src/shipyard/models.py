from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

Effect = Literal["verify", "build", "external"]
StepStatus = Literal[
    "pending", "running", "succeeded", "failed", "blocked", "uncertain"
]
RunStatus = Literal[
    "running", "succeeded", "failed", "awaiting_authorization", "uncertain"
]


@dataclass(frozen=True)
class RepositorySnapshot:
    path: Path
    sha: str
    branch: str | None
    dirty: bool
    changed_paths: tuple[str, ...]
    remote_url: str | None
    upstream_sha: str | None
    worktree_digest: str | None


@dataclass(frozen=True)
class Step:
    id: str
    name: str
    effect: Effect
    command: tuple[str, ...]
    timeout_seconds: int = 900
    action: str | None = None
    config: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ArtifactSpec:
    path: str
    required: bool = True


@dataclass(frozen=True)
class Playbook:
    path: Path
    name: str
    target: str
    allow_dirty: bool
    digest: str
    steps: tuple[Step, ...]
    provider: str = "raw"
    destination: str = ""
    artifacts: tuple[ArtifactSpec, ...] = ()
    schema_version: int = 1


@dataclass(frozen=True)
class StepRun:
    ordinal: int
    id: str
    name: str
    effect: Effect
    command: tuple[str, ...]
    timeout_seconds: int
    status: StepStatus
    attempts: int
    exit_code: int | None
    output_sha256: str | None
    output_preview: str
    action: str | None = None
    config: dict[str, object] = field(default_factory=dict)
    operation_id: str | None = None
    provider_status: str | None = None
    readback: dict[str, object] | None = None


@dataclass(frozen=True)
class ReleaseRun:
    run_id: str
    repo_path: Path
    playbook_path: Path
    playbook_name: str
    playbook_digest: str
    target: str
    allow_dirty: bool
    source: RepositorySnapshot
    status: RunStatus
    steps: tuple[StepRun, ...]
    created_at: str
    updated_at: str
    provider: str = "raw"
    destination: str = ""
    artifacts: tuple[ArtifactSpec, ...] = ()
    candidate_digest: str | None = None
    candidate_payload: dict[str, object] | None = None
    manifest_revision: int = 0
    playbook_schema: int = 1

    @property
    def source_sha(self) -> str:
        return self.source.sha
