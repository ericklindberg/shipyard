from __future__ import annotations

import hashlib
import os
import re
import stat
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from .adapters.base import AdapterError
from .apple_auth import APPLE_AUTH_OPTION_KEYS, validate_apple_credential_references
from .candidate import canonical_repository_identity
from .safe_files import SafeFileError, open_relative_regular

_SCHEMA = 1
_SOURCE_SHA = re.compile(r"^[0-9a-f]{40}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
_REPOSITORY_PART = re.compile(r"^[A-Za-z0-9_.-]+$")
_BUNDLE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{2,254}$")
_GATE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_MAX_BYTES = 1024 * 1024
_RELEASE_SCOPES = frozenset({"internal", "external", "production"})


class ReleaseProjectError(ValueError):
    pass


def _require_string(mapping: Mapping[str, object], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ReleaseProjectError(f"release project {key} must be a non-empty string")
    normalized = value.strip()
    if any(character in normalized for character in ("\x00", "\r", "\n")):
        raise ReleaseProjectError(f"release project {key} must be one line")
    return normalized


def _optional_string(mapping: Mapping[str, object], key: str) -> str | None:
    value = mapping.get(key)
    if value is None:
        return None
    return _require_string(mapping, key)


@dataclass(frozen=True)
class ReleaseGate:
    name: str
    required_for: tuple[str, ...]

    def payload(self) -> dict[str, object]:
        return {"name": self.name, "required_for": list(self.required_for)}


@dataclass(frozen=True)
class GitHubReleaseProject:
    owner: str
    repo: str
    repository_id: str
    required_workflow_ids: tuple[str, ...]
    token_env: str

    def config(self) -> dict[str, object]:
        return {
            "owner": self.owner,
            "repo": self.repo,
            "repository_id": self.repository_id,
            "required_workflow_ids": ",".join(self.required_workflow_ids),
            "token_env": self.token_env,
        }


@dataclass(frozen=True)
class AppleReleaseProject:
    workflow_id: str
    source_remote: str
    source_git_remote: str
    bundle_id: str
    beta_group_name: str
    expected_marketing_version: str | None
    credential_config: Mapping[str, object]

    def config(self, *, expected_build_number: str | None = None) -> dict[str, object]:
        result: dict[str, object] = {
            "workflow_id": self.workflow_id,
            "source_remote": self.source_remote,
            "source_git_remote": self.source_git_remote,
            "bundle_id": self.bundle_id,
            "beta_group_name": self.beta_group_name,
            **self.credential_config,
        }
        if self.expected_marketing_version is not None:
            result["expected_marketing_version"] = self.expected_marketing_version
        if expected_build_number is not None:
            result["expected_build_number"] = expected_build_number
        return result


@dataclass(frozen=True)
class GitReleaseProject:
    github_remote: str
    buzz_remote: str | None
    main_ref: str

    def payload(self) -> dict[str, object]:
        return {
            "github_remote": self.github_remote,
            "buzz_remote": self.buzz_remote,
            "main_ref": self.main_ref,
        }


@dataclass(frozen=True)
class ReleaseProject:
    path: Path
    name: str
    source_remote: str
    git: GitReleaseProject | None
    github: GitHubReleaseProject | None
    apple: AppleReleaseProject | None
    gates: tuple[ReleaseGate, ...]
    digest: str

    def gate_names(self) -> tuple[str, ...]:
        return tuple(gate.name for gate in self.gates)

    def required_gate_names(self, release_scope: str) -> tuple[str, ...]:
        if release_scope not in _RELEASE_SCOPES:
            raise ReleaseProjectError(
                "release scope must be internal, external, or production"
            )
        return tuple(
            sorted(
                gate.name
                for gate in self.gates
                if release_scope in gate.required_for
            )
        )

    def public_payload(self) -> dict[str, object]:
        return {
            "schema_version": "shipyard.release-project/v1",
            "name": self.name,
            "source_remote": self.source_remote,
            "git": self.git.payload() if self.git is not None else None,
            "github": (
                {
                    "owner": self.github.owner,
                    "repo": self.github.repo,
                    "repository_id": self.github.repository_id,
                    "required_workflow_ids": list(self.github.required_workflow_ids),
                    "token_env": self.github.token_env,
                }
                if self.github is not None
                else None
            ),
            "apple": (
                {
                    "workflow_id": self.apple.workflow_id,
                    "source_remote": self.apple.source_remote,
                    "source_git_remote": self.apple.source_git_remote,
                    "bundle_id": self.apple.bundle_id,
                    "beta_group_name": self.apple.beta_group_name,
                    "expected_marketing_version": self.apple.expected_marketing_version,
                    "credential_env": sorted(
                        str(value) for value in self.apple.credential_config.values()
                    ),
                }
                if self.apple is not None
                else None
            ),
            "gates": [gate.payload() for gate in self.gates],
            "digest": self.digest,
        }


def _read_document(path: str | Path) -> tuple[Path, bytes, dict[str, object]]:
    candidate = Path(path).expanduser()
    absolute = candidate if candidate.is_absolute() else Path.cwd() / candidate
    absolute = Path(os.path.abspath(absolute))
    try:
        relative = absolute.relative_to(Path("/")).as_posix()
        descriptor = open_relative_regular(Path("/"), relative)
    except (SafeFileError, ValueError) as exc:
        raise ReleaseProjectError(f"release project not found: {candidate}") from exc
    try:
        file_metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(file_metadata.st_mode)
        if mode & 0o022:
            raise ReleaseProjectError("release project must not be group/world writable")
        raw = bytearray()
        while chunk := __import__("os").read(descriptor, min(65536, _MAX_BYTES + 1 - len(raw))):
            raw.extend(chunk)
            if len(raw) > _MAX_BYTES:
                raise ReleaseProjectError("release project exceeds the 1 MiB safety limit")
    finally:
        __import__("os").close(descriptor)
    try:
        parsed = tomllib.loads(bytes(raw).decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ReleaseProjectError("release project is not valid TOML") from exc
    if not isinstance(parsed, dict):
        raise ReleaseProjectError("release project root must be a table")
    return absolute, bytes(raw), parsed


def _github(value: object) -> GitHubReleaseProject | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ReleaseProjectError("release project github must be a table")
    allowed = {"owner", "repo", "repository_id", "required_workflow_ids", "token_env"}
    unsupported = set(value) - allowed
    if unsupported:
        raise ReleaseProjectError(f"unsupported github option: {sorted(unsupported)[0]}")
    owner = _require_string(value, "owner")
    repo = _require_string(value, "repo")
    repository_id = _require_string(value, "repository_id")
    token_env = _require_string(value, "token_env")
    raw_workflows = value.get("required_workflow_ids")
    if not isinstance(raw_workflows, list) or not raw_workflows:
        raise ReleaseProjectError("required_workflow_ids must be a non-empty array")
    workflows = tuple(str(item) for item in raw_workflows)
    if (
        not _REPOSITORY_PART.fullmatch(owner)
        or not _REPOSITORY_PART.fullmatch(repo)
        or not repository_id.isdecimal()
        or any(not item.isdecimal() for item in workflows)
        or len(set(workflows)) != len(workflows)
        or not re.fullmatch(r"GITHUB_[A-Z0-9_]+", token_env)
    ):
        raise ReleaseProjectError("GitHub release coordinates are invalid")
    return GitHubReleaseProject(owner, repo, repository_id, workflows, token_env)


def _git(value: object) -> GitReleaseProject | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ReleaseProjectError("release project git must be a table")
    allowed = {"github_remote", "buzz_remote", "main_ref"}
    unsupported = set(value) - allowed
    if unsupported:
        raise ReleaseProjectError(f"unsupported git option: {sorted(unsupported)[0]}")
    github_remote = _require_string(value, "github_remote")
    buzz_remote = _optional_string(value, "buzz_remote")
    main_ref = _require_string(value, "main_ref")
    remote_pattern = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    if (
        remote_pattern.fullmatch(github_remote) is None
        or (buzz_remote is not None and remote_pattern.fullmatch(buzz_remote) is None)
        or not re.fullmatch(r"refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", main_ref)
        or ".." in main_ref
    ):
        raise ReleaseProjectError("Git release coordinates are invalid")
    return GitReleaseProject(github_remote, buzz_remote, main_ref)


def _apple(value: object) -> AppleReleaseProject | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ReleaseProjectError("release project apple must be a table")
    allowed = {
        "workflow_id",
        "source_remote",
        "source_git_remote",
        "bundle_id",
        "beta_group_name",
        "expected_marketing_version",
        *APPLE_AUTH_OPTION_KEYS,
    }
    unsupported = set(value) - allowed
    if unsupported:
        raise ReleaseProjectError(f"unsupported apple option: {sorted(unsupported)[0]}")
    workflow_id = _require_string(value, "workflow_id")
    source_remote = _require_string(value, "source_remote")
    source_git_remote = _require_string(value, "source_git_remote")
    bundle_id = _require_string(value, "bundle_id")
    group_name = _require_string(value, "beta_group_name")
    version = _optional_string(value, "expected_marketing_version")
    if (
        _IDENTIFIER.fullmatch(workflow_id) is None
        or len(source_remote) > 1024
        or canonical_repository_identity(source_remote) is None
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", source_git_remote)
        is None
        or _BUNDLE.fullmatch(bundle_id) is None
        or "." not in bundle_id
        or len(group_name) > 255
        or (version is not None and _IDENTIFIER.fullmatch(version) is None)
    ):
        raise ReleaseProjectError("Apple release coordinates are invalid")
    credentials = {key: value[key] for key in APPLE_AUTH_OPTION_KEYS if key in value}
    try:
        validate_apple_credential_references(credentials)
    except AdapterError as exc:
        raise ReleaseProjectError(str(exc)) from exc
    return AppleReleaseProject(
        workflow_id,
        source_remote,
        source_git_remote,
        bundle_id,
        group_name,
        version,
        MappingProxyType(dict(credentials)),
    )


def _gates(value: object) -> tuple[ReleaseGate, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ReleaseProjectError("release project gates must be an array of tables")
    gates: list[ReleaseGate] = []
    seen: set[str] = set()
    for raw in value:
        if not isinstance(raw, dict) or set(raw) != {"name", "required_for"}:
            raise ReleaseProjectError("each release gate requires only name and required_for")
        name = _require_string(raw, "name")
        required_for = raw.get("required_for")
        if (
            _GATE_NAME.fullmatch(name) is None
            or name in seen
            or not isinstance(required_for, list)
            or not required_for
            or any(item not in _RELEASE_SCOPES for item in required_for)
        ):
            raise ReleaseProjectError("release gate definition is invalid")
        seen.add(name)
        gates.append(ReleaseGate(name, tuple(dict.fromkeys(str(item) for item in required_for))))
    return tuple(gates)


def load_release_project(path: str | Path) -> ReleaseProject:
    resolved, raw, data = _read_document(path)
    allowed = {
        "schema_version",
        "name",
        "source_remote",
        "git",
        "github",
        "apple",
        "gates",
    }
    unsupported = set(data) - allowed
    if unsupported:
        raise ReleaseProjectError(f"unsupported release project option: {sorted(unsupported)[0]}")
    if data.get("schema_version") != _SCHEMA:
        raise ReleaseProjectError("unsupported release project schema_version")
    name = _require_string(data, "name")
    source_remote = _require_string(data, "source_remote")
    if len(name) > 128 or len(source_remote) > 1024:
        raise ReleaseProjectError("release project identity is too long")
    git = _git(data.get("git"))
    github = _github(data.get("github"))
    apple = _apple(data.get("apple"))
    if github is None and apple is None:
        raise ReleaseProjectError("release project must configure at least one provider")
    gates = _gates(data.get("gates"))
    if apple is not None:
        physical = next((gate for gate in gates if gate.name == "physical-device"), None)
        if physical is None or not {"external", "production"}.issubset(
            physical.required_for
        ):
            raise ReleaseProjectError(
                "Apple release project requires physical-device for external and production"
            )
    return ReleaseProject(
        path=resolved,
        name=name,
        source_remote=source_remote,
        git=git,
        github=github,
        apple=apple,
        gates=gates,
        digest=hashlib.sha256(raw).hexdigest(),
    )


def validate_source_sha(value: str) -> str:
    normalized = value.strip().lower()
    if _SOURCE_SHA.fullmatch(normalized) is None:
        raise ReleaseProjectError("source SHA must be a full 40-character lowercase hex identity")
    return normalized


def render_project_template() -> str:
    return '''schema_version = 1
name = "example-ios-release"
source_remote = "https://github.com/example/example.git"

[git]
github_remote = "origin"
buzz_remote = "buzz"
main_ref = "refs/heads/main"

[github]
owner = "example"
repo = "example"
repository_id = "123456789"
required_workflow_ids = ["111111", "222222"]
token_env = "GITHUB_ACTIONS_TOKEN"

[apple]
workflow_id = "change-me"
source_remote = "https://github.com/example/example.git"
source_git_remote = "origin"
bundle_id = "com.example.app"
beta_group_name = "Testing"
expected_marketing_version = "1.0"
issuer_id_env = "APPLE_ISSUER_ID"
key_id_env = "APPLE_KEY_ID"
private_key_path_env = "APPLE_PRIVATE_KEY_PATH"

[[gates]]
name = "physical-device"
required_for = ["external", "production"]
'''
