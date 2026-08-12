from __future__ import annotations

import json
from collections.abc import Mapping

from .apple_auth import APPLE_AUTH_OPTION_KEYS, validate_apple_credential_references
from .candidate import canonical_repository_identity
from .observations import ReleaseObservation
from .release_project import ReleaseProject


class ReleasePhaseError(ValueError):
    pass


def render_xcode_build_playbook(
    project: ReleaseProject,
    *,
    source_sha: str,
    repo_path: str,
    source_remote: str,
    source_observation: ReleaseObservation,
    target: str = "production",
) -> str:
    if project.apple is None:
        raise ReleasePhaseError("release project does not configure Apple")
    if len(source_sha) != 40 or any(
        character not in "0123456789abcdef" for character in source_sha
    ):
        raise ReleasePhaseError("Xcode build source SHA must be full lowercase hex")
    if (
        source_observation.provider != "apple"
        or source_observation.project_digest != project.digest
        or source_observation.source_sha != source_sha
    ):
        raise ReleasePhaseError("Apple source observation identity does not match release")
    evidence: Mapping[str, object] = source_observation.evidence
    state = evidence.get("state")
    if state != "absent":
        raise ReleasePhaseError(
            "Xcode build playbook requires an Apple observation with no exact-SHA run"
        )
    workflow_id = evidence.get("workflow_id")
    reference_id = evidence.get("git_reference_id")
    reference_name = evidence.get("git_reference_name")
    repository_identity = evidence.get("repository_identity")
    expected_reference = f"refs/tags/shipyard-candidate-{source_sha}"
    if (
        workflow_id != project.apple.workflow_id
        or not isinstance(reference_id, str)
        or not reference_id
        or reference_name != expected_reference
        or repository_identity
        != canonical_repository_identity(project.apple.source_remote)
    ):
        raise ReleasePhaseError("Apple source observation does not match the release project")
    credentials = {
        key: project.apple.credential_config[key]
        for key in APPLE_AUTH_OPTION_KEYS
        if key in project.apple.credential_config
    }
    validate_apple_credential_references(credentials)
    config: dict[str, object] = {
        "workflow_id": workflow_id,
        "git_reference_id": reference_id,
        "git_reference_name": reference_name,
        "source_remote": source_remote,
        "repo_path": repo_path,
        "clean": True,
        "source_observation_digest": source_observation.digest,
        **credentials,
    }
    lines = [
        "# Generated from a read-only exact-SHA Apple source observation.",
        "# This playbook starts one Xcode Cloud run only after Shipyard approval.",
        "schema_version = 2",
        f"name = {json.dumps(project.name + '-xcode-build-' + source_sha[:12])}",
        f"target = {json.dumps(target)}",
        'provider = "apple"',
        f"destination = {json.dumps(str(workflow_id) + ':' + reference_id)}",
        "approval_quorum = 1",
        "",
        "[[steps]]",
        'id = "xcode-build"',
        'name = "Start exact candidate Xcode Cloud build"',
        'effect = "external"',
        'action = "xcodecloud.build"',
        "",
        "[steps.config]",
    ]
    for key, value in sorted(config.items()):
        lines.append(f"{key} = {json.dumps(value)}")
    return "\n".join(lines) + "\n"


def _playbook(
    *,
    name: str,
    provider: str,
    destination: str,
    step_id: str,
    step_name: str,
    config: dict[str, object],
    target: str,
) -> str:
    lines = [
        "# Generated from a stable Shipyard release project.",
        "# Every phase remains an independently approved exact-SHA mutation.",
        "schema_version = 2",
        f"name = {json.dumps(name)}",
        f"target = {json.dumps(target)}",
        f"provider = {json.dumps(provider)}",
        f"destination = {json.dumps(destination)}",
        "approval_quorum = 1",
        "",
        "[[steps]]",
        f"id = {json.dumps(step_id)}",
        f"name = {json.dumps(step_name)}",
        'effect = "external"',
        'action = "git.ref"',
        "",
        "[steps.config]",
    ]
    for key, value in sorted(config.items()):
        lines.append(f"{key} = {json.dumps(value)}")
    return "\n".join(lines) + "\n"


def render_release_phase(
    project: ReleaseProject,
    *,
    source_sha: str,
    phase: str,
    repo_path: str,
    target: str = "production",
) -> str:
    if project.git is None:
        raise ReleasePhaseError("release project does not configure Git remotes")
    if len(source_sha) != 40 or any(
        character not in "0123456789abcdef" for character in source_sha
    ):
        raise ReleasePhaseError("release phase source SHA must be full lowercase hex")
    candidate_ref = f"refs/tags/shipyard-candidate-{source_sha}"
    if phase == "github-candidate":
        provider = "github"
        remote = project.git.github_remote
        ref = candidate_ref
        tag_kind = "annotated"
        step_name = "Publish immutable annotated candidate tag to GitHub"
    elif phase == "buzz-candidate":
        if project.git.buzz_remote is None:
            raise ReleasePhaseError("release project does not configure a Buzz remote")
        provider = "buzz-git"
        remote = project.git.buzz_remote
        ref = candidate_ref
        tag_kind = "lightweight"
        step_name = "Mirror exact candidate tag to Buzz"
    elif phase == "buzz-main":
        if project.git.buzz_remote is None:
            raise ReleasePhaseError("release project does not configure a Buzz remote")
        provider = "buzz-git"
        remote = project.git.buzz_remote
        ref = project.git.main_ref
        tag_kind = "lightweight"
        step_name = "Promote Buzz main to exact approved candidate"
    elif phase == "github-main":
        provider = "github"
        remote = project.git.github_remote
        ref = project.git.main_ref
        tag_kind = "lightweight"
        step_name = "Mirror approved Buzz main to GitHub"
    else:
        raise ReleasePhaseError(f"unsupported release phase: {phase}")
    config: dict[str, object] = {
        "remote": remote,
        "ref": ref,
        "repo_path": repo_path,
    }
    if tag_kind == "annotated":
        config["tag_kind"] = "annotated"
    destination = f"{provider}:{remote}:{ref}"
    return _playbook(
        name=f"{project.name}-{phase}-{source_sha[:12]}",
        provider=provider,
        destination=destination,
        step_id=phase,
        step_name=step_name,
        config=config,
        target=target,
    )
