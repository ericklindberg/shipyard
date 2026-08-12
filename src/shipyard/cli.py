from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import stat
import sys
from contextlib import suppress
from pathlib import Path
from typing import Any, NoReturn

from .adapters.base import AdapterError
from .adapters.registry import AdapterRegistry
from .apple_release import (
    AppleReleaseCoordinates,
    render_testflight_playbook,
)
from .approvals import (
    ApprovalPacketError,
    build_approval_statement,
    build_candidate_review,
    canonical_packet_bytes,
    load_candidate_review,
    load_signed_approval,
    sign_approval_ssh,
    verify_signed_approval_ssh,
)
from .bootstrap import BootstrapBundle, BootstrapInputError, plan_github_bootstrap
from .candidate import CandidateError, canonical_repository_identity
from .connections import (
    ConnectionError,
    ConnectionStore,
    default_config_dir,
    render_playbook,
    verify_connection,
)
from .dossier import DossierError, export_release_dossier, verify_release_dossier
from .evidence import EvidenceError, export_evidence_bundle, verify_evidence_bundle
from .executor import (
    AuthorizationError,
    ProcessInterrupted,
    ProvenanceDriftError,
    ReleaseExecutor,
    UncertainOutcomeError,
)
from .gates import GateAttestation, GateError, GateStore
from .gitops import GitError, named_remote_url, snapshot_repository
from .identity import package_version, runtime_identity
from .ledger import Ledger, LedgerError
from .models import ReleaseRun, RepositorySnapshot
from .observations import ObservationError, ObservationStore, ReleaseObservation
from .playbook import PlaybookError, load_playbook
from .quickstart import QuickstartError, run_quickstart
from .release_inspection import inspect_release
from .release_phases import (
    ReleasePhaseError,
    render_release_phase,
    render_xcode_build_playbook,
)
from .release_project import (
    ReleaseProjectError,
    load_release_project,
    render_project_template,
    validate_source_sha,
)
from .reports import load_verified_report, render_html, render_markdown
from .runtime import RuntimeIdentityError
from .wait import WaitState, wait_for_reconciliation
from .web import create_server


def _default_state_dir() -> Path:
    configured = os.environ.get("SHIPYARD_STATE_DIR")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".local" / "state" / "shipyard"


def _snapshot_payload(snapshot: RepositorySnapshot) -> dict[str, Any]:
    return {
        "path": str(snapshot.path),
        "sha": snapshot.sha,
        "branch": snapshot.branch,
        "dirty": snapshot.dirty,
        "changed_paths": list(snapshot.changed_paths),
        "remote_url": snapshot.remote_url,
        "upstream_sha": snapshot.upstream_sha,
        "worktree_digest": snapshot.worktree_digest,
    }


def _run_payload(run: ReleaseRun, ledger: Ledger | None = None) -> dict[str, Any]:
    payload = {
        "run_id": run.run_id,
        "status": run.status,
        "source": _snapshot_payload(run.source),
        "playbook": run.playbook_name,
        "target": run.target,
        "provider": run.provider,
        "destination": run.destination,
        "candidate_digest": run.candidate_digest,
        "manifest_revision": run.manifest_revision,
        "steps": [
            {
                "id": step.id,
                "name": step.name,
                "effect": step.effect,
                "action": step.action,
                "status": step.status,
                "attempts": step.attempts,
                "exit_code": step.exit_code,
                "operation_id": step.operation_id,
                "provider_status": step.provider_status,
                "readback": step.readback,
                "output_sha256": step.output_sha256,
                "output_preview": step.output_preview,
            }
            for step in run.steps
        ],
        "created_at": run.created_at,
        "updated_at": run.updated_at,
    }
    if ledger is not None:
        payload["approval"] = ledger.get_approval(run.run_id)
        payload["audit_chain_valid"] = ledger.verify_audit_chain(run.run_id)
        payload["audit_events"] = ledger.list_audit_events(run.run_id)
    return payload


_JSON_API_VERSION = "shipyard.cli/v1"


def _payload_status(payload: Any) -> str:
    if isinstance(payload, dict):
        status = payload.get("status")
        if isinstance(status, str) and status:
            return status
        state = payload.get("state")
        if isinstance(state, str) and state:
            return state
        valid = payload.get("valid")
        if isinstance(valid, bool):
            return "verified" if valid else "invalid"
        ready = payload.get("ready")
        if isinstance(ready, bool):
            return "ready" if ready else "blocked"
        verified = payload.get("verified")
        if isinstance(verified, bool):
            return "verified" if verified else "invalid"
    return "succeeded"


def _json_envelope(payload: Any) -> dict[str, Any]:
    return {
        "api_version": _JSON_API_VERSION,
        "ok": True,
        "status": _payload_status(payload),
        "data": payload,
    }


def _print_error(
    message: str,
    *,
    as_json: bool,
    code: str = "INVALID_REQUEST",
    phase: str = "config",
    retryable: bool = False,
    mutation: str = "none",
) -> None:
    if as_json:
        print(
            json.dumps(
                {
                    "api_version": _JSON_API_VERSION,
                    "ok": False,
                    "status": "invalid",
                    "data": None,
                    "error": {
                        "code": code,
                        "message": message,
                        "retryable": retryable,
                        "mutation": mutation,
                        "phase": phase,
                    },
                },
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return
    print(f"shipyard: {message}", file=sys.stderr)


class CliArgumentError(ValueError):
    pass


class ShipyardArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise CliArgumentError(message)


def _print(payload: Any, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(_json_envelope(payload), indent=2, sort_keys=True))
        return
    if isinstance(payload, dict) and "run_id" in payload:
        print(f"Run: {payload['run_id']}")
        print(f"Status: {payload['status']}")
        print(f"Source: {payload['source']['sha']}")
        if payload.get("candidate_digest"):
            print(f"Candidate: {payload['candidate_digest']}")
        for step in payload["steps"]:
            action = step.get("action") or step["effect"]
            print(f"  {step['status']:>22}  {action:<18}  {step['id']}")
        return
    if isinstance(payload, dict):
        for key, value in payload.items():
            print(f"{key}: {value}")
        return
    print(payload)


def _write_private_text(path: str | Path, content: str, *, force: bool) -> Path:
    destination = Path(path).expanduser()
    if destination.name in {"", ".", ".."}:
        raise PlaybookError("output must name a file")
    try:
        parent = destination.parent.resolve(strict=True)
        expected_parent = parent.stat()
    except OSError as exc:
        raise PlaybookError(f"cannot open output directory: {destination.parent}") from exc

    directory_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    directory_fd = -1
    descriptor = -1
    temporary_name: str | None = None
    try:
        directory_fd = os.open(parent, directory_flags)
        opened_parent = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(opened_parent.st_mode)
            or opened_parent.st_dev != expected_parent.st_dev
            or opened_parent.st_ino != expected_parent.st_ino
        ):
            raise PlaybookError("output directory changed during access")
        try:
            existing = os.stat(destination.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and stat.S_ISLNK(existing.st_mode):
            raise PlaybookError(f"refusing symlink output: {destination}")
        if existing is not None and not force:
            raise PlaybookError(f"refusing to overwrite existing file: {destination}")

        temporary_name = f".shipyard-{secrets.token_hex(16)}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=directory_fd)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            descriptor = -1
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        if force:
            os.replace(
                temporary_name,
                destination.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
        else:
            os.link(
                temporary_name,
                destination.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            os.unlink(temporary_name, dir_fd=directory_fd)
        temporary_name = None
        os.fsync(directory_fd)
        current_parent = os.stat(parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(current_parent.st_mode)
            or current_parent.st_dev != opened_parent.st_dev
            or current_parent.st_ino != opened_parent.st_ino
        ):
            raise PlaybookError("output directory changed during access")
        return parent / destination.name
    except FileExistsError as exc:
        raise PlaybookError(f"refusing to overwrite existing file: {destination}") from exc
    except PlaybookError:
        raise
    except OSError as exc:
        raise PlaybookError(f"cannot write output file: {destination}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name is not None and directory_fd >= 0:
            with suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=directory_fd)
        if directory_fd >= 0:
            os.close(directory_fd)


def _write_bootstrap_bundle(bundle: BootstrapBundle, output_dir: str | Path) -> list[Path]:
    root = Path(output_dir).expanduser()
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        raise PlaybookError("bootstrap output must be a directory")
    existed = root.exists()
    if existed and any(root.iterdir()):
        raise PlaybookError("bootstrap output directory must be empty")
    created_files: list[Path] = []
    try:
        if not existed:
            root.mkdir(parents=True, mode=0o700)
        for relative, content in sorted(bundle.files.items()):
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            created_files.append(_write_private_text(destination, content, force=False))
        return created_files
    except Exception:
        if not existed:
            shutil.rmtree(root, ignore_errors=True)
        else:
            for path in reversed(created_files):
                path.unlink(missing_ok=True)
            for directory in sorted(
                (path for path in root.rglob("*") if path.is_dir()),
                key=lambda path: len(path.parts),
                reverse=True,
            ):
                with suppress(OSError):
                    directory.rmdir()
        raise


def _result_code(run: ReleaseRun) -> int:
    if run.status == "succeeded":
        return 0
    if run.status == "awaiting_authorization":
        return 3
    if run.status == "uncertain":
        return 4
    return 1


def _named_paths(values: list[str], option: str) -> tuple[tuple[str, str], ...]:
    parsed: list[tuple[str, str]] = []
    seen: set[str] = set()
    for value in values:
        name, separator, path = value.partition("=")
        if not separator or not name or not path or name in seen:
            raise DossierError(f"{option} must use unique NAME=PATH values")
        seen.add(name)
        parsed.append((name, path))
    return tuple(parsed)


def _release_source_sha(repo: str, configured: str | None) -> tuple[str, RepositorySnapshot]:
    snapshot = snapshot_repository(repo)
    if snapshot.dirty:
        raise GitError("release inspection requires a clean source worktree")
    source_sha = validate_source_sha(configured) if configured else snapshot.sha
    if source_sha != snapshot.sha:
        raise GitError("configured release source SHA does not match the inspected repository HEAD")
    return source_sha, snapshot


def _verify_release_project_source(project_remote: str, snapshot: RepositorySnapshot) -> None:
    configured = canonical_repository_identity(project_remote)
    observed = canonical_repository_identity(snapshot.remote_url)
    if configured is None or observed is None or configured != observed:
        raise GitError(
            "release project source_remote does not match the inspected Git repository"
        )


def _apple_coordinates_from_observation(
    observation: ReleaseObservation,
) -> AppleReleaseCoordinates:
    evidence = observation.evidence
    required = {
        "workflow_id": evidence.get("workflow_id"),
        "repository_id": evidence.get("repository_id"),
        "repository_identity": evidence.get("repository_identity"),
        "git_reference_id": evidence.get("git_reference_id"),
        "git_reference_name": evidence.get("git_reference_name"),
        "app_id": evidence.get("app_id"),
        "bundle_id": evidence.get("bundle_id"),
        "run_id": evidence.get("run_id"),
        "run_number": evidence.get("run_number"),
        "build_id": evidence.get("build_id"),
        "build_number": evidence.get("build_number"),
        "processing_state": evidence.get("processing_state"),
        "pre_release_version_id": evidence.get("pre_release_version_id"),
        "marketing_version": evidence.get("marketing_version"),
        "beta_group_id": evidence.get("beta_group_id"),
        "beta_group_name": evidence.get("beta_group_name"),
    }
    if observation.provider != "apple" or observation.status != "succeeded":
        raise ObservationError("TestFlight playbook requires a successful Apple observation")
    if any(not isinstance(value, str) or not value for value in required.values()):
        raise ObservationError("Apple observation lacks resolved release coordinates")
    expired = evidence.get("expired")
    internal = evidence.get("beta_group_internal")
    relationship = evidence.get("relationship_present")
    if not isinstance(expired, bool) or not isinstance(internal, bool) or not isinstance(
        relationship, bool
    ):
        raise ObservationError("Apple observation release state is malformed")
    return AppleReleaseCoordinates(
        source_sha=observation.source_sha,
        workflow_id=str(required["workflow_id"]),
        repository_id=str(required["repository_id"]),
        repository_identity=str(required["repository_identity"]),
        git_reference_id=str(required["git_reference_id"]),
        git_reference_name=str(required["git_reference_name"]),
        app_id=str(required["app_id"]),
        bundle_id=str(required["bundle_id"]),
        run_id=str(required["run_id"]),
        run_number=str(required["run_number"]),
        run_status=observation.status,
        build_id=str(required["build_id"]),
        build_number=str(required["build_number"]),
        processing_state=str(required["processing_state"]),
        expired=expired,
        pre_release_version_id=str(required["pre_release_version_id"]),
        marketing_version=str(required["marketing_version"]),
        beta_group_id=str(required["beta_group_id"]),
        beta_group_name=str(required["beta_group_name"]),
        beta_group_internal=internal,
        relationship_present=relationship,
        internal_build_state=(
            str(evidence["internal_build_state"])
            if isinstance(evidence.get("internal_build_state"), str)
            else None
        ),
        external_build_state=(
            str(evidence["external_build_state"])
            if isinstance(evidence.get("external_build_state"), str)
            else None
        ),
    )


def _connection_options(args: argparse.Namespace) -> dict[str, object]:
    provider = args.provider
    if provider in {"github", "buzz-git"}:
        return {
            "remote": args.remote or "origin",
            "ref": args.ref or "refs/heads/main",
        }
    if provider == "github-actions":
        return {
            "owner": args.owner,
            "repo": args.repo_name,
            "repository_id": args.repository_id,
            "workflow_id": args.workflow_id,
            "workflow_file": args.workflow_file,
            "ref": args.ref or "refs/tags/shipyard-candidate-{source_sha}",
            "token_env": args.token_env or "GITHUB_ACTIONS_TOKEN",
        }
    if provider == "buzz":
        return {"workflow_id": args.workflow_id}
    if provider == "render":
        return {
            "service_id": args.service_id,
            "token_env": args.token_env or "RENDER_API_KEY",
        }
    if provider == "heroku":
        return {
            "app": args.app,
            "token_env": args.token_env or "HEROKU_API_KEY",
            "source_blob_url_env": args.source_blob_url_env or "HEROKU_SOURCE_BLOB_URL",
        }
    options: dict[str, object] = {
        "project": args.project,
        "repo_id": args.repo_id,
        "token_env": args.token_env or "VERCEL_TOKEN",
    }
    if args.team_id:
        options["team_id"] = args.team_id
    return options


def _template(provider: str) -> str:
    headers = {
        "github": ("github", "owner/repository:refs/heads/main", "git.ref"),
        "github-actions": (
            "github-actions",
            "github-actions:repository-id:workflow-id:refs/tags/shipyard-candidate-{source_sha}",
            "github.workflow",
        ),
        "buzz": ("buzz", "repository:refs/heads/main", "git.ref"),
        "render": ("render", "owner/service/production", "render.deploy"),
        "heroku": ("heroku", "app/production", "heroku.build"),
        "vercel": ("vercel", "team/project/production", "vercel.deploy"),
    }
    selected, destination, action = headers[provider]
    configs = {
        "github": 'remote = "origin"\nref = "refs/heads/main"',
        "github-actions": (
            'owner = "change-me"\nrepo = "change-me"\nrepository_id = "1234"\n'
            'workflow_id = "5678"\nworkflow_file = "release.yml"\n'
            'ref = "refs/tags/shipyard-candidate-{source_sha}"\n'
            'token_env = "GITHUB_ACTIONS_TOKEN"'
        ),
        "buzz": 'remote = "buzz"\nref = "refs/heads/main"',
        "render": 'service_id = "srv-change-me"\ntoken_env = "RENDER_API_KEY"',
        "heroku": (
            'app = "change-me"\ntoken_env = "HEROKU_API_KEY"\n'
            'source_blob_url_env = "HEROKU_SOURCE_BLOB_URL"'
        ),
        "vercel": (
            'project = "change-me"\nrepo_id = "change-me"\n'
            'team_id = "change-me"\ntoken_env = "VERCEL_TOKEN"'
        ),
    }
    return f'''schema_version = 2
name = "{provider}-production"
target = "production"
provider = "{selected}"
destination = "{destination}"

[[steps]]
id = "deploy"
name = "Deploy exact candidate"
effect = "external"
action = "{action}"

[steps.config]
{configs[provider]}
'''


def _doctor(repo: str, state_dir: str, playbook_path: str | None) -> tuple[dict[str, object], int]:
    checks: list[dict[str, object]] = []
    identity = runtime_identity()
    checks.append({"name": "runtime_identity", "status": "ok", "detail": identity})
    ledger = Ledger(state_dir)
    mode = ledger.state_dir.stat().st_mode & 0o777
    checks.append(
        {
            "name": "state_permissions",
            "status": "ok" if mode == 0o700 else "error",
            "detail": oct(mode),
        }
    )
    try:
        source = snapshot_repository(repo)
        checks.append(
            {
                "name": "git_source",
                "status": "ok" if not source.dirty else "warning",
                "detail": {"sha": source.sha, "dirty": source.dirty},
            }
        )
    except GitError as exc:
        checks.append({"name": "git_source", "status": "error", "detail": str(exc)})
    checks.append(
        {
            "name": "adapters",
            "status": "ok",
            "detail": list(AdapterRegistry().actions()),
        }
    )
    if playbook_path:
        playbook = load_playbook(playbook_path)
        missing: list[str] = []
        for step in playbook.steps:
            for key, value in step.config.items():
                if key.endswith("_env") and isinstance(value, str) and not os.environ.get(value):
                    missing.append(value)
        checks.append(
            {
                "name": "playbook",
                "status": "blocked" if missing else "ok",
                "detail": {
                    "name": playbook.name,
                    "provider": playbook.provider,
                    "missing_credential_env": sorted(set(missing)),
                },
            }
        )
    healthy = not any(check["status"] in {"error", "blocked"} for check in checks)
    return {"ready": healthy, "checks": checks}, 0 if healthy else 1


def _build_parser() -> argparse.ArgumentParser:
    parser = ShipyardArgumentParser(
        prog="shipyard",
        description="Candidate-bound deployment control for humans and coding agents.",
    )
    parser.add_argument("--version", action="version", version=f"shipyard {package_version()}")
    subparsers = parser.add_subparsers(
        dest="command", required=True, parser_class=ShipyardArgumentParser
    )

    quickstart_parser = subparsers.add_parser(
        "quickstart", help="Run a credential-free governed local release demonstration"
    )
    quickstart_parser.add_argument("directory", nargs="?", default="shipyard-quickstart")
    quickstart_parser.add_argument("--json", action="store_true")

    bootstrap_parser = subparsers.add_parser(
        "bootstrap", help="Generate safe integration files without network access"
    )
    bootstrap_subparsers = bootstrap_parser.add_subparsers(
        dest="bootstrap_command", required=True
    )
    github_bootstrap = bootstrap_subparsers.add_parser(
        "github-actions", help="Generate an exact-source GitHub workflow and playbook"
    )
    github_bootstrap.add_argument("owner")
    github_bootstrap.add_argument("repo")
    github_bootstrap.add_argument("source_sha")
    github_bootstrap.add_argument("--repository-id", required=True)
    github_bootstrap.add_argument("--workflow-id", required=True)
    github_bootstrap.add_argument("--workflow-file", default="shipyard.yml")
    github_bootstrap.add_argument("--output-dir", required=True)
    github_bootstrap.add_argument("--json", action="store_true")

    approval_parser = subparsers.add_parser(
        "approval", help="Export, sign, verify, or import portable candidate approvals"
    )
    approval_subparsers = approval_parser.add_subparsers(
        dest="approval_command", required=True
    )
    approval_export = approval_subparsers.add_parser(
        "export", help="Export the current ledger-bound candidate review"
    )
    approval_export.add_argument("run_id")
    approval_export.add_argument("--state-dir", default=str(_default_state_dir()))
    approval_export.add_argument("--output", required=True)
    approval_export.add_argument("--force", action="store_true")
    approval_export.add_argument("--json", action="store_true")
    approval_sign = approval_subparsers.add_parser(
        "sign", help="Sign one candidate review with an operator-owned SSH key"
    )
    approval_sign.add_argument("review")
    approval_sign.add_argument("--key", required=True)
    approval_sign.add_argument("--actor", required=True)
    approval_sign.add_argument("--reason", required=True)
    approval_sign.add_argument("--approved-at", required=True)
    approval_sign.add_argument("--output", required=True)
    approval_sign.add_argument("--force", action="store_true")
    approval_sign.add_argument("--json", action="store_true")
    approval_verify = approval_subparsers.add_parser(
        "verify", help="Verify a signed approval against a candidate review"
    )
    approval_verify.add_argument("review")
    approval_verify.add_argument("signed")
    approval_verify.add_argument("--allowed-signers", required=True)
    approval_verify.add_argument("--json", action="store_true")
    approval_import = approval_subparsers.add_parser(
        "import", help="Verify and record a signed approval for the current ledger candidate"
    )
    approval_import.add_argument("run_id")
    approval_import.add_argument("--state-dir", default=str(_default_state_dir()))
    approval_import.add_argument("--review", required=True)
    approval_import.add_argument("--signed", required=True)
    approval_import.add_argument("--allowed-signers", required=True)
    approval_import.add_argument("--json", action="store_true")

    connection_parser = subparsers.add_parser(
        "connection", help="Manage private per-user provider connections"
    )
    connection_subparsers = connection_parser.add_subparsers(
        dest="connection_command", required=True
    )

    connection_add = connection_subparsers.add_parser(
        "add", help="Save a non-secret provider connection profile"
    )
    connection_add.add_argument("name")
    connection_add.add_argument(
        "--provider",
        required=True,
        choices=[
            "github",
            "github-actions",
            "buzz-git",
            "buzz",
            "render",
            "heroku",
            "vercel",
        ],
    )
    connection_add.add_argument("--remote")
    connection_add.add_argument("--ref")
    connection_add.add_argument("--workflow-id")
    connection_add.add_argument("--workflow-file")
    connection_add.add_argument("--owner")
    connection_add.add_argument("--repo-name")
    connection_add.add_argument("--repository-id")
    connection_add.add_argument("--service-id")
    connection_add.add_argument("--app")
    connection_add.add_argument("--project")
    connection_add.add_argument("--repo-id")
    connection_add.add_argument("--team-id")
    connection_add.add_argument("--token-env")
    connection_add.add_argument("--source-blob-url-env")
    connection_add.add_argument("--replace", action="store_true")
    connection_add.add_argument("--config-dir", default=str(default_config_dir()))
    connection_add.add_argument("--json", action="store_true")

    for operation, help_text in (
        ("list", "List connection profiles without credential values"),
        ("show", "Show one connection profile without credential values"),
        ("remove", "Remove a connection profile"),
        ("check", "Validate a connection; network checks require explicit consent"),
        ("playbook", "Generate an immutable schema-v2 playbook snapshot"),
    ):
        child = connection_subparsers.add_parser(operation, help=help_text)
        if operation != "list":
            child.add_argument("name")
        child.add_argument("--config-dir", default=str(default_config_dir()))
        child.add_argument("--json", action="store_true")
        if operation == "check":
            child.add_argument("--repo", default=".")
            child.add_argument("--allow-network", action="store_true")
        if operation == "playbook":
            child.add_argument("--output", default="shipyard.toml")
            child.add_argument("--target", default="production")
            child.add_argument("--force", action="store_true")

    inspect_parser = subparsers.add_parser("inspect", help="Inspect Git source identity")
    inspect_parser.add_argument("repo", nargs="?", default=".")
    inspect_parser.add_argument("--json", action="store_true")

    release_parser = subparsers.add_parser(
        "release", help="Operate a standalone exact-SHA multi-provider release"
    )
    release_subparsers = release_parser.add_subparsers(
        dest="release_command", required=True
    )
    release_init = release_subparsers.add_parser(
        "init", help="Create a stable non-secret release project manifest"
    )
    release_init.add_argument("--output", default="shipyard.release.toml")
    release_init.add_argument("--force", action="store_true")
    release_init.add_argument("--json", action="store_true")

    release_project = release_subparsers.add_parser(
        "project", help="Initialize, validate, or show stable release-project configuration"
    )
    release_project_subparsers = release_project.add_subparsers(
        dest="release_project_command",
        required=True,
        parser_class=ShipyardArgumentParser,
    )
    project_init = release_project_subparsers.add_parser(
        "init", help="Create a non-secret release project without network access"
    )
    project_init.add_argument("path", nargs="?", default="shipyard.release.toml")
    project_init.add_argument("--force", action="store_true")
    project_init.add_argument("--json", action="store_true")
    project_validate = release_project_subparsers.add_parser(
        "validate", help="Validate a release project offline"
    )
    project_validate.add_argument("path")
    project_validate.add_argument("--json", action="store_true")
    project_show = release_project_subparsers.add_parser(
        "show", help="Show redacted stable release-project coordinates offline"
    )
    project_show.add_argument("path")
    project_show.add_argument("--json", action="store_true")

    release_inspect = release_subparsers.add_parser(
        "inspect", help="Adopt current GitHub and Apple state with GET-only exact-SHA discovery"
    )
    release_inspect.add_argument("repo", nargs="?", default=".")
    release_inspect.add_argument("--project", required=True)
    release_inspect.add_argument("--source-sha")
    release_inspect.add_argument("--expected-build-number")
    release_inspect.add_argument("--provider", choices=["all", "github", "apple"], default="all")
    release_inspect.add_argument("--allow-network", action="store_true")
    release_inspect.add_argument("--state-dir", default=str(_default_state_dir()))
    release_inspect.add_argument("--json", action="store_true")

    release_wait = release_subparsers.add_parser(
        "wait",
        help="Poll exact-SHA provider state with GET-only discovery and no persistence",
    )
    release_wait.add_argument("repo", nargs="?", default=".")
    release_wait.add_argument("--project", required=True)
    release_wait.add_argument("--source-sha")
    release_wait.add_argument("--expected-build-number")
    release_wait.add_argument(
        "--provider", choices=["all", "github", "apple"], default="all"
    )
    release_wait.add_argument("--allow-network", action="store_true")
    release_wait.add_argument("--timeout", type=float, default=900.0)
    release_wait.add_argument("--interval", type=float, default=15.0)
    release_wait.add_argument("--json", action="store_true")

    release_playbook = release_subparsers.add_parser(
        "playbook", help="Render an exact resolved TestFlight playbook from one Apple observation"
    )
    release_playbook.add_argument("--project", required=True)
    release_playbook.add_argument("--source-sha", required=True)
    release_playbook.add_argument(
        "--phase",
        choices=[
            "github-candidate",
            "buzz-candidate",
            "buzz-main",
            "github-main",
            "xcode-build",
            "testflight",
        ],
        default="testflight",
    )
    release_playbook.add_argument("--apple-observation")
    release_playbook.add_argument("--physical-device-attestation")
    release_playbook.add_argument("--repo", default=".")
    release_playbook.add_argument("--output", required=True)
    release_playbook.add_argument("--target", default="production")
    release_playbook.add_argument("--state-dir", default=str(_default_state_dir()))
    release_playbook.add_argument("--force", action="store_true")
    release_playbook.add_argument("--json", action="store_true")

    release_observation = release_subparsers.add_parser(
        "observation", help="List or verify immutable read-only provider observations"
    )
    release_observation_subparsers = release_observation.add_subparsers(
        dest="release_observation_command",
        required=True,
        parser_class=ShipyardArgumentParser,
    )
    observation_list = release_observation_subparsers.add_parser(
        "list", help="List immutable observations without network or state mutation"
    )
    observation_list.add_argument("--project")
    observation_list.add_argument("--project-digest")
    observation_list.add_argument("--source-sha")
    observation_list.add_argument("--provider", choices=["github", "apple"])
    observation_list.add_argument("--limit", type=int, default=100)
    observation_list.add_argument("--state-dir", default=str(_default_state_dir()))
    observation_list.add_argument("--json", action="store_true")
    observation_show = release_observation_subparsers.add_parser(
        "show", help="Verify and show one immutable observation"
    )
    observation_show.add_argument("observation")
    observation_show.add_argument("--state-dir", default=str(_default_state_dir()))
    observation_show.add_argument("--json", action="store_true")

    release_gate = release_subparsers.add_parser(
        "gate", help="Record or inspect exact-SHA operator gate attestations"
    )
    release_gate_subparsers = release_gate.add_subparsers(
        dest="release_gate_command", required=True
    )
    gate_attest = release_gate_subparsers.add_parser(
        "attest", help="Record an immutable gate result and evidence"
    )
    gate_attest.add_argument("gate")
    gate_attest.add_argument("--project", required=True)
    gate_attest.add_argument("--source-sha", required=True)
    gate_attest.add_argument("--status", choices=["passed", "failed", "pending"], required=True)
    gate_attest.add_argument("--actor", required=True)
    gate_attest.add_argument("--reason", required=True)
    gate_attest.add_argument("--evidence", action="append", default=[])
    gate_attest.add_argument("--apple-observation")
    gate_attest.add_argument("--app-version")
    gate_attest.add_argument("--build-number")
    gate_attest.add_argument("--device")
    gate_attest.add_argument("--os-version")
    gate_attest.add_argument("--check", action="append", default=[])
    gate_attest.add_argument("--state-dir", default=str(_default_state_dir()))
    gate_attest.add_argument("--json", action="store_true")
    gate_show = release_gate_subparsers.add_parser(
        "show", help="Verify and show one immutable gate attestation"
    )
    gate_show.add_argument("attestation")
    gate_show.add_argument("--state-dir", default=str(_default_state_dir()))
    gate_show.add_argument("--json", action="store_true")

    release_dossier = release_subparsers.add_parser(
        "dossier", help="Export or verify one aggregate offline release dossier"
    )
    release_dossier_subparsers = release_dossier.add_subparsers(
        dest="release_dossier_command", required=True
    )
    dossier_export = release_dossier_subparsers.add_parser(
        "export", help="Export runs, observations, gates, and artifacts as one dossier"
    )
    dossier_export.add_argument("--project", required=True)
    dossier_export.add_argument("--source-sha", required=True)
    dossier_export.add_argument(
        "--scope", choices=["internal", "external", "production"], required=True
    )
    dossier_export.add_argument("--run", action="append", default=[], metavar="NAME=PATH")
    dossier_export.add_argument(
        "--observation", action="append", default=[], metavar="NAME=PATH"
    )
    dossier_export.add_argument("--gate", action="append", default=[], metavar="PATH")
    dossier_export.add_argument(
        "--artifact", action="append", default=[], metavar="NAME=PATH"
    )
    dossier_export.add_argument("--output", required=True)
    dossier_export.add_argument("--json", action="store_true")
    dossier_verify = release_dossier_subparsers.add_parser(
        "verify", help="Verify a release dossier without ledger or network access"
    )
    dossier_verify.add_argument("bundle")
    dossier_verify.add_argument("--json", action="store_true")

    plan_parser = subparsers.add_parser("plan", help="Render a release plan without running it")
    plan_parser.add_argument("repo", nargs="?", default=".")
    plan_parser.add_argument("--playbook", required=True)
    plan_parser.add_argument("--json", action="store_true")

    init_parser = subparsers.add_parser("init", help="Create a typed provider playbook")
    init_parser.add_argument(
        "provider",
        choices=["github", "github-actions", "buzz", "render", "heroku", "vercel"],
    )
    init_parser.add_argument("--output", default="shipyard.toml")
    init_parser.add_argument("--force", action="store_true")
    init_parser.add_argument("--json", action="store_true")

    run_parser = subparsers.add_parser("run", help="Prepare a candidate and stop for approval")
    run_parser.add_argument("repo", nargs="?", default=".")
    run_parser.add_argument("--playbook", required=True)
    run_parser.add_argument("--state-dir", default=str(_default_state_dir()))
    run_parser.add_argument("--execute-external", action="store_true")
    run_parser.add_argument("--confirm-sha")
    run_parser.add_argument("--approve-candidate")
    run_parser.add_argument("--approval-actor")
    run_parser.add_argument("--approval-reason")
    run_parser.add_argument("--json", action="store_true")

    resume_parser = subparsers.add_parser("resume", help="Approve/resume a persisted run")
    resume_parser.add_argument("run_id")
    resume_parser.add_argument("--state-dir", default=str(_default_state_dir()))
    resume_parser.add_argument("--execute-external", action="store_true")
    resume_parser.add_argument("--confirm-sha")
    resume_parser.add_argument("--approve-candidate")
    resume_parser.add_argument("--approval-actor")
    resume_parser.add_argument("--approval-reason")
    resume_parser.add_argument("--json", action="store_true")

    resolve_parser = subparsers.add_parser(
        "resolve", help="Read back an uncertain typed provider operation"
    )
    resolve_parser.add_argument("run_id")
    resolve_parser.add_argument("--state-dir", default=str(_default_state_dir()))
    resolve_parser.add_argument("--json", action="store_true")

    wait_parser = subparsers.add_parser(
        "wait", help="Poll provider readback without reconciling or continuing the run"
    )
    wait_parser.add_argument("run_id")
    wait_parser.add_argument("--state-dir", default=str(_default_state_dir()))
    wait_parser.add_argument("--timeout", type=float, default=300.0)
    wait_parser.add_argument("--interval", type=float, default=5.0)
    wait_parser.add_argument("--json", action="store_true")

    status_parser = subparsers.add_parser("status", help="Read back a persisted run")
    status_parser.add_argument("run_id")
    status_parser.add_argument("--state-dir", default=str(_default_state_dir()))
    status_parser.add_argument("--json", action="store_true")

    list_parser = subparsers.add_parser("list", help="List persisted runs")
    list_parser.add_argument("--state-dir", default=str(_default_state_dir()))
    list_parser.add_argument("--limit", type=int, default=100)
    list_parser.add_argument("--json", action="store_true")

    evidence_parser = subparsers.add_parser(
        "evidence", help="Export or verify a portable offline evidence bundle"
    )
    evidence_subparsers = evidence_parser.add_subparsers(
        dest="evidence_command", required=True
    )
    evidence_export = evidence_subparsers.add_parser(
        "export", help="Export one run and its approved artifacts"
    )
    evidence_export.add_argument("run_id")
    evidence_export.add_argument("--state-dir", default=str(_default_state_dir()))
    evidence_export.add_argument("--output", required=True)
    evidence_export.add_argument("--json", action="store_true")
    evidence_verify = evidence_subparsers.add_parser(
        "verify", help="Verify a bundle without ledger or network access"
    )
    evidence_verify.add_argument("bundle")
    evidence_verify.add_argument("--json", action="store_true")
    evidence_report = evidence_subparsers.add_parser(
        "report", help="Render a verified bundle as static Markdown or HTML"
    )
    evidence_report.add_argument("bundle")
    evidence_report.add_argument("--format", choices=["markdown", "html"], default="markdown")
    evidence_report.add_argument("--output")
    evidence_report.add_argument("--force", action="store_true")
    evidence_report.add_argument("--json", action="store_true")

    adapters_parser = subparsers.add_parser("adapters", help="List typed adapter actions")
    adapters_parser.add_argument("--json", action="store_true")

    version_parser = subparsers.add_parser("version", help="Show runtime/build identity")
    version_parser.add_argument("--json", action="store_true")

    doctor_parser = subparsers.add_parser("doctor", help="Validate local deployment readiness")
    doctor_parser.add_argument("repo", nargs="?", default=".")
    doctor_parser.add_argument("--state-dir", default=str(_default_state_dir()))
    doctor_parser.add_argument("--playbook")
    doctor_parser.add_argument("--json", action="store_true")

    serve_parser = subparsers.add_parser("serve", help="Serve the loopback read-only web app")
    serve_parser.add_argument("--state-dir", default=str(_default_state_dir()))
    serve_parser.add_argument("--config-dir", default=str(default_config_dir()))
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8787)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    arguments = list(sys.argv[1:] if argv is None else argv)
    json_requested = "--json" in arguments
    try:
        args = parser.parse_args(arguments)
    except CliArgumentError as exc:
        _print_error(
            str(exc),
            as_json=json_requested,
            code="INVALID_ARGUMENT",
            phase="config",
        )
        return 2
    try:
        if args.command == "quickstart":
            summary = run_quickstart(args.directory)
            payload = {
                "destination": str(summary.destination),
                "run_id": summary.run_id,
                "status": summary.status,
                "candidate_digest": summary.candidate_digest,
                "source_sha": summary.source_sha,
                "remote_sha": summary.remote_sha,
                "remote_url": summary.remote_url,
                "evidence_path": str(summary.evidence_path),
                "evidence_verified": summary.evidence_verified,
                "verdict": summary.verdict,
            }
            if args.json:
                _print(payload, as_json=True)
            else:
                print(f"Shipyard quickstart: {summary.status}")
                print(f"Source: {summary.source_sha}")
                print(f"Candidate: {summary.candidate_digest}")
                print(f"Evidence: {summary.evidence_path}")
            return 0
        if args.command == "bootstrap":
            bundle = plan_github_bootstrap(
                args.owner,
                args.repo,
                args.source_sha,
                repository_id=args.repository_id,
                workflow_id=args.workflow_id,
                workflow_file=args.workflow_file,
            )
            created = _write_bootstrap_bundle(bundle, args.output_dir)
            _print(
                {
                    "target": f"{bundle.owner}/{bundle.repo}",
                    "source_sha": bundle.source_sha,
                    "created": [str(path) for path in created],
                    "network_used": False,
                    "provider_mutation": False,
                },
                as_json=args.json,
            )
            return 0
        if args.command == "approval":
            operation = args.approval_command
            if operation == "export":
                ledger = Ledger(args.state_dir)
                review = build_candidate_review(ledger.get_run(args.run_id))
                destination = _write_private_text(
                    args.output,
                    canonical_packet_bytes(review).decode("utf-8") + "\n",
                    force=args.force,
                )
                payload = {
                    "run_id": args.run_id,
                    "candidate_digest": review["candidate_digest"],
                    "output": str(destination),
                }
                if args.json:
                    _print(payload, as_json=True)
                else:
                    print(f"Candidate review: {destination}")
                return 0
            review = load_candidate_review(args.review)
            if operation == "sign":
                statement = build_approval_statement(
                    review,
                    actor=args.actor,
                    reason=args.reason,
                    approved_at=args.approved_at,
                )
                signed = sign_approval_ssh(statement, key_path=args.key)
                destination = _write_private_text(
                    args.output,
                    json.dumps(signed, separators=(",", ":"), sort_keys=True) + "\n",
                    force=args.force,
                )
                _print(
                    {
                        "output": str(destination),
                        "actor": statement["actor"],
                        "candidate_digest": statement["candidate_digest"],
                    },
                    as_json=args.json,
                )
                return 0
            signed = load_signed_approval(args.signed)
            if operation == "verify":
                statement = verify_signed_approval_ssh(
                    signed,
                    review=review,
                    allowed_signers=args.allowed_signers,
                )
                _print(
                    {"verified": True, "statement": statement}, as_json=args.json
                )
                return 0
            ledger = Ledger(args.state_dir)
            if ledger.get_approval(args.run_id) is not None:
                raise ApprovalPacketError("run already has a recorded approval")
            current_review = build_candidate_review(ledger.get_run(args.run_id))
            if canonical_packet_bytes(review) != canonical_packet_bytes(current_review):
                raise ApprovalPacketError(
                    "supplied review does not match the current ledger candidate"
                )
            statement = verify_signed_approval_ssh(
                signed,
                review=current_review,
                allowed_signers=args.allowed_signers,
            )
            signed_digest = hashlib.sha256(
                json.dumps(signed, separators=(",", ":"), sort_keys=True).encode("utf-8")
            ).hexdigest()
            quorum_met = ledger.record_signed_approval(
                args.run_id,
                statement["candidate_digest"],
                actor=statement["actor"],
                reason=statement["reason"],
                approved_at=statement["approved_at"],
                review_sha256=statement["review_sha256"],
                signed_approval_sha256=signed_digest,
            )
            approval_payload = {
                "run_id": args.run_id,
                "candidate_digest": statement["candidate_digest"],
                "actor": statement["actor"],
                "approved_at": statement["approved_at"],
                "signature_verified": True,
                "quorum_met": quorum_met,
                "signed_approval_count": len(
                    ledger.list_signed_approvals(args.run_id)
                ),
            }
            if args.json:
                _print(approval_payload, as_json=True)
            else:
                print(f"Signed approval imported for run {args.run_id}")
                print(f"Actor: {statement['actor']}")
                print(f"Approved at: {statement['approved_at']}")
            return 0
        if args.command == "connection":
            store = ConnectionStore(args.config_dir)
            operation = args.connection_command
            if operation == "add":
                profile = store.add(
                    args.name,
                    args.provider,
                    _connection_options(args),
                    replace=args.replace,
                )
                payload = {
                    "connection": profile.public_payload(),
                    "stored_at": str(store.path),
                    "secrets_stored": False,
                    "next_steps": [
                        f"shipyard connection check {profile.name}",
                        f"shipyard connection check {profile.name} --allow-network",
                        f"shipyard connection playbook {profile.name} --output shipyard.toml",
                    ],
                }
                _print(payload, as_json=args.json)
                return 0
            if operation == "list":
                _print(
                    {"connections": [profile.public_payload() for profile in store.list()]},
                    as_json=args.json,
                )
                return 0
            if operation == "show":
                _print(store.get(args.name).public_payload(), as_json=args.json)
                return 0
            if operation == "remove":
                removed = store.remove(args.name)
                _print({"removed": removed.name}, as_json=args.json)
                return 0
            if operation == "check":
                result = verify_connection(
                    store.get(args.name), args.repo, allow_network=args.allow_network
                )
                _print(result, as_json=args.json)
                return 1 if result["status"] in {"blocked", "unknown"} else 0
            profile = store.get(args.name)
            destination = _write_private_text(
                args.output,
                render_playbook(profile, target=args.target),
                force=args.force,
            )
            _print(
                {
                    "created": str(destination),
                    "connection": profile.name,
                    "connection_digest": profile.digest,
                    "secrets_stored": False,
                },
                as_json=args.json,
            )
            return 0
        if args.command == "release":
            operation = args.release_command
            if operation in {"init", "project"} and (
                operation == "init" or args.release_project_command == "init"
            ):
                output = args.output if operation == "init" else args.path
                destination = _write_private_text(
                    output,
                    render_project_template(),
                    force=args.force,
                )
                destination.chmod(0o644)
                _print(
                    {
                        "created": str(destination),
                        "status": "created",
                        "schema_version": "shipyard.release-project/v1",
                        "secrets_stored": False,
                        "provider_mutations": 0,
                        "next_steps": [
                            f"edit {destination}",
                            f"shipyard release project validate {destination} --json",
                            (
                                f"shipyard release inspect --project {destination} "
                                "--allow-network --json"
                            ),
                        ],
                    },
                    as_json=args.json,
                )
                return 0
            if operation == "project":
                project = load_release_project(args.path)
                payload = {
                    "status": "valid",
                    "valid": True,
                    "project": project.public_payload(),
                    "project_digest": project.digest,
                    "offline": True,
                    "provider_mutations": 0,
                }
                _print(payload, as_json=args.json)
                return 0
            if operation == "observation":
                store = ObservationStore(args.state_dir)
                if args.release_observation_command == "show":
                    observation = store.load(args.observation)
                    _print(
                        {
                            "status": observation.status,
                            "observation": observation.payload(),
                            "path": str(observation.path),
                            "offline": True,
                            "provider_mutations": 0,
                        },
                        as_json=args.json,
                    )
                    return 0
                project_digest = args.project_digest
                if args.project:
                    project = load_release_project(args.project)
                    if project_digest is not None and project_digest != project.digest:
                        raise ObservationError(
                            "observation project and project digest filters do not match"
                        )
                    project_digest = project.digest
                observations = store.list(
                    project_digest=project_digest,
                    source_sha=args.source_sha,
                    provider=args.provider,
                    limit=args.limit,
                )
                _print(
                    {
                        "status": "listed",
                        "observations": [
                            {
                                **observation.payload(),
                                "path": str(observation.path),
                            }
                            for observation in observations
                        ],
                        "count": len(observations),
                        "offline": True,
                        "provider_mutations": 0,
                    },
                    as_json=args.json,
                )
                return 0
            if operation == "dossier" and args.release_dossier_command == "verify":
                report = verify_release_dossier(args.bundle)
                _print(report, as_json=args.json)
                return 0 if report.get("valid") is True else 1
            if operation == "gate" and args.release_gate_command == "show":
                gate = GateStore(args.state_dir).load(args.attestation)
                _print(gate.payload(), as_json=args.json)
                return 0
            project = load_release_project(args.project)
            if operation in {"inspect", "wait"}:
                if not args.allow_network:
                    raise ReleaseProjectError(
                        f"release {operation} requires explicit --allow-network consent"
                    )
                source_sha, snapshot = _release_source_sha(args.repo, args.source_sha)
                _verify_release_project_source(project.source_remote, snapshot)

                def current_inspection():
                    return inspect_release(
                        project,
                        source_sha,
                        provider=args.provider,
                        expected_build_number=args.expected_build_number,
                    )

                if operation == "wait":
                    result = wait_for_reconciliation(
                        current_inspection,
                        timeout=args.timeout,
                        interval=args.interval,
                    )
                    inspection = result.last_value
                    if inspection is None:
                        raise ObservationError("release wait produced no provider observation")
                    payload = {
                        **inspection.payload(),
                        "state": result.state.value,
                        "polls": result.polls,
                        "last_status": result.last_status,
                        "source": _snapshot_payload(snapshot),
                        "project_digest": project.digest,
                        "persisted": False,
                        "next_step": (
                            "shipyard release inspect "
                            f"--project {project.path} --source-sha {source_sha} "
                            f"--provider {args.provider} --allow-network --json"
                        ),
                    }
                    _print(payload, as_json=args.json)
                    if result.state is WaitState.SUCCEEDED:
                        return 0
                    return 1 if result.state is WaitState.FAILED else 4

                inspection = current_inspection()
                store = ObservationStore(args.state_dir)
                observations: list[dict[str, object]] = []
                for provider_inspection in inspection.inspections:
                    observation = ReleaseObservation.create(
                        provider_inspection.provider,
                        project.digest,
                        source_sha,
                        provider_inspection.readback,
                    )
                    path = store.save(observation)
                    observations.append(
                        {
                            "provider": observation.provider,
                            "status": observation.status,
                            "state": observation.evidence.get("state", "present"),
                            "digest": observation.digest,
                            "path": str(path),
                            "evidence": observation.evidence,
                        }
                    )
                payload = {
                    "project": project.public_payload(),
                    "project_digest": project.digest,
                    "source": _snapshot_payload(snapshot),
                    "source_sha": source_sha,
                    "status": inspection.status,
                    "state": inspection.status,
                    "read_only": True,
                    "provider_mutations": 0,
                    "observations": observations,
                }
                _print(payload, as_json=args.json)
                return 0 if inspection.status == "succeeded" else 4
            source_sha = validate_source_sha(args.source_sha)
            if operation == "playbook":
                if args.phase in {
                    "github-candidate",
                    "buzz-candidate",
                    "buzz-main",
                    "github-main",
                }:
                    _, phase_snapshot = _release_source_sha(args.repo, source_sha)
                    _verify_release_project_source(
                        project.source_remote, phase_snapshot
                    )
                    repo = phase_snapshot.path.resolve()
                    destination = _write_private_text(
                        args.output,
                        render_release_phase(
                            project,
                            source_sha=source_sha,
                            phase=args.phase,
                            repo_path=str(repo),
                            target=args.target,
                        ),
                        force=args.force,
                    )
                    load_playbook(destination)
                    _print(
                        {
                            "created": str(destination),
                            "phase": args.phase,
                            "source_sha": source_sha,
                            "requires_candidate_approval": True,
                            "provider_mutations": 0,
                            "next_step": f"shipyard run {repo} --playbook {destination}",
                        },
                        as_json=args.json,
                    )
                    return 0
                if project.apple is None:
                    raise ReleaseProjectError("release project does not configure Apple")
                if not args.apple_observation:
                    raise ObservationError(
                        f"{args.phase} playbook requires --apple-observation"
                    )
                observation = ObservationStore(args.state_dir).load(args.apple_observation)
                if (
                    observation.project_digest != project.digest
                    or observation.source_sha != source_sha
                ):
                    raise ObservationError(
                        "Apple observation does not match project and source SHA"
                    )
                if args.phase == "xcode-build":
                    _, phase_snapshot = _release_source_sha(args.repo, source_sha)
                    _verify_release_project_source(
                        project.source_remote, phase_snapshot
                    )
                    repo = phase_snapshot.path.resolve()
                    remote_url = named_remote_url(repo, project.apple.source_git_remote)
                    if canonical_repository_identity(remote_url) != canonical_repository_identity(
                        project.apple.source_remote
                    ):
                        raise GitError(
                            "Apple source_git_remote does not match Apple source_remote"
                        )
                    destination = _write_private_text(
                        args.output,
                        render_xcode_build_playbook(
                            project,
                            source_sha=source_sha,
                            repo_path=str(repo),
                            source_remote=project.apple.source_git_remote,
                            source_observation=observation,
                            target=args.target,
                        ),
                        force=args.force,
                    )
                    load_playbook(destination)
                    _print(
                        {
                            "created": str(destination),
                            "phase": "xcode-build",
                            "source_sha": source_sha,
                            "apple_observation_digest": observation.digest,
                            "requires_candidate_approval": True,
                            "provider_mutations": 0,
                            "next_step": f"shipyard run {repo} --playbook {destination}",
                        },
                        as_json=args.json,
                    )
                    return 0
                coordinates = _apple_coordinates_from_observation(observation)
                physical_gate = (
                    GateStore(args.state_dir).load(args.physical_device_attestation)
                    if args.physical_device_attestation
                    else None
                )
                release_scope = (
                    "internal" if coordinates.beta_group_internal else "external"
                )
                required_gates = set(project.required_gate_names(release_scope))
                unsupported_gates = sorted(required_gates - {"physical-device"})
                if unsupported_gates:
                    raise GateError(
                        "TestFlight playbook cannot satisfy required release gate: "
                        + unsupported_gates[0]
                    )
                if "physical-device" in required_gates and physical_gate is None:
                    raise GateError(
                        "TestFlight playbook requires the project physical-device gate"
                    )
                destination = _write_private_text(
                    args.output,
                    render_testflight_playbook(
                        coordinates,
                        credential_config=project.apple.credential_config,
                        name=f"{project.name}-{coordinates.build_number}-{coordinates.beta_group_name}",
                        target=args.target,
                        project_digest=project.digest,
                        apple_observation_digest=observation.digest,
                        physical_device_attestation=physical_gate,
                    ),
                    force=args.force,
                )
                load_playbook(destination)
                _print(
                    {
                        "created": str(destination),
                        "source_sha": source_sha,
                        "apple_observation_digest": observation.digest,
                        "destination": coordinates.operation_destination,
                        "release_scope": release_scope,
                        "required_gates": sorted(required_gates),
                        "requires_candidate_approval": True,
                        "provider_mutations": 0,
                        "next_step": f"shipyard run . --playbook {destination}",
                    },
                    as_json=args.json,
                )
                return 0
            if operation == "gate":
                store = GateStore(args.state_dir)
                apple_observation_digest = None
                if args.apple_observation:
                    observation = ObservationStore(args.state_dir).load(
                        args.apple_observation
                    )
                    if (
                        observation.provider != "apple"
                        or observation.project_digest != project.digest
                        or observation.source_sha != source_sha
                    ):
                        raise ObservationError(
                            "gate Apple observation does not match project and source SHA"
                        )
                    apple_observation_digest = observation.digest
                gate = GateAttestation.create(
                    gate=args.gate,
                    project_digest=project.digest,
                    source_sha=source_sha,
                    status=args.status,
                    actor=args.actor,
                    reason=args.reason,
                    evidence_paths=args.evidence,
                    apple_observation_digest=apple_observation_digest,
                    app_version=args.app_version,
                    build_number=args.build_number,
                    device=args.device,
                    os_version=args.os_version,
                    checks=args.check,
                )
                gate_path = store.save(gate)
                _print(
                    {
                        **gate.payload(),
                        "path": str(gate_path),
                    },
                    as_json=args.json,
                )
                return 0 if gate.status == "passed" else 1 if gate.status == "failed" else 4
            dossier_path = export_release_dossier(
                project=project,
                source_sha=source_sha,
                release_scope=args.scope,
                run_bundles=_named_paths(args.run, "--run"),
                observations=_named_paths(args.observation, "--observation"),
                gates=args.gate,
                artifacts=_named_paths(args.artifact, "--artifact"),
                output=args.output,
            )
            report = verify_release_dossier(dossier_path)
            _print(
                {"bundle": str(dossier_path), **report},
                as_json=args.json,
            )
            return 0
        if args.command == "inspect":
            _print(_snapshot_payload(snapshot_repository(args.repo)), as_json=args.json)
            return 0
        if args.command == "version":
            _print(runtime_identity(), as_json=args.json)
            return 0
        if args.command == "adapters":
            _print({"actions": list(AdapterRegistry().actions())}, as_json=args.json)
            return 0
        if args.command == "init":
            destination = _write_private_text(
                args.output, _template(args.provider), force=args.force
            )
            _print(
                {"created": str(destination), "provider": args.provider},
                as_json=args.json,
            )
            return 0
        if args.command == "plan":
            snapshot = snapshot_repository(args.repo)
            playbook = load_playbook(args.playbook)
            payload = {
                "source": _snapshot_payload(snapshot),
                "playbook": playbook.name,
                "target": playbook.target,
                "provider": playbook.provider,
                "destination": playbook.destination,
                "dirty_source_allowed": playbook.allow_dirty,
                "steps": [
                    {
                        "id": step.id,
                        "name": step.name,
                        "effect": step.effect,
                        "command": list(step.command),
                        "action": step.action,
                        "config": step.config,
                        "requires_confirmation": step.effect == "external",
                        "requires_candidate_approval": step.effect == "external",
                    }
                    for step in playbook.steps
                ],
            }
            _print(payload, as_json=args.json)
            return 0
        if args.command == "doctor":
            payload, code = _doctor(args.repo, args.state_dir, args.playbook)
            _print(payload, as_json=args.json)
            return code
        if args.command == "evidence":
            if args.evidence_command == "export":
                ledger = Ledger(args.state_dir)
                run = ledger.get_run(args.run_id)
                destination = export_evidence_bundle(ledger, run.run_id, args.output)
                _print(
                    {
                        "bundle": str(destination),
                        "run_id": run.run_id,
                        "source_sha": run.source_sha,
                        "candidate_digest": run.candidate_digest,
                    },
                    as_json=args.json,
                )
                return 0
            if args.evidence_command == "report":
                verified = load_verified_report(args.bundle)
                content = (
                    render_markdown(verified)
                    if args.format == "markdown"
                    else render_html(verified)
                )
                destination = None
                if args.output:
                    destination = _write_private_text(
                        args.output, content, force=args.force
                    )
                payload = {
                    "bundle": str(Path(args.bundle).expanduser()),
                    "format": args.format,
                    "output": str(destination) if destination else None,
                    "valid": verified.get("valid") is True,
                }
                if args.json:
                    if destination is None:
                        payload["report"] = content
                    _print(payload, as_json=True)
                elif destination is None:
                    print(content, end="")
                else:
                    _print(payload, as_json=False)
                return 0 if payload["valid"] else 1
            payload = verify_evidence_bundle(args.bundle)
            _print(payload, as_json=args.json)
            return 0 if payload["valid"] else 1
        if args.command == "serve":
            server = create_server(
                args.state_dir, args.host, args.port, config_dir=args.config_dir
            )
            address, port = server.server_address[:2]
            print(f"Shipyard read-only web app: http://{address}:{port}", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
            return 0

        ledger = Ledger(args.state_dir)
        if args.command == "wait":
            executor = ReleaseExecutor(ledger)
            result = wait_for_reconciliation(
                lambda: executor.readback_once(args.run_id),
                timeout=args.timeout,
                interval=args.interval,
            )
            readback = result.last_value
            payload = {
                "run_id": args.run_id,
                "state": result.state.value,
                "polls": result.polls,
                "last_status": result.last_status,
                "operation_id": getattr(readback, "operation_id", None),
                "observed_sha": getattr(readback, "observed_sha", None),
                "reconciled": False,
                "next_step": f"shipyard resolve {args.run_id} --state-dir {args.state_dir}",
            }
            if args.json:
                _print(payload, as_json=True)
            else:
                print(f"Run: {args.run_id}")
                print(f"Observed provider state: {result.state.value}")
                print("Ledger unchanged; use the explicit resolve command to reconcile.")
            if result.state is WaitState.SUCCEEDED:
                return 0
            return 1 if result.state is WaitState.FAILED else 4
        if args.command == "run":
            run = ReleaseExecutor(ledger).start(
                args.repo,
                load_playbook(args.playbook),
                execute_external=args.execute_external,
                confirm_sha=args.confirm_sha,
                approve_candidate=args.approve_candidate,
                approval_actor=args.approval_actor,
                approval_reason=args.approval_reason,
            )
        elif args.command == "resume":
            run = ReleaseExecutor(ledger).resume(
                args.run_id,
                execute_external=args.execute_external,
                confirm_sha=args.confirm_sha,
                approve_candidate=args.approve_candidate,
                approval_actor=args.approval_actor,
                approval_reason=args.approval_reason,
            )
        elif args.command == "resolve":
            run = ReleaseExecutor(ledger).resolve(args.run_id)
        elif args.command == "list":
            payload = {"runs": [_run_payload(run) for run in ledger.list_runs(args.limit)]}
            _print(payload, as_json=args.json)
            return 0
        else:
            run = ReleaseExecutor(ledger).recover_stale(args.run_id)
        _print(_run_payload(run, ledger), as_json=args.json)
        return _result_code(run)
    except UncertainOutcomeError as exc:
        _print_error(str(exc), as_json=bool(getattr(args, "json", False)))
        return 4
    except (
        AdapterError,
        ApprovalPacketError,
        AuthorizationError,
        CandidateError,
        BootstrapInputError,
        ConnectionError,
        DossierError,
        EvidenceError,
        GateError,
        GitError,
        LedgerError,
        ObservationError,
        PlaybookError,
        ProcessInterrupted,
        ProvenanceDriftError,
        QuickstartError,
        ReleasePhaseError,
        ReleaseProjectError,
        RuntimeIdentityError,
        ValueError,
    ) as exc:
        _print_error(str(exc), as_json=bool(getattr(args, "json", False)))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
