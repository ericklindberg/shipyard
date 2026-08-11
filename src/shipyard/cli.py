from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import stat
import sys
from contextlib import suppress
from pathlib import Path
from typing import Any

from .adapters.base import AdapterError
from .adapters.registry import AdapterRegistry
from .bootstrap import BootstrapBundle, BootstrapInputError, plan_github_bootstrap
from .candidate import CandidateError
from .connections import (
    ConnectionError,
    ConnectionStore,
    default_config_dir,
    render_playbook,
    verify_connection,
)
from .evidence import EvidenceError, export_evidence_bundle, verify_evidence_bundle
from .executor import (
    AuthorizationError,
    ProcessInterrupted,
    ProvenanceDriftError,
    ReleaseExecutor,
    UncertainOutcomeError,
)
from .gitops import GitError, snapshot_repository
from .identity import package_version, runtime_identity
from .ledger import Ledger, LedgerError
from .models import ReleaseRun, RepositorySnapshot
from .playbook import PlaybookError, load_playbook
from .quickstart import QuickstartError, run_quickstart
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


def _json_envelope(payload: Any) -> dict[str, Any]:
    return {"api_version": _JSON_API_VERSION, "ok": True, "data": payload}


def _print_error(message: str, *, as_json: bool) -> None:
    if as_json:
        print(
            json.dumps(
                {
                    "api_version": _JSON_API_VERSION,
                    "ok": False,
                    "error": {"message": message},
                },
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return
    print(f"shipyard: {message}", file=sys.stderr)


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
    parser = argparse.ArgumentParser(
        prog="shipyard",
        description="Candidate-bound deployment control for humans and coding agents.",
    )
    parser.add_argument("--version", action="version", version=f"shipyard {package_version()}")
    subparsers = parser.add_subparsers(dest="command", required=True)

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
    args = parser.parse_args(argv)
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
        AuthorizationError,
        CandidateError,
        BootstrapInputError,
        ConnectionError,
        EvidenceError,
        GitError,
        LedgerError,
        PlaybookError,
        ProcessInterrupted,
        ProvenanceDriftError,
        QuickstartError,
        RuntimeIdentityError,
        ValueError,
    ) as exc:
        _print_error(str(exc), as_json=bool(getattr(args, "json", False)))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
