from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import sys
from contextlib import suppress
from pathlib import Path
from typing import Any

from .adapters.base import AdapterError
from .adapters.registry import AdapterRegistry
from .candidate import CandidateError
from .connections import (
    ConnectionError,
    ConnectionStore,
    default_config_dir,
    render_playbook,
    verify_connection,
)
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
from .runtime import RuntimeIdentityError
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
        "buzz": ("buzz", "repository:refs/heads/main", "git.ref"),
        "render": ("render", "owner/service/production", "render.deploy"),
        "heroku": ("heroku", "app/production", "heroku.build"),
        "vercel": ("vercel", "team/project/production", "vercel.deploy"),
    }
    selected, destination, action = headers[provider]
    configs = {
        "github": 'remote = "origin"\nref = "refs/heads/main"',
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
        choices=["github", "buzz-git", "buzz", "render", "heroku", "vercel"],
    )
    connection_add.add_argument("--remote")
    connection_add.add_argument("--ref")
    connection_add.add_argument("--workflow-id")
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
    init_parser.add_argument("provider", choices=["github", "buzz", "render", "heroku", "vercel"])
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

    status_parser = subparsers.add_parser("status", help="Read back a persisted run")
    status_parser.add_argument("run_id")
    status_parser.add_argument("--state-dir", default=str(_default_state_dir()))
    status_parser.add_argument("--json", action="store_true")

    list_parser = subparsers.add_parser("list", help="List persisted runs")
    list_parser.add_argument("--state-dir", default=str(_default_state_dir()))
    list_parser.add_argument("--limit", type=int, default=100)
    list_parser.add_argument("--json", action="store_true")

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
        ConnectionError,
        GitError,
        LedgerError,
        PlaybookError,
        ProcessInterrupted,
        ProvenanceDriftError,
        RuntimeIdentityError,
        ValueError,
    ) as exc:
        _print_error(str(exc), as_json=bool(getattr(args, "json", False)))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
