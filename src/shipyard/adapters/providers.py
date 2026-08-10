from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from ..runtime import resolve_executable, sanitized_environment
from .base import (
    AdapterContext,
    AdapterError,
    AdapterStatus,
    ConnectionCheck,
    MutationReceipt,
    ProviderReadback,
)
from .http import HttpResponse, HttpTransport, UrllibTransport

CommandRunner = Callable[[tuple[str, ...], Path, tuple[str, ...]], tuple[int, str]]
_EXACT_SHA = re.compile(r"^[0-9a-f]{40}$")
_EXACT_REF = re.compile(r"^refs/(?:heads|tags)/[A-Za-z0-9._/-]+$")
_NAMED_GIT_REMOTE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")


def _default_command_runner(
    command: tuple[str, ...], cwd: Path, allowed_env: tuple[str, ...] = ()
) -> tuple[int, str]:
    executable = resolve_executable(command[0], cwd)
    environment = sanitized_environment()
    for name in allowed_env:
        value = os.environ.get(name)
        if value is not None:
            environment[name] = value
    completed = subprocess.run(  # noqa: S603
        (str(executable), *command[1:]),
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    output = (completed.stdout + completed.stderr)[-64_000:]
    return completed.returncode, output


def _config_string(context: AdapterContext, name: str) -> str:
    value = context.config.get(name)
    if not isinstance(value, str) or not value.strip():
        raise AdapterError(f"adapter config requires {name}")
    return value.strip()


def _operation_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\0".join(parts).encode()).hexdigest()[:24]
    return f"{prefix}-{digest}"


@dataclass
class GitRefAdapter:
    runner: CommandRunner = _default_command_runner
    action: str = "git.ref"

    def _parameters(self, context: AdapterContext) -> tuple[str, str, Path]:
        remote = _config_string(context, "remote")
        ref = _config_string(context, "ref")
        if (
            not _NAMED_GIT_REMOTE.fullmatch(remote)
            or ".." in remote
            or remote.endswith("/")
        ):
            raise AdapterError("git.ref requires a named Git remote")
        repo_value = context.config.get("repo_path", ".")
        if not isinstance(repo_value, str):
            raise AdapterError("adapter config repo_path must be a string")
        repo = Path(repo_value).expanduser().resolve()
        if not _EXACT_REF.fullmatch(ref) or ".." in ref or ref.endswith("/"):
            raise AdapterError("git.ref requires a canonical refs/heads/* or refs/tags/* ref")
        if not _EXACT_SHA.fullmatch(context.source_sha):
            raise AdapterError("git.ref requires a full 40-character source SHA")
        return remote, ref, repo

    def check(self, context: AdapterContext) -> ConnectionCheck:
        remote, ref, repo = self._parameters(context)
        remote_code, _remote_output = self.runner(
            ("git", "remote", "get-url", "--", remote), repo, ()
        )
        if remote_code != 0:
            raise AdapterError("git connection verification requires a configured named remote")
        code, output = self.runner(("git", "ls-remote", remote, ref), repo, ())
        if code != 0:
            raise AdapterError("Git remote verification failed")
        observed = None
        for line in output.splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[1] == ref and _EXACT_SHA.fullmatch(fields[0]):
                observed = fields[0]
                break
        if observed is None:
            raise AdapterError("Git remote verification did not return the configured ref")
        return ConnectionCheck(
            "verified", context.provider, self.action, observed, {"remote": remote, "ref": ref}
        )

    def execute(self, context: AdapterContext) -> MutationReceipt:
        remote, ref, repo = self._parameters(context)
        code, _output = self.runner(
            ("git", "push", "--porcelain", remote, f"{context.source_sha}:{ref}"),
            repo,
            (),
        )
        if code != 0:
            raise AdapterError("exact-ref git push failed; provider outcome requires readback")
        operation_id = _operation_id("git", remote, ref, context.source_sha)
        return MutationReceipt(
            provider=context.provider,
            action=self.action,
            operation_id=operation_id,
            submitted_sha=context.source_sha,
            evidence={"remote": remote, "ref": ref},
        )

    def readback(
        self, context: AdapterContext, receipt: MutationReceipt
    ) -> ProviderReadback:
        remote, ref, repo = self._parameters(context)
        code, output = self.runner(("git", "ls-remote", remote, ref), repo, ())
        if code != 0:
            return ProviderReadback("unknown", receipt.operation_id, None, {"ref": ref})
        observed = None
        for line in output.splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[1] == ref and _EXACT_SHA.fullmatch(fields[0]):
                observed = fields[0]
                break
        status = "succeeded" if observed == receipt.submitted_sha else "failed"
        return ProviderReadback(
            status,
            receipt.operation_id,
            observed,
            {"remote": remote, "ref": ref},
        )


class _HttpAdapter:
    action = ""
    token_prefix = "Bearer"
    credential_prefix = ""

    def __init__(self, transport: HttpTransport | None = None) -> None:
        self.transport = transport or UrllibTransport()

    def _token(self, context: AdapterContext) -> str:
        name = _config_string(context, "token_env")
        if not self.credential_prefix or not name.startswith(self.credential_prefix):
            raise AdapterError(
                f"{self.action} token_env must use a {self.credential_prefix} variable"
            )
        token = os.environ.get(name)
        if not token:
            raise AdapterError(f"credential environment variable {name} is not set")
        return token

    def _headers(self, context: AdapterContext) -> dict[str, str]:
        return {"Authorization": f"{self.token_prefix} {self._token(context)}"}

    @staticmethod
    def _base(context: AdapterContext, expected: str) -> str:
        configured = context.config.get("api_base")
        if configured is None:
            return expected
        if not isinstance(configured, str) or configured.rstrip("/") != expected:
            raise AdapterError("typed HTTP adapters only connect to their official provider API")
        return expected

    @staticmethod
    def _require_success(response: HttpResponse, operation: str) -> None:
        if not 200 <= response.status < 300:
            raise AdapterError(f"{operation} failed with status {response.status}")


class RenderAdapter(_HttpAdapter):
    action = "render.deploy"
    credential_prefix = "RENDER_"

    def check(self, context: AdapterContext) -> ConnectionCheck:
        configured_service_id = _config_string(context, "service_id")
        service_id = quote(configured_service_id, safe="")
        base = self._base(context, "https://api.render.com/v1")
        response = self.transport.request(
            "GET", f"{base}/services/{service_id}", headers=self._headers(context)
        )
        self._require_success(response, "Render connection verification")
        identity = response.payload.get("id")
        if not isinstance(identity, str) or identity != configured_service_id:
            raise AdapterError("Render connection verification returned a different service id")
        return ConnectionCheck(
            "verified",
            context.provider,
            self.action,
            identity,
            {"service_id": service_id, "http_status": response.status},
        )

    def execute(self, context: AdapterContext) -> MutationReceipt:
        service_id = quote(_config_string(context, "service_id"), safe="")
        base = self._base(context, "https://api.render.com/v1")
        response = self.transport.request(
            "POST",
            f"{base}/services/{service_id}/deploys",
            headers=self._headers(context),
            body={
                "clearCache": str(context.config.get("clear_cache", "do_not_clear")),
                "commitId": context.source_sha,
            },
        )
        self._require_success(response, "Render deploy creation")
        operation_id = response.payload.get("id")
        if not isinstance(operation_id, str) or not operation_id:
            raise AdapterError("Render response omitted deploy id")
        return MutationReceipt(
            context.provider,
            self.action,
            operation_id,
            context.source_sha,
            {"service_id": service_id, "http_status": response.status},
        )

    def readback(
        self, context: AdapterContext, receipt: MutationReceipt
    ) -> ProviderReadback:
        service_id = quote(_config_string(context, "service_id"), safe="")
        base = self._base(context, "https://api.render.com/v1")
        response = self.transport.request(
            "GET",
            f"{base}/services/{service_id}/deploys/{quote(receipt.operation_id, safe='')}",
            headers=self._headers(context),
        )
        self._require_success(response, "Render deploy readback")
        commit = response.payload.get("commit")
        observed = commit.get("id") if isinstance(commit, dict) else None
        provider_status = response.payload.get("status")
        if provider_status == "live" and observed == receipt.submitted_sha:
            status = "succeeded"
        elif provider_status in {"build_failed", "update_failed", "canceled"}:
            status = "failed"
        else:
            status = "pending"
        return ProviderReadback(
            status,
            receipt.operation_id,
            observed if isinstance(observed, str) else None,
            {"service_id": service_id, "provider_status": provider_status},
        )


class VercelAdapter(_HttpAdapter):
    action = "vercel.deploy"
    credential_prefix = "VERCEL_"

    def check(self, context: AdapterContext) -> ConnectionCheck:
        configured_project = _config_string(context, "project")
        project = quote(configured_project, safe="")
        base = self._base(context, "https://api.vercel.com")
        team_id = context.config.get("team_id")
        suffix = f"?teamId={quote(str(team_id), safe='')}" if team_id else ""
        response = self.transport.request(
            "GET", f"{base}/v9/projects/{project}{suffix}", headers=self._headers(context)
        )
        self._require_success(response, "Vercel connection verification")
        identity = response.payload.get("id")
        returned_name = response.payload.get("name")
        if (
            not isinstance(identity, str)
            or configured_project
            not in {identity, returned_name if isinstance(returned_name, str) else None}
        ):
            raise AdapterError("Vercel connection verification returned a different project")
        if team_id and response.payload.get("accountId") != str(team_id):
            raise AdapterError("Vercel connection verification returned a different team")
        return ConnectionCheck(
            "verified",
            context.provider,
            self.action,
            identity,
            {"project": project, "http_status": response.status},
        )

    def execute(self, context: AdapterContext) -> MutationReceipt:
        project = _config_string(context, "project")
        repo_id = context.config.get("repo_id")
        if not isinstance(repo_id, (str, int)):
            raise AdapterError("vercel.deploy requires repo_id")
        base = self._base(context, "https://api.vercel.com")
        team_id = context.config.get("team_id")
        suffix = f"?teamId={quote(str(team_id), safe='')}" if team_id else ""
        response = self.transport.request(
            "POST",
            f"{base}/v13/deployments{suffix}",
            headers=self._headers(context),
            body={
                "name": project,
                "target": str(context.config.get("target", "production")),
                "gitSource": {
                    "type": str(context.config.get("git_type", "github")),
                    "repoId": repo_id,
                    "ref": context.source_sha,
                    "sha": context.source_sha,
                },
            },
        )
        self._require_success(response, "Vercel deploy creation")
        operation_id = response.payload.get("id")
        if not isinstance(operation_id, str) or not operation_id:
            raise AdapterError("Vercel response omitted deployment id")
        return MutationReceipt(
            context.provider,
            self.action,
            operation_id,
            context.source_sha,
            {"project": project, "http_status": response.status},
        )

    def readback(
        self, context: AdapterContext, receipt: MutationReceipt
    ) -> ProviderReadback:
        base = self._base(context, "https://api.vercel.com")
        team_id = context.config.get("team_id")
        suffix = f"?teamId={quote(str(team_id), safe='')}" if team_id else ""
        response = self.transport.request(
            "GET",
            f"{base}/v13/deployments/{quote(receipt.operation_id, safe='')}{suffix}",
            headers=self._headers(context),
        )
        self._require_success(response, "Vercel deploy readback")
        source = response.payload.get("gitSource")
        observed = source.get("sha") if isinstance(source, dict) else None
        provider_status = response.payload.get("readyState")
        if provider_status == "READY" and observed == receipt.submitted_sha:
            status = "succeeded"
        elif provider_status in {"ERROR", "CANCELED"}:
            status = "failed"
        else:
            status = "pending"
        return ProviderReadback(
            status,
            receipt.operation_id,
            observed if isinstance(observed, str) else None,
            {"provider_status": provider_status},
        )


class HerokuBuildAdapter(_HttpAdapter):
    action = "heroku.build"
    token_prefix = "Bearer"
    credential_prefix = "HEROKU_"

    def check(self, context: AdapterContext) -> ConnectionCheck:
        configured_app = _config_string(context, "app")
        app = quote(configured_app, safe="")
        base = self._base(context, "https://api.heroku.com")
        response = self.transport.request(
            "GET", f"{base}/apps/{app}", headers=self._headers(context)
        )
        self._require_success(response, "Heroku connection verification")
        identity = response.payload.get("id")
        returned_name = response.payload.get("name")
        if (
            not isinstance(identity, str)
            or configured_app
            not in {identity, returned_name if isinstance(returned_name, str) else None}
        ):
            raise AdapterError("Heroku connection verification returned a different app")
        return ConnectionCheck(
            "verified",
            context.provider,
            self.action,
            identity,
            {"app": app, "http_status": response.status},
        )

    def _headers(self, context: AdapterContext) -> dict[str, str]:
        return {
            **super()._headers(context),
            "Accept": "application/vnd.heroku+json; version=3",
        }

    def execute(self, context: AdapterContext) -> MutationReceipt:
        app = quote(_config_string(context, "app"), safe="")
        blob_env = _config_string(context, "source_blob_url_env")
        if not blob_env.startswith("HEROKU_"):
            raise AdapterError("heroku.build source_blob_url_env must use a HEROKU_ variable")
        source_url = os.environ.get(blob_env)
        if not source_url:
            raise AdapterError(f"credential environment variable {blob_env} is not set")
        base = self._base(context, "https://api.heroku.com")
        response = self.transport.request(
            "POST",
            f"{base}/apps/{app}/builds",
            headers=self._headers(context),
            body={"source_blob": {"url": source_url, "version": context.source_sha}},
        )
        self._require_success(response, "Heroku build creation")
        operation_id = response.payload.get("id")
        if not isinstance(operation_id, str) or not operation_id:
            raise AdapterError("Heroku response omitted build id")
        return MutationReceipt(
            context.provider,
            self.action,
            operation_id,
            context.source_sha,
            {"app": app, "http_status": response.status},
        )

    def readback(
        self, context: AdapterContext, receipt: MutationReceipt
    ) -> ProviderReadback:
        app = quote(_config_string(context, "app"), safe="")
        base = self._base(context, "https://api.heroku.com")
        response = self.transport.request(
            "GET",
            f"{base}/apps/{app}/builds/{quote(receipt.operation_id, safe='')}",
            headers=self._headers(context),
        )
        self._require_success(response, "Heroku build readback")
        source_blob = response.payload.get("source_blob")
        observed = source_blob.get("version") if isinstance(source_blob, dict) else None
        provider_status = response.payload.get("status")
        if provider_status == "succeeded" and observed == receipt.submitted_sha:
            status = "succeeded"
        elif provider_status == "failed":
            status = "failed"
        else:
            status = "pending"
        return ProviderReadback(
            status,
            receipt.operation_id,
            observed if isinstance(observed, str) else None,
            {"app": app, "provider_status": provider_status},
        )


@dataclass
class BuzzWorkflowAdapter:
    runner: CommandRunner = _default_command_runner
    action: str = "buzz.workflow"

    def check(self, context: AdapterContext) -> ConnectionCheck:
        workflow = _config_string(context, "workflow_id")
        code, output = self.runner(
            (
                "buzz",
                "--format",
                "json",
                "workflows",
                "get",
                "--workflow",
                workflow,
            ),
            Path.cwd(),
            ("BUZZ_PRIVATE_KEY", "BUZZ_AUTH_TAG", "BUZZ_RELAY_URL"),
        )
        if code != 0:
            raise AdapterError("Buzz workflow verification failed")
        try:
            payload = json.loads(output)
        except json.JSONDecodeError as exc:
            raise AdapterError("Buzz workflow verification returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise AdapterError("Buzz workflow verification returned invalid data")
        identity = payload.get("id", payload.get("workflow_id"))
        if identity != workflow:
            raise AdapterError("Buzz workflow verification returned a different workflow")
        return ConnectionCheck(
            "verified",
            context.provider,
            self.action,
            workflow,
            {"workflow_id": workflow},
        )

    def execute(self, context: AdapterContext) -> MutationReceipt:
        workflow = _config_string(context, "workflow_id")
        inputs = {"shipyard_candidate_sha": context.source_sha, "run_id": context.run_id}
        code, output = self.runner(
            (
                "buzz",
                "--format",
                "json",
                "workflows",
                "trigger",
                "--workflow",
                workflow,
                "--inputs",
                json.dumps(inputs, separators=(",", ":")),
            ),
            Path.cwd(),
            ("BUZZ_PRIVATE_KEY", "BUZZ_AUTH_TAG", "BUZZ_RELAY_URL"),
        )
        if code != 0:
            raise AdapterError("Buzz workflow trigger failed; outcome requires readback")
        try:
            payload = json.loads(output)
        except json.JSONDecodeError as exc:
            raise AdapterError("Buzz workflow trigger returned invalid JSON") from exc
        operation_id = payload.get("id") or payload.get("run_id")
        if not isinstance(operation_id, str):
            raise AdapterError("Buzz workflow trigger omitted run id")
        return MutationReceipt(
            context.provider,
            self.action,
            operation_id,
            context.source_sha,
            {"workflow_id": workflow},
        )

    def readback(
        self, context: AdapterContext, receipt: MutationReceipt
    ) -> ProviderReadback:
        workflow = _config_string(context, "workflow_id")
        code, output = self.runner(
            (
                "buzz",
                "--format",
                "json",
                "workflows",
                "runs",
                "--workflow",
                workflow,
                "--limit",
                "100",
            ),
            Path.cwd(),
            ("BUZZ_PRIVATE_KEY", "BUZZ_AUTH_TAG", "BUZZ_RELAY_URL"),
        )
        if code != 0:
            return ProviderReadback("unknown", receipt.operation_id, None, {})
        try:
            payload = json.loads(output)
        except json.JSONDecodeError:
            return ProviderReadback("unknown", receipt.operation_id, None, {})
        rows = (
            payload.get("items", payload.get("runs", []))
            if isinstance(payload, dict)
            else payload
        )
        if not isinstance(rows, list):
            rows = []
        match = next(
            (
                row
                for row in rows
                if isinstance(row, dict)
                and (
                    row.get("id") == receipt.operation_id
                    or row.get("run_id") == receipt.operation_id
                )
            ),
            None,
        )
        if match is None:
            return ProviderReadback("unknown", receipt.operation_id, None, {})
        provider_status = str(match.get("status", "unknown")).lower()
        status_map: dict[str, AdapterStatus] = {
            "succeeded": "succeeded",
            "completed": "succeeded",
            "failed": "failed",
            "cancelled": "failed",
            "canceled": "failed",
            "running": "pending",
            "queued": "pending",
            "pending": "pending",
        }
        status = status_map.get(provider_status, "unknown")
        inputs = match.get("inputs")
        observed = inputs.get("shipyard_candidate_sha") if isinstance(inputs, dict) else None
        if status == "succeeded" and observed != receipt.submitted_sha:
            status = "failed"
        return ProviderReadback(
            status,
            receipt.operation_id,
            observed if isinstance(observed, str) else None,
            {"workflow_id": workflow, "provider_status": provider_status},
        )
