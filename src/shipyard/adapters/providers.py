from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote, urlsplit

from ..runtime import resolve_executable, sanitized_environment
from ..safe_files import SafeFileError, copy_private_regular
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
_CANDIDATE_TAG_TEMPLATE = re.compile(
    r"^refs/tags/[A-Za-z0-9][A-Za-z0-9._/-]*-\{source_sha\}$"
)
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

    @staticmethod
    def _allowed_env(context: AdapterContext) -> tuple[str, ...]:
        return (
            ("NOSTR_PRIVATE_KEY", "BUZZ_AUTH_TAG")
            if context.provider == "buzz-git"
            else ()
        )

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
        self._tag_kind(context, ref)
        return remote, ref, repo

    @staticmethod
    def _tag_kind(context: AdapterContext, ref: str) -> str:
        value = context.config.get("tag_kind", "lightweight")
        if not isinstance(value, str) or value not in {"lightweight", "annotated"}:
            raise AdapterError("git.ref tag_kind must be lightweight or annotated")
        if value == "annotated" and (
            context.provider != "github"
            or ref != f"refs/tags/shipyard-candidate-{context.source_sha}"
        ):
            raise AdapterError(
                "git.ref annotated mode requires an exact GitHub annotated candidate tag"
            )
        return value

    @staticmethod
    def _remote_refs(output: str) -> dict[str, str]:
        result: dict[str, str] = {}
        for line in output.splitlines():
            if "\t" not in line:
                continue
            fields = line.split("\t")
            if (
                len(fields) != 2
                or _EXACT_SHA.fullmatch(fields[0]) is None
                or fields[1] in result
            ):
                raise AdapterError("Git remote verification returned malformed identity")
            result[fields[1]] = fields[0]
        return result

    @contextmanager
    def _buzz_command_prefix(
        self, context: AdapterContext, remote: str, repo: Path
    ):
        code, output = self.runner(
            ("git", "remote", "get-url", "--all", remote), repo, ()
        )
        urls = [line.strip() for line in output.splitlines() if line.strip()]
        if code != 0 or len(urls) != 1:
            raise AdapterError("git connection verification requires a configured named remote")
        parsed = urlsplit(urls[0])
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise AdapterError("buzz-git requires one credential-free HTTPS remote")
        try:
            port = parsed.port
        except ValueError as exc:
            raise AdapterError("buzz-git remote HTTPS authority is invalid") from exc
        host = parsed.hostname.lower()
        if ":" in host:
            host = f"[{host}]"
        authority = f"{host}:{port}" if port is not None else host
        options = [
            "git",
            "-c",
            "credential.helper=",
            "-c",
            f"credential.https://{authority}.helper=",
            "-c",
            f"credential.https://{authority}.helper=nostr",
            "-c",
            f"credential.https://{authority}.useHttpPath=true",
        ]
        if os.environ.get("NOSTR_PRIVATE_KEY"):
            yield tuple(options)
            return
        code, output = self.runner(
            ("git", "config", "--get", "nostr.keyfile"), repo, ()
        )
        keyfiles = [line.strip() for line in output.splitlines() if line.strip()]
        if code != 0 or len(keyfiles) != 1:
            raise AdapterError("Buzz Nostr private key source is unavailable")
        keyfile = Path(keyfiles[0]).expanduser()
        if not keyfile.is_absolute():
            raise AdapterError("Buzz Nostr keyfile must be absolute")
        with TemporaryDirectory(prefix="shipyard-buzz-auth-") as temporary:
            private_copy = Path(temporary).resolve(strict=True) / "nostr.key"
            try:
                copy_private_regular(keyfile, private_copy)
            except SafeFileError as exc:
                raise AdapterError("Buzz Nostr keyfile is unsafe") from exc
            yield (*options, "-c", f"nostr.keyfile={private_copy}")

    @contextmanager
    def _git_command_prefix(
        self, context: AdapterContext, remote: str, repo: Path
    ):
        if context.provider == "buzz-git":
            with self._buzz_command_prefix(context, remote, repo) as command:
                yield command
        else:
            yield ("git",)

    def check(self, context: AdapterContext) -> ConnectionCheck:
        remote, ref, repo = self._parameters(context)
        tag_kind = self._tag_kind(context, ref)
        with self._git_command_prefix(context, remote, repo) as command:
            if context.provider != "buzz-git":
                remote_code, _remote_output = self.runner(
                    (*command, "remote", "get-url", "--", remote),
                    repo,
                    self._allowed_env(context),
                )
                if remote_code != 0:
                    raise AdapterError(
                        "git connection verification requires a configured named remote"
                    )
            code, output = self.runner(
                (
                    *command,
                    "ls-remote",
                    remote,
                    ref,
                    *([f"{ref}^{{}}"] if tag_kind == "annotated" else []),
                ),
                repo,
                self._allowed_env(context),
            )
        if code != 0:
            raise AdapterError("Git remote verification failed")
        refs = self._remote_refs(output)
        observed = refs.get(ref)
        if tag_kind == "annotated":
            peeled = refs.get(f"{ref}^{{}}")
            if observed is None and peeled is None:
                return ConnectionCheck(
                    "verified",
                    context.provider,
                    self.action,
                    ref,
                    {
                        "remote": remote,
                        "ref": ref,
                        "tag_kind": tag_kind,
                        "ref_exists": False,
                    },
                )
            if observed is None or peeled != context.source_sha or observed == peeled:
                raise AdapterError(
                    "Git remote candidate tag is not an exact annotated source tag"
                )
            return ConnectionCheck(
                "verified",
                context.provider,
                self.action,
                peeled,
                {
                    "remote": remote,
                    "ref": ref,
                    "tag_kind": tag_kind,
                    "tag_object_sha": observed,
                    "ref_exists": True,
                },
            )
        if observed is None:
            return ConnectionCheck(
                "verified",
                context.provider,
                self.action,
                ref,
                {
                    "remote": remote,
                    "ref": ref,
                    "tag_kind": tag_kind,
                    "ref_exists": False,
                },
            )
        return ConnectionCheck(
            "verified",
            context.provider,
            self.action,
            observed,
            {"remote": remote, "ref": ref, "tag_kind": tag_kind, "ref_exists": True},
        )

    def execute(self, context: AdapterContext) -> MutationReceipt:
        remote, ref, repo = self._parameters(context)
        tag_kind = self._tag_kind(context, ref)
        tag_object_sha: str | None = None
        code = 0
        if tag_kind == "annotated":
            check = self.check(context)
            existing = check.evidence.get("ref_exists")
            existing_object = check.evidence.get("tag_object_sha")
            if existing is True:
                if not isinstance(existing_object, str):
                    raise AdapterError("annotated candidate tag preflight omitted object identity")
                tag_object_sha = existing_object
            else:
                remote_code, remote_output = self.runner(
                    ("git", "remote", "get-url", "--all", remote), repo, ()
                )
                remote_urls = [line for line in remote_output.splitlines() if line]
                if remote_code != 0 or len(remote_urls) != 1:
                    raise AdapterError(
                        "annotated candidate tag requires exactly one configured remote URL"
                    )
                with TemporaryDirectory(prefix="shipyard-annotated-tag-") as temporary:
                    clone = Path(temporary) / "repository"
                    commands = [
                        (
                            "git",
                            "clone",
                            "--local",
                            "--no-hardlinks",
                            "--no-checkout",
                            "--",
                            str(repo),
                            str(clone),
                        ),
                        ("git", "remote", "remove", "origin"),
                        ("git", "remote", "add", remote, remote_urls[0]),
                        (
                            "git",
                            "-c",
                            "user.name=Shipyard Release",
                            "-c",
                            "user.email=release@shipyard.invalid",
                            "-c",
                            "tag.gpgSign=false",
                            "tag",
                            "--annotate",
                            "--message",
                            f"Shipyard candidate {context.source_sha}",
                            ref.removeprefix("refs/tags/"),
                            context.source_sha,
                        ),
                    ]
                    for index, command_parts in enumerate(commands):
                        cwd = repo if index == 0 else clone
                        code, _output = self.runner(command_parts, cwd, ())
                        if code != 0:
                            raise AdapterError(
                                "isolated annotated candidate tag preparation failed"
                            )
                    code, output = self.runner(
                        ("git", "rev-parse", ref, f"{ref}^{{}}"), clone, ()
                    )
                    identities = output.splitlines()
                    if (
                        code != 0
                        or len(identities) != 2
                        or _EXACT_SHA.fullmatch(identities[0]) is None
                        or identities[1] != context.source_sha
                        or identities[0] == identities[1]
                    ):
                        raise AdapterError(
                            "isolated annotated candidate tag identity is invalid"
                        )
                    tag_object_sha = identities[0]
                    code, _output = self.runner(
                        ("git", "push", "--porcelain", remote, f"{ref}:{ref}"),
                        clone,
                        (),
                    )
                if code != 0:
                    raise AdapterError(
                        "annotated candidate tag push failed; provider outcome requires readback"
                    )
        else:
            with self._git_command_prefix(context, remote, repo) as command:
                code, _output = self.runner(
                    (*command, "push", "--porcelain", remote, f"{context.source_sha}:{ref}"),
                    repo,
                    self._allowed_env(context),
                )
        if code != 0:
            raise AdapterError("exact-ref git push failed; provider outcome requires readback")
        operation_id = _operation_id("git", remote, ref, context.source_sha)
        return MutationReceipt(
            provider=context.provider,
            action=self.action,
            operation_id=operation_id,
            submitted_sha=context.source_sha,
            evidence={
                "remote": remote,
                "ref": ref,
                "tag_kind": tag_kind,
                **({"tag_object_sha": tag_object_sha} if tag_object_sha is not None else {}),
            },
        )

    def readback(
        self, context: AdapterContext, receipt: MutationReceipt
    ) -> ProviderReadback:
        remote, ref, repo = self._parameters(context)
        tag_kind = self._tag_kind(context, ref)
        expected_operation = _operation_id("git", remote, ref, context.source_sha)
        receipt_kind = receipt.evidence.get("tag_kind")
        expected_object = receipt.evidence.get("tag_object_sha")
        if (
            receipt.provider != context.provider
            or receipt.action != self.action
            or receipt.operation_id != expected_operation
            or receipt.submitted_sha != context.source_sha
            or receipt.evidence.get("remote", remote) != remote
            or receipt.evidence.get("ref", ref) != ref
            or (
                receipt_kind is not None
                and (not isinstance(receipt_kind, str) or receipt_kind != tag_kind)
            )
            or (
                tag_kind == "annotated"
                and (
                    not isinstance(expected_object, str)
                    or _EXACT_SHA.fullmatch(expected_object) is None
                )
            )
        ):
            return ProviderReadback(
                "failed", receipt.operation_id, None, {"identity_match": False}
            )
        with self._git_command_prefix(context, remote, repo) as command:
            code, output = self.runner(
                (
                    *command,
                    "ls-remote",
                    remote,
                    ref,
                    *([f"{ref}^{{}}"] if tag_kind == "annotated" else []),
                ),
                repo,
                self._allowed_env(context),
            )
        if code != 0:
            return ProviderReadback("unknown", receipt.operation_id, None, {"ref": ref})
        try:
            refs = self._remote_refs(output)
        except AdapterError:
            return ProviderReadback("failed", receipt.operation_id, None, {"ref": ref})
        tag_object_sha = refs.get(ref)
        observed = (
            refs.get(f"{ref}^{{}}") if tag_kind == "annotated" else tag_object_sha
        )
        object_matches = (
            tag_kind != "annotated"
            or (
                isinstance(expected_object, str)
                and tag_object_sha == expected_object
                and tag_object_sha != observed
            )
        )
        status = (
            "succeeded"
            if observed == receipt.submitted_sha and object_matches
            else "failed"
        )
        return ProviderReadback(
            status,
            receipt.operation_id,
            observed,
            {
                "remote": remote,
                "ref": ref,
                "tag_kind": tag_kind,
                **({"tag_object_sha": tag_object_sha} if tag_object_sha is not None else {}),
            },
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


class GitHubWorkflowAdapter(_HttpAdapter):
    action = "github.workflow"
    credential_prefix = "GITHUB_"

    def _headers(self, context: AdapterContext) -> dict[str, str]:
        return {
            **super()._headers(context),
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
        }

    @staticmethod
    def _coordinates(context: AdapterContext) -> tuple[str, str, str, str, str, str]:
        owner = _config_string(context, "owner")
        repo = _config_string(context, "repo")
        repository_id = _config_string(context, "repository_id")
        workflow_id = _config_string(context, "workflow_id")
        workflow_file = _config_string(context, "workflow_file")
        ref = _config_string(context, "ref")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", owner):
            raise AdapterError("github.workflow owner is invalid")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", repo):
            raise AdapterError("github.workflow repository is invalid")
        if not repository_id.isdecimal() or not workflow_id.isdecimal():
            raise AdapterError("github.workflow requires numeric repository and workflow ids")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\.ya?ml", workflow_file):
            raise AdapterError("github.workflow requires a workflow .yml or .yaml file name")
        if (
            not (_EXACT_REF.fullmatch(ref) or _CANDIDATE_TAG_TEMPLATE.fullmatch(ref))
            or ".." in ref
            or ref.endswith("/")
        ):
            raise AdapterError(
                "github.workflow requires a canonical refs/heads/* or refs/tags/* ref"
            )
        return owner, repo, repository_id, workflow_id, workflow_file, ref

    def _identity(
        self, context: AdapterContext
    ) -> tuple[str, str, str, str, str, str, dict[str, object]]:
        owner, repo, repository_id, workflow_id, workflow_file, ref = self._coordinates(context)
        base = self._base(context, "https://api.github.com")
        repository = self.transport.request(
            "GET",
            f"{base}/repos/{quote(owner, safe='')}/{quote(repo, safe='')}",
            headers=self._headers(context),
        )
        self._require_success(repository, "GitHub repository verification")
        if str(repository.payload.get("id")) != repository_id:
            raise AdapterError("GitHub repository verification returned a different repository id")
        expected_name = f"{owner}/{repo}"
        full_name = repository.payload.get("full_name")
        if not isinstance(full_name, str) or full_name.casefold() != expected_name.casefold():
            raise AdapterError("GitHub repository verification returned a different repository")
        workflow = self.transport.request(
            "GET",
            f"{base}/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
            f"/actions/workflows/{quote(workflow_id, safe='')}",
            headers=self._headers(context),
        )
        self._require_success(workflow, "GitHub workflow verification")
        if str(workflow.payload.get("id")) != workflow_id:
            raise AdapterError("GitHub workflow verification returned a different workflow id")
        expected_path = f".github/workflows/{workflow_file}"
        if workflow.payload.get("path") != expected_path:
            raise AdapterError("GitHub workflow verification returned a different workflow file")
        if workflow.payload.get("state") != "active":
            raise AdapterError("GitHub workflow is not active")
        return owner, repo, repository_id, workflow_id, workflow_file, ref, workflow.payload

    def check(self, context: AdapterContext) -> ConnectionCheck:
        owner, repo, repository_id, workflow_id, workflow_file, ref, _ = self._identity(context)
        return ConnectionCheck(
            "verified",
            context.provider,
            self.action,
            f"{repository_id}:{workflow_id}",
            {
                "repository": f"{owner}/{repo}",
                "workflow_file": workflow_file,
                "ref": ref,
            },
        )

    @staticmethod
    def _dispatch_ref(ref: str) -> str:
        for prefix in ("refs/heads/", "refs/tags/"):
            if ref.startswith(prefix):
                return ref.removeprefix(prefix)
        raise AdapterError("github.workflow requires a branch or tag ref")

    @staticmethod
    def _require_immutable_candidate_tag(ref: str, source_sha: str) -> None:
        expected_suffix = f"-{source_sha}"
        if not ref.startswith("refs/tags/") or not ref.endswith(expected_suffix):
            raise AdapterError(
                "github.workflow requires an immutable candidate tag ending in the approved SHA"
            )

    @staticmethod
    def _resolved_context(context: AdapterContext) -> AdapterContext:
        configured_ref = _config_string(context, "ref")
        resolved_ref = configured_ref.replace("{source_sha}", context.source_sha)
        return replace(context, config={**context.config, "ref": resolved_ref})

    def execute(self, context: AdapterContext) -> MutationReceipt:
        resolved_context = self._resolved_context(context)
        configured_ref = _config_string(resolved_context, "ref")
        self._require_immutable_candidate_tag(configured_ref, context.source_sha)
        owner, repo, repository_id, workflow_id, workflow_file, ref, _ = self._identity(
            resolved_context
        )
        dispatch_ref = self._dispatch_ref(ref)
        base = self._base(context, "https://api.github.com")
        commit = self.transport.request(
            "GET",
            f"{base}/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
            f"/commits/{quote(dispatch_ref, safe='')}",
            headers=self._headers(context),
        )
        self._require_success(commit, "GitHub workflow ref verification")
        if commit.payload.get("sha") != context.source_sha:
            raise AdapterError("GitHub workflow ref does not resolve to the approved source SHA")
        response = self.transport.request(
            "POST",
            f"{base}/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
            f"/actions/workflows/{quote(workflow_id, safe='')}/dispatches",
            headers=self._headers(context),
            body={
                "ref": dispatch_ref,
                "inputs": {
                    "shipyard_candidate_sha": context.source_sha,
                    "shipyard_run_id": context.run_id,
                },
                "return_run_details": True,
            },
        )
        if response.status != 200:
            raise AdapterError(
                "GitHub workflow dispatch did not return a durable run id; "
                "outcome requires readback"
            )
        operation_id = response.payload.get("workflow_run_id")
        if not isinstance(operation_id, int) or isinstance(operation_id, bool):
            raise AdapterError("GitHub workflow dispatch omitted workflow run id")
        return MutationReceipt(
            context.provider,
            self.action,
            str(operation_id),
            context.source_sha,
            {
                "repository_id": repository_id,
                "workflow_id": workflow_id,
                "workflow_file": workflow_file,
                "ref": ref,
                "html_url": response.payload.get("html_url"),
            },
        )

    def readback(
        self, context: AdapterContext, receipt: MutationReceipt
    ) -> ProviderReadback:
        context = self._resolved_context(context)
        owner, repo, repository_id, workflow_id, workflow_file, ref = self._coordinates(
            context
        )
        base = self._base(context, "https://api.github.com")
        response = self.transport.request(
            "GET",
            f"{base}/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
            f"/actions/runs/{quote(receipt.operation_id, safe='')}",
            headers=self._headers(context),
        )
        self._require_success(response, "GitHub workflow run readback")
        payload = response.payload
        observed = payload.get("head_sha")
        repository = payload.get("repository")
        observed_repository_id = (
            str(repository.get("id")) if isinstance(repository, dict) else None
        )
        identity_matches = (
            str(payload.get("id")) == receipt.operation_id
            and str(payload.get("workflow_id")) == workflow_id
            and observed_repository_id == repository_id
            and payload.get("event") == "workflow_dispatch"
        )
        provider_status = payload.get("status")
        conclusion = payload.get("conclusion")
        if not identity_matches or observed != receipt.submitted_sha:
            status: AdapterStatus = "failed"
        elif provider_status == "completed" and conclusion != "success":
            status = "failed"
        elif provider_status == "completed" and conclusion == "success":
            status = "succeeded"
        elif provider_status in {
            "queued",
            "in_progress",
            "pending",
            "requested",
            "waiting",
        }:
            status = "pending"
        else:
            status = "unknown"
        return ProviderReadback(
            status,
            receipt.operation_id,
            observed if isinstance(observed, str) else None,
            {
                "repository": f"{owner}/{repo}",
                "workflow_file": workflow_file,
                "ref": ref,
                "provider_status": provider_status,
                "conclusion": conclusion,
                "html_url": payload.get("html_url"),
            },
        )


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
