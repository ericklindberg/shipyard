from __future__ import annotations

import hashlib
import re
import tomllib
from pathlib import Path
from typing import Any

from .models import ArtifactSpec, Playbook, Step
from .redact import redact_argv


class PlaybookError(ValueError):
    pass


_ID = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_NAMED_GIT_REMOTE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_EFFECTS = {"verify", "build", "external"}
_GIT_GLOBAL_OPTIONS_WITH_VALUE = {
    "-C",
    "-c",
    "--config-env",
    "--git-dir",
    "--namespace",
    "--super-prefix",
    "--work-tree",
}
_GIT_GLOBAL_FLAGS = {
    "--bare",
    "--glob-pathspecs",
    "--help",
    "--html-path",
    "--icase-pathspecs",
    "--info-path",
    "--literal-pathspecs",
    "--man-path",
    "--no-optional-locks",
    "--no-pager",
    "--no-replace-objects",
    "--noglob-pathspecs",
    "--paginate",
    "--version",
    "-P",
    "-p",
}
_PACKAGE_RUNNER_OPTIONS_WITH_VALUE = {
    "--cache",
    "--package",
    "--registry",
    "--userconfig",
    "-p",
}
_SAFE_GIT_SUBCOMMANDS = {
    "cat-file",
    "check-attr",
    "check-ignore",
    "check-mailmap",
    "check-ref-format",
    "count-objects",
    "describe",
    "diff",
    "diff-index",
    "diff-tree",
    "for-each-ref",
    "fsck",
    "grep",
    "log",
    "ls-files",
    "ls-remote",
    "ls-tree",
    "merge-base",
    "name-rev",
    "rev-list",
    "rev-parse",
    "shortlog",
    "show",
    "show-branch",
    "status",
    "verify-commit",
    "verify-pack",
    "verify-tag",
    "version",
    "whatchanged",
}
_OPAQUE_EXECUTION_WRAPPERS = {"nice", "nohup", "setsid", "stdbuf", "timeout"}
_LOCAL_PYTHON_MODULES = {"build", "compileall", "pytest"}
_LOCAL_EXECUTABLES = {
    "bandit",
    "echo",
    "false",
    "mypy",
    "pyright",
    "pytest",
    "ruff",
    "true",
    "ty",
}
_ADAPTER_ACTIONS = {
    "buzz.workflow",
    "git.ref",
    "heroku.build",
    "render.deploy",
    "vercel.deploy",
}
_ACTION_ENV_PREFIX = {
    "heroku.build": "HEROKU_",
    "render.deploy": "RENDER_",
    "vercel.deploy": "VERCEL_",
}


def _git_subcommand_index(command: tuple[str, ...]) -> int | None:
    if not command or Path(command[0]).name.lower() != "git":
        return None
    index = 1
    while index < len(command):
        token = command[index]
        if token == "--":
            index += 1
            return index if index < len(command) else None
        if token in _GIT_GLOBAL_OPTIONS_WITH_VALUE:
            index += 2
            continue
        if any(
            token.startswith(f"{option}=")
            for option in _GIT_GLOBAL_OPTIONS_WITH_VALUE
            if option.startswith("--")
        ):
            index += 1
            continue
        if token in _GIT_GLOBAL_FLAGS or token.startswith("--exec-path="):
            index += 1
            continue
        if token.startswith("-"):
            return None
        return index
    return None


def _git_subcommand(command: tuple[str, ...]) -> str | None:
    index = _git_subcommand_index(command)
    return command[index].lower() if index is not None else None


def _contains_git_push(command: tuple[str, ...]) -> bool:
    return any(
        Path(token).name.lower() == "git" and _git_subcommand(command[index:]) == "push"
        for index, token in enumerate(command)
    )


def _has_exact_sha_push_refspec(command: tuple[str, ...]) -> bool:
    """Accept one remote plus one exact-SHA destination refspec and nothing mutable."""
    allowed_flags = {
        "--atomic",
        "--dry-run",
        "--porcelain",
        "--quiet",
        "--set-upstream",
        "--verbose",
        "-n",
        "-q",
        "-u",
        "-v",
    }
    for index, token in enumerate(command):
        if Path(token).name.lower() != "git":
            continue
        git_command = command[index:]
        subcommand_index = _git_subcommand_index(git_command)
        if subcommand_index is None or git_command[subcommand_index].lower() != "push":
            continue
        positional: list[str] = []
        for argument in git_command[subcommand_index + 1 :]:
            if argument in allowed_flags:
                continue
            if argument.startswith("-"):
                return False
            positional.append(argument)
        return len(positional) == 2 and bool(
            re.fullmatch(r"\+?\{sha\}:refs/(?:heads|tags)/[^\s:]+", positional[1])
        )
    return False


def _is_external_command(command: tuple[str, ...]) -> bool:
    if not command:
        return False
    executable = Path(command[0]).name.lower()
    args = [part.lower() for part in command[1:]]
    first = args[0] if args else ""
    if executable == "env":
        index = 1
        while (
            index < len(command)
            and "=" in command[index]
            and not command[index].startswith("-")
        ):
            index += 1
        while index < len(command) and command[index] in {
            "-i",
            "--ignore-environment",
            "--",
        }:
            index += 1
        if index < len(command) and command[index].startswith("-"):
            return True
        return _is_external_command(command[index:])
    if executable in _OPAQUE_EXECUTION_WRAPPERS:
        return True
    if executable in {"npx", "bunx"} and len(command) > 1:
        index = 1
        while index < len(command) and command[index].startswith("-"):
            option = command[index]
            if option in _PACKAGE_RUNNER_OPTIONS_WITH_VALUE:
                index += 2
            elif any(
                option.startswith(f"{name}=")
                for name in _PACKAGE_RUNNER_OPTIONS_WITH_VALUE
                if name.startswith("--")
            ) or option in {"--yes", "-y"}:
                index += 1
            else:
                return True
        return _is_external_command(command[index:])
    if executable in {"pnpm", "yarn"} and first in {"dlx", "exec"} and len(command) > 2:
        return _is_external_command(command[2:])
    shell_command = executable in {"bash", "sh", "zsh", "fish"} and any(
        "c" in arg for arg in args if arg.startswith("-")
    )
    if shell_command:
        return True
    if executable in {"sudo", "doas"}:
        return True
    if executable in {"ssh", "scp", "rsync"}:
        return True
    if executable == "git":
        if "-c" in command[1:] or any(
            option == "--config-env"
            or option.startswith("--config-env=")
            or option.startswith("--exec-path=")
            for option in command[1:]
        ):
            return True
        subcommand = _git_subcommand(command)
        return subcommand is not None and subcommand not in _SAFE_GIT_SUBCOMMANDS
    if executable == "gh":
        if first == "pr" and len(args) > 1:
            return any(
                argument in {"create", "merge", "close", "edit", "review", "reopen"}
                for argument in args[1:]
            )
        if first == "workflow" and len(args) > 1:
            return any(
                argument in {"run", "enable", "disable"} for argument in args[1:]
            )
        if first == "run" and len(args) > 1:
            return any(
                argument in {"cancel", "delete", "rerun"} for argument in args[1:]
            )
        if first == "api":
            joined = " ".join(args)
            if any(
                arg in {"-f", "--field", "--raw-field", "--input"}
                or arg.startswith(("-f=", "--field=", "--raw-field=", "--input="))
                for arg in args
            ):
                return True
            return any(
                marker in joined
                for marker in (
                    "--method post",
                    "--method put",
                    "--method patch",
                    "--method delete",
                    "-x post",
                    "-x put",
                    "-x patch",
                    "-x delete",
                )
            ) or any(
                argument.startswith(
                    ("--method=post", "--method=put", "--method=patch", "--method=delete")
                )
                for argument in args
            )
        if first == "repo":
            return len(args) < 2 or args[1] not in {"clone", "list", "view"}
        if first == "auth":
            return len(args) < 2 or args[1] != "status"
        return first not in {"search", "status"}
    if executable == "eas":
        return first not in {
            "branch:list",
            "branch:view",
            "build:list",
            "build:view",
            "channel:list",
            "channel:view",
            "project:info",
            "update:list",
            "update:view",
            "whoami",
        }
    if executable == "systemctl":
        return first not in {
            "cat",
            "help",
            "is-active",
            "is-enabled",
            "list-dependencies",
            "list-sockets",
            "list-timers",
            "list-unit-files",
            "list-units",
            "show",
            "status",
        }
    if executable == "service":
        return not (args == ["--status-all"] or (len(args) == 2 and args[1] == "status"))
    if executable == "curl":
        for index, argument in enumerate(args):
            method: str | None = None
            if argument in {"-x", "--request"} and index + 1 < len(args):
                method = args[index + 1]
            elif argument.startswith("-x") and len(argument) > 2:
                method = argument[2:]
            elif argument.startswith("--request="):
                method = argument.partition("=")[2]
            if method is not None and method not in {"get", "head", "options"}:
                return True
        write_flags = {
            "-d",
            "--data",
            "--data-raw",
            "--data-binary",
            "--data-urlencode",
            "--json",
            "-f",
            "--form",
            "--form-string",
            "-t",
            "--upload-file",
        }
        write_prefixes = (
            "--data=",
            "--data-raw=",
            "--data-binary=",
            "--data-urlencode=",
            "--json=",
            "--form=",
            "--form-string=",
            "--upload-file=",
        )
        if any(
            arg in write_flags or arg.startswith(write_prefixes)
            for arg in args
        ):
            return True
        return any(
            arg.startswith(("-d", "-f", "-t", "-xdelete", "-xpatch", "-xpost", "-xput"))
            or arg.startswith(
                (
                    "--request=delete",
                    "--request=patch",
                    "--request=post",
                    "--request=put",
                )
            )
            for arg in args
        )
    if executable in {"kubectl", "helm"} and first not in {"get", "describe", "diff", "list"}:
        return True
    if executable == "docker":
        if first == "build" and any(
            argument == "--push"
            or argument.startswith("--output=type=registry")
            or argument == "type=registry"
            for argument in args[1:]
        ):
            return True
        return first not in {
            "build",
            "events",
            "history",
            "images",
            "info",
            "inspect",
            "logs",
            "ps",
            "stats",
            "top",
            "version",
        }
    if executable == "npm":
        return first in {
            "access",
            "adduser",
            "deprecate",
            "dist-tag",
            "login",
            "logout",
            "org",
            "owner",
            "publish",
            "star",
            "team",
            "token",
            "unpublish",
            "unstar",
        }
    if executable == "cargo":
        return first in {"login", "owner", "publish", "yank"}
    if executable in {"node", "perl", "python", "python3", "ruby"}:
        if any(argument in {"-c", "-e"} for argument in args):
            return True
        if first == "-m":
            return len(args) < 2 or args[1] not in _LOCAL_PYTHON_MODULES
        return False
    if executable in {"bash", "sh", "zsh", "fish"}:
        return shell_command
    if executable == "uv":
        if first == "build":
            return False
        if first != "run":
            return True
        index = 2
        while index < len(command) and command[index].startswith("-"):
            if command[index] in {"--extra", "--group", "--python"}:
                index += 2
            else:
                index += 1
        return _is_external_command(command[index:])
    if executable == "twine":
        return first == "upload"
    if executable == "terraform":
        return first in {"apply", "destroy", "import"}
    return executable not in _LOCAL_EXECUTABLES


def _uses_env_split_string(command: tuple[str, ...]) -> bool:
    for index, token in enumerate(command):
        if Path(token).name.lower() != "env":
            continue
        return any(
            (
                argument.startswith("-")
                and not argument.startswith("--")
                and "S" in argument[1:]
            )
            or argument == "--split-string"
            or argument.startswith("--split-string=")
            for argument in command[index + 1 :]
        )
    return False


def _require(mapping: dict[str, Any], key: str, expected: type) -> Any:
    value = mapping.get(key)
    if not isinstance(value, expected):
        raise PlaybookError(f"{key} must be {expected.__name__}")
    return value


def load_playbook(path: str | Path) -> Playbook:
    playbook_path = Path(path).expanduser().resolve()
    try:
        raw_bytes = playbook_path.read_bytes()
        data = tomllib.loads(raw_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise PlaybookError(f"cannot load playbook: {exc}") from exc

    schema_version = data.get("schema_version")
    if schema_version not in {1, 2}:
        raise PlaybookError("schema_version must be 1 or 2")
    name = _require(data, "name", str).strip()
    target = _require(data, "target", str).strip()
    provider = data.get("provider", "raw")
    destination = data.get("destination", target)
    if not isinstance(provider, str) or not _ID.fullmatch(provider):
        raise PlaybookError("provider must be a lowercase identifier")
    if not isinstance(destination, str) or not destination.strip():
        raise PlaybookError("destination must be a non-empty string")
    allow_dirty = data.get("allow_dirty", False)
    if not isinstance(allow_dirty, bool):
        raise PlaybookError("allow_dirty must be bool")
    raw_steps = data.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise PlaybookError("steps must be a non-empty array")

    artifacts: list[ArtifactSpec] = []
    raw_artifacts = data.get("artifacts", [])
    if not isinstance(raw_artifacts, list):
        raise PlaybookError("artifacts must be an array")
    for raw_artifact in raw_artifacts:
        if not isinstance(raw_artifact, dict):
            raise PlaybookError("each artifact must be a table")
        artifact_path = _require(raw_artifact, "path", str).strip()
        required = raw_artifact.get("required", True)
        if not artifact_path:
            raise PlaybookError("artifact path must not be empty")
        if not isinstance(required, bool):
            raise PlaybookError("artifact required must be bool")
        artifacts.append(ArtifactSpec(path=artifact_path, required=required))

    seen: set[str] = set()
    steps: list[Step] = []
    for raw_step in raw_steps:
        if not isinstance(raw_step, dict):
            raise PlaybookError("each step must be a table")
        step_id = _require(raw_step, "id", str)
        if not _ID.fullmatch(step_id):
            raise PlaybookError(f"invalid step id: {step_id}")
        if step_id in seen:
            raise PlaybookError(f"duplicate step id: {step_id}")
        seen.add(step_id)
        step_name = _require(raw_step, "name", str).strip()
        effect = _require(raw_step, "effect", str)
        if effect not in _EFFECTS:
            raise PlaybookError(f"invalid effect for {step_id}: {effect}")
        action_value = raw_step.get("action")
        config_value = raw_step.get("config", {})
        if action_value is not None:
            if schema_version != 2:
                raise PlaybookError(f"adapter action for {step_id} requires schema_version 2")
            if not isinstance(action_value, str) or action_value not in _ADAPTER_ACTIONS:
                raise PlaybookError(f"unknown adapter action for {step_id}: {action_value}")
            if effect != "external":
                raise PlaybookError(f"adapter action {step_id} must be marked external")
            if "command" in raw_step:
                raise PlaybookError(f"step {step_id} cannot define both action and command")
            if not isinstance(config_value, dict):
                raise PlaybookError(f"config for {step_id} must be a table")
            for key, value in config_value.items():
                lowered = str(key).lower()
                if any(
                    word in lowered for word in ("token", "secret", "password", "key")
                ) and not lowered.endswith("_env"):
                    raise PlaybookError(
                        f"credential config {key} for {step_id} must name an *_env variable"
                    )
                if not isinstance(value, (str, int, bool)):
                    raise PlaybookError(
                        f"config value {key} for {step_id} must be string, int, or bool"
                    )
                prefix = _ACTION_ENV_PREFIX.get(action_value)
                if (
                    lowered.endswith("_env")
                    and prefix is not None
                    and (not isinstance(value, str) or not value.startswith(prefix))
                ):
                    raise PlaybookError(
                        f"credential config {key} for {step_id} must use a {prefix} variable"
                    )
            if action_value == "git.ref":
                remote = config_value.get("remote", "origin")
                if (
                    not isinstance(remote, str)
                    or not _NAMED_GIT_REMOTE.fullmatch(remote)
                    or ".." in remote
                    or remote.endswith("/")
                ):
                    raise PlaybookError(
                        f"git.ref config for {step_id} must use a named Git remote"
                    )
            command: tuple[str, ...] = ()
        else:
            command_value = raw_step.get("command")
            if (
                not isinstance(command_value, list)
                or not command_value
                or not all(isinstance(part, str) and part for part in command_value)
            ):
                raise PlaybookError(f"command for {step_id} must be a non-empty string array")
            command = tuple(command_value)
            if schema_version == 2 and effect == "external":
                raise PlaybookError(
                    f"schema_version 2 external step {step_id} must use a typed adapter action"
                )
            if _uses_env_split_string(command):
                raise PlaybookError(
                    f"env split-string is not supported in command for {step_id}"
                )
            if redact_argv(command) != command:
                raise PlaybookError(
                    f"secret values may not appear in command for {step_id}; use a credential store"
                )
        timeout = raw_step.get("timeout_seconds", 900)
        if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 7200:
            raise PlaybookError(f"timeout_seconds for {step_id} must be between 1 and 7200")
        if command and effect != "external" and _is_external_command(command):
            raise PlaybookError(f"step {step_id} must be marked external")
        if (
            effect == "external"
            and _contains_git_push(command)
            and not _has_exact_sha_push_refspec(command)
        ):
            raise PlaybookError(
                f"external git push step {step_id} must use the exact {{sha}} placeholder "
                "in one {sha}:refs/heads/... or {sha}:refs/tags/... refspec"
            )
        steps.append(
            Step(
                id=step_id,
                name=step_name,
                effect=effect,  # type: ignore[arg-type]
                command=command,
                timeout_seconds=timeout,
                action=action_value,
                config=dict(config_value),
            )
        )

    if allow_dirty and any(step.effect == "external" for step in steps):
        raise PlaybookError("external steps require a clean source; allow_dirty must be false")

    return Playbook(
        path=playbook_path,
        name=name,
        target=target,
        allow_dirty=allow_dirty,
        digest=hashlib.sha256(raw_bytes).hexdigest(),
        steps=tuple(steps),
        provider=provider,
        destination=destination.strip(),
        artifacts=tuple(artifacts),
        schema_version=schema_version,
    )
