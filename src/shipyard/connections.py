from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

from .adapters.base import DeploymentAdapter
from .runtime import RuntimeIdentityError, resolve_executable, sanitized_environment
from .safe_files import SafeFileError, open_relative_regular


class _AdapterRegistry(Protocol):
    def get(self, action: str) -> DeploymentAdapter: ...


class ConnectionError(RuntimeError):
    pass


_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]*$")
_EXACT_REF = re.compile(r"^refs/(?:heads|tags)/[A-Za-z0-9._/-]+$")
_REMOTE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_RESOURCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
_SCHEMA_VERSION = 1
_PROVIDER_ENV_PREFIX = {
    "github-actions": "GITHUB_",
    "render": "RENDER_",
    "heroku": "HEROKU_",
    "vercel": "VERCEL_",
}
_PROVIDER_RESOURCE_KEYS = {
    "github-actions": (
        "owner",
        "repo",
        "repository_id",
        "workflow_id",
        "workflow_file",
    ),
    "buzz": ("workflow_id",),
    "render": ("service_id",),
    "heroku": ("app",),
    "vercel": ("project", "repo_id", "team_id"),
}

_PROVIDER_ACTIONS = {
    "github": "git.ref",
    "github-actions": "github.workflow",
    "buzz-git": "git.ref",
    "buzz": "buzz.workflow",
    "render": "render.deploy",
    "heroku": "heroku.build",
    "vercel": "vercel.deploy",
}
_PROVIDER_OPTIONS = {
    "github": frozenset({"remote", "ref"}),
    "github-actions": frozenset(
        {
            "owner",
            "repo",
            "repository_id",
            "workflow_id",
            "workflow_file",
            "ref",
            "token_env",
        }
    ),
    "buzz-git": frozenset({"remote", "ref"}),
    "buzz": frozenset({"workflow_id"}),
    "render": frozenset({"service_id", "token_env"}),
    "heroku": frozenset({"app", "token_env", "source_blob_url_env"}),
    "vercel": frozenset({"project", "repo_id", "team_id", "token_env"}),
}
_REQUIRED_OPTIONS = {
    "github": frozenset({"remote", "ref"}),
    "github-actions": frozenset(
        {
            "owner",
            "repo",
            "repository_id",
            "workflow_id",
            "workflow_file",
            "ref",
            "token_env",
        }
    ),
    "buzz-git": frozenset({"remote", "ref"}),
    "buzz": frozenset({"workflow_id"}),
    "render": frozenset({"service_id", "token_env"}),
    "heroku": frozenset({"app", "token_env", "source_blob_url_env"}),
    "vercel": frozenset({"project", "repo_id", "token_env"}),
}
_BUZZ_ENV = ("BUZZ_AUTH_TAG", "BUZZ_PRIVATE_KEY", "BUZZ_RELAY_URL")
_MINIMUM_NIP98_GIT = (2, 46, 0)


def default_config_dir() -> Path:
    configured = os.environ.get("SHIPYARD_CONFIG_DIR")
    if configured:
        return Path(configured).expanduser()
    xdg = os.environ.get("XDG_CONFIG_HOME")
    root = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    return root / "shipyard"


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _require_string(options: dict[str, object], key: str) -> str:
    value = options.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConnectionError(f"connection option {key} must be a non-empty string")
    return value.strip()


def _validate_options(provider: str, raw: dict[str, object]) -> dict[str, object]:
    if provider not in _PROVIDER_ACTIONS:
        raise ConnectionError(f"unsupported provider: {provider}")
    for key in raw:
        lowered = key.lower()
        if any(word in lowered for word in ("token", "secret", "password", "key")) and not (
            lowered.endswith("_env")
        ):
            raise ConnectionError("literal credentials are forbidden; store only *_env references")
    unsupported = set(raw) - _PROVIDER_OPTIONS[provider]
    if unsupported:
        raise ConnectionError(f"unsupported option for {provider}: {sorted(unsupported)[0]}")
    missing = _REQUIRED_OPTIONS[provider] - set(raw)
    if missing:
        raise ConnectionError(f"missing required option for {provider}: {sorted(missing)[0]}")

    options: dict[str, object] = {}
    for key, value in raw.items():
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise ConnectionError(f"connection option {key} must be a scalar value")
        if isinstance(value, int) and not (provider == "vercel" and key == "repo_id"):
            raise ConnectionError(f"connection option {key} must be a string")
        if isinstance(value, str):
            value = value.strip()
            if not value:
                raise ConnectionError(f"connection option {key} must not be empty")
            if any(ord(character) < 32 for character in value):
                raise ConnectionError(f"connection option {key} must be a single-line value")
            if len(value) > 1024:
                raise ConnectionError(f"connection option {key} is too long")
        options[key] = value

    for key in options:
        if key.endswith("_env"):
            env_name = _require_string(options, key)
            if not _ENV_NAME.fullmatch(env_name):
                raise ConnectionError(f"{key} must name an uppercase environment variable")
            prefix = _PROVIDER_ENV_PREFIX.get(provider)
            if prefix is not None and not env_name.startswith(prefix):
                raise ConnectionError(
                    f"{key} for {provider} must use a {prefix} environment variable"
                )
    for key in _PROVIDER_RESOURCE_KEYS.get(provider, ()):
        if key in options and not _RESOURCE_ID.fullmatch(str(options[key])):
            raise ConnectionError(f"{key} must be a conservative provider identifier")
    if provider in {"github", "buzz-git"}:
        remote = _require_string(options, "remote")
        if (
            not _REMOTE_NAME.fullmatch(remote)
            or ".." in remote
            or remote.startswith("/")
        ):
            raise ConnectionError(
                "github remote must be a named Git remote and must not contain embedded credentials"
            )
        ref = _require_string(options, "ref")
        if not _EXACT_REF.fullmatch(ref) or ".." in ref or ref.endswith("/"):
            raise ConnectionError("github ref must be a canonical refs/heads/* or refs/tags/* ref")
    if provider == "github-actions":
        repository_id = _require_string(options, "repository_id")
        workflow_id = _require_string(options, "workflow_id")
        workflow_file = _require_string(options, "workflow_file")
        ref = _require_string(options, "ref")
        if not repository_id.isdecimal() or not workflow_id.isdecimal():
            raise ConnectionError("GitHub Actions repository and workflow ids must be numeric")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\.ya?ml", workflow_file):
            raise ConnectionError("GitHub Actions workflow file must be a .yml or .yaml file name")
        exact_candidate_tag = re.fullmatch(
            r"refs/tags/[A-Za-z0-9][A-Za-z0-9._/-]*-[0-9a-f]{40}", ref
        )
        candidate_tag_template = re.fullmatch(
            r"refs/tags/[A-Za-z0-9][A-Za-z0-9._/-]*-\{source_sha\}", ref
        )
        if ".." in ref or ref.endswith("/") or not (
            exact_candidate_tag or candidate_tag_template
        ):
            raise ConnectionError(
                "GitHub Actions ref must be an immutable candidate tag ending in its "
                "40-character SHA or {source_sha}"
            )
    return options


def _destination(provider: str, options: dict[str, object]) -> str:
    if provider in {"github", "buzz-git"}:
        return f"{provider}:{options['remote']}:{options['ref']}"
    if provider == "buzz":
        return f"buzz:{options['workflow_id']}"
    if provider == "github-actions":
        return (
            f"github-actions:{options['repository_id']}:"
            f"{options['workflow_id']}:{options['ref']}"
        )
    if provider == "render":
        return f"render:{options['service_id']}"
    if provider == "heroku":
        return f"heroku:{options['app']}"
    project = str(options["project"])
    team = options.get("team_id")
    return f"vercel:{team}/{project}" if team else f"vercel:{project}"


@dataclass(frozen=True)
class ConnectionProfile:
    name: str
    provider: str
    action: str
    destination: str
    config: dict[str, object]
    created_at: str
    updated_at: str

    @classmethod
    def create(
        cls,
        name: str,
        provider: str,
        options: dict[str, object],
        *,
        created_at: str | None = None,
        updated_at: str | None = None,
    ) -> ConnectionProfile:
        normalized_name = name.strip()
        if not _NAME.fullmatch(normalized_name):
            raise ConnectionError(
                "connection name must be lowercase letters, numbers, dots, dashes, or underscores"
            )
        normalized_provider = provider.strip().lower()
        config = _validate_options(normalized_provider, dict(options))
        now = _timestamp()
        return cls(
            name=normalized_name,
            provider=normalized_provider,
            action=_PROVIDER_ACTIONS[normalized_provider],
            destination=_destination(normalized_provider, config),
            config=config,
            created_at=created_at or now,
            updated_at=updated_at or now,
        )

    @property
    def digest(self) -> str:
        payload = {
            "schema_version": _SCHEMA_VERSION,
            "name": self.name,
            "provider": self.provider,
            "action": self.action,
            "destination": self.destination,
            "config": self.config,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(canonical).hexdigest()

    def credential_env_names(self) -> tuple[str, ...]:
        names = {str(value) for key, value in self.config.items() if key.endswith("_env")}
        if self.provider == "buzz":
            names.update(_BUZZ_ENV)
        return tuple(sorted(names))

    def required_check_env_names(self) -> tuple[str, ...]:
        if self.provider == "buzz":
            return ("BUZZ_PRIVATE_KEY",)
        token_env = self.config.get("token_env")
        return (str(token_env),) if isinstance(token_env, str) else ()

    def required_deploy_env_names(self) -> tuple[str, ...]:
        if self.provider == "buzz":
            return ("BUZZ_PRIVATE_KEY",)
        return tuple(
            sorted(str(value) for key, value in self.config.items() if key.endswith("_env"))
        )

    def public_payload(self) -> dict[str, object]:
        required = set(self.required_deploy_env_names())
        return {
            "name": self.name,
            "provider": self.provider,
            "action": self.action,
            "destination": self.destination,
            "config": dict(self.config),
            "digest": self.digest,
            "credential_env": [
                {
                    "name": name,
                    "present": bool(os.environ.get(name)),
                    "purpose": "runtime",
                    "required": name in required,
                }
                for name in self.credential_env_names()
            ],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def record(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "action": self.action,
            "destination": self.destination,
            "config": dict(self.config),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_record(cls, name: str, record: object) -> ConnectionProfile:
        if not isinstance(record, dict):
            raise ConnectionError(f"connection profile {name!r} must be an object")
        provider = record.get("provider")
        config = record.get("config")
        created_at = record.get("created_at")
        updated_at = record.get("updated_at")
        if not isinstance(provider, str) or not isinstance(config, dict):
            raise ConnectionError(f"connection profile {name!r} is malformed")
        if not isinstance(created_at, str) or not isinstance(updated_at, str):
            raise ConnectionError(f"connection profile {name!r} has invalid timestamps")
        profile = cls.create(
            name,
            provider,
            config,
            created_at=created_at,
            updated_at=updated_at,
        )
        if (
            record.get("action") != profile.action
            or record.get("destination") != profile.destination
        ):
            raise ConnectionError(f"connection profile {name!r} has inconsistent derived fields")
        return profile


class ConnectionStore:
    def __init__(self, config_dir: str | Path | None = None) -> None:
        self.config_dir = Path(config_dir or default_config_dir()).expanduser()
        self.path = self.config_dir / "connections.json"
        self.lock_path = self.config_dir / "connections.lock"

    def _ensure_dir(self) -> os.stat_result:
        if self.config_dir.is_symlink():
            raise ConnectionError("connection config directory must not be a symlink")
        try:
            self.config_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        except OSError as exc:
            raise ConnectionError("cannot create connection config directory") from exc
        metadata = self.config_dir.stat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise ConnectionError("connection config path must be a directory")
        if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
            raise ConnectionError("connection config directory must be owned by the current user")
        if metadata.st_mode & 0o077:
            raise ConnectionError("connection config directory permissions must be 0700")
        return metadata

    def _assert_directory_path(self, descriptor: int) -> None:
        try:
            current = os.stat(self.config_dir, follow_symlinks=False)
        except OSError as exc:
            raise ConnectionError("connection config directory changed during access") from exc
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(current.st_mode)
            or opened.st_dev != current.st_dev
            or opened.st_ino != current.st_ino
        ):
            raise ConnectionError("connection config directory changed during access")

    def _open_directory(self, expected: os.stat_result) -> int:
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.config_dir, flags)
        except OSError as exc:
            raise ConnectionError("cannot open connection config directory") from exc
        actual = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(actual.st_mode)
            or actual.st_dev != expected.st_dev
            or actual.st_ino != expected.st_ino
        ):
            os.close(descriptor)
            raise ConnectionError("connection config directory changed during access")
        return descriptor

    def _validate_file(self, path: Path) -> None:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISLNK(metadata.st_mode):
            raise ConnectionError(f"connection {path.name} must not be a symlink")
        if not stat.S_ISREG(metadata.st_mode):
            raise ConnectionError(f"connection {path.name} must be a regular file")
        if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
            raise ConnectionError(f"connection {path.name} must be owned by the current user")
        if metadata.st_mode & 0o177:
            raise ConnectionError(f"connection {path.name} permissions must be 0600")

    @contextmanager
    def _lock(self, *, exclusive: bool) -> Iterator[int]:
        directory_fd = self._open_directory(self._ensure_dir())
        descriptor = -1
        try:
            self._validate_file(self.lock_path)
            flags = os.O_RDWR | os.O_CREAT
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open("connections.lock", flags, 0o600, dir_fd=directory_fd)
            except OSError as exc:
                raise ConnectionError("cannot open connection lock") from exc
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ConnectionError("connection lock must be a regular file")
            if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
                raise ConnectionError("connection lock must be owned by the current user")
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            self._assert_directory_path(directory_fd)
            yield directory_fd
            self._assert_directory_path(directory_fd)
        finally:
            if descriptor >= 0:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
            os.close(directory_fd)

    def _read_unlocked(self, directory_fd: int) -> dict[str, ConnectionProfile]:
        self._validate_file(self.path)
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open("connections.json", flags, dir_fd=directory_fd)
        except FileNotFoundError:
            return {}
        except OSError as exc:
            raise ConnectionError("cannot open connection profiles") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ConnectionError("connection profiles must be a regular file")
            if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
                raise ConnectionError("connection profiles must be owned by the current user")
            if metadata.st_mode & 0o177:
                raise ConnectionError("connection profiles permissions must be 0600")
            with os.fdopen(descriptor, "r", encoding="utf-8") as source:
                descriptor = -1
                serialized = source.read(1_048_577)
            if len(serialized) > 1_048_576:
                raise ConnectionError("connection profiles exceed the 1 MiB safety limit")
            data = json.loads(serialized)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ConnectionError("cannot read connection profiles") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if not isinstance(data, dict) or data.get("schema_version") != _SCHEMA_VERSION:
            raise ConnectionError("unsupported connection profile schema")
        records = data.get("profiles")
        if not isinstance(records, dict):
            raise ConnectionError("connection profiles must be an object")
        profiles: dict[str, ConnectionProfile] = {}
        for name, record in sorted(records.items()):
            if not isinstance(name, str) or not _NAME.fullmatch(name):
                raise ConnectionError("connection profiles contain an invalid profile name")
            if not isinstance(record, dict):
                raise ConnectionError(f"connection profile {name!r} must be an object")
            profiles[name] = ConnectionProfile.from_record(name, record)
        return profiles

    def _write_unlocked(
        self, profiles: dict[str, ConnectionProfile], directory_fd: int
    ) -> None:
        payload = {
            "schema_version": _SCHEMA_VERSION,
            "profiles": {name: profile.record() for name, profile in sorted(profiles.items())},
        }
        serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        descriptor = -1
        temporary_name: str | None = None
        try:
            temporary_name = f".connections-{secrets.token_hex(16)}"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(temporary_name, flags, 0o600, dir_fd=directory_fd)
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
                descriptor = -1
                destination.write(serialized)
                destination.flush()
                os.fsync(destination.fileno())
            os.replace(
                temporary_name,
                "connections.json",
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            temporary_name = None
            os.fsync(directory_fd)
        except OSError as exc:
            raise ConnectionError("cannot write connection profiles") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary_name is not None:
                with suppress(FileNotFoundError):
                    os.unlink(temporary_name, dir_fd=directory_fd)

    def list(self) -> tuple[ConnectionProfile, ...]:
        with self._lock(exclusive=False) as directory_fd:
            return tuple(self._read_unlocked(directory_fd).values())

    def get(self, name: str) -> ConnectionProfile:
        with self._lock(exclusive=False) as directory_fd:
            profiles = self._read_unlocked(directory_fd)
        try:
            return profiles[name]
        except KeyError as exc:
            raise ConnectionError(f"connection profile not found: {name}") from exc

    def add(
        self,
        name: str,
        provider: str,
        options: dict[str, object],
        *,
        replace: bool = False,
    ) -> ConnectionProfile:
        with self._lock(exclusive=True) as directory_fd:
            profiles = self._read_unlocked(directory_fd)
            if name in profiles and not replace:
                raise ConnectionError(f"connection profile already exists: {name}")
            existing = profiles.get(name)
            profile = ConnectionProfile.create(
                name,
                provider,
                options,
                created_at=existing.created_at if existing else None,
            )
            profiles[name] = profile
            self._write_unlocked(profiles, directory_fd)
        return profile

    def remove(self, name: str) -> ConnectionProfile:
        with self._lock(exclusive=True) as directory_fd:
            profiles = self._read_unlocked(directory_fd)
            try:
                removed = profiles.pop(name)
            except KeyError as exc:
                raise ConnectionError(f"connection profile not found: {name}") from exc
            self._write_unlocked(profiles, directory_fd)
        return removed


def _resolve_buzz_git_executable(name: str, repo_path: Path) -> Path:
    return resolve_executable(name, repo_path)


def _run_buzz_git_command(argv: tuple[str, ...], repo_path: Path) -> tuple[int, str]:
    completed = subprocess.run(  # noqa: S603 - executable path is resolved above
        argv,
        cwd=repo_path,
        env=sanitized_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=15,
        check=False,
    )
    return completed.returncode, completed.stdout


def _secure_nostr_keyfile(configured: str) -> bool:
    path = Path(configured).expanduser()
    if not path.is_absolute():
        return False
    try:
        relative = path.relative_to(Path("/")).as_posix()
        descriptor = open_relative_regular(Path("/"), relative)
    except (SafeFileError, ValueError):
        return False
    try:
        metadata = os.fstat(descriptor)
        if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
            return False
        mode = stat.S_IMODE(metadata.st_mode)
        return bool(mode & stat.S_IRUSR) and not bool(mode & 0o177)
    finally:
        os.close(descriptor)


def inspect_buzz_git_auth(repo_path: str | Path, remote: str) -> dict[str, object]:
    """Inspect local NIP-98 Git readiness without network access or key reads."""
    repo = Path(repo_path).expanduser().resolve()
    issues: list[str] = []
    git_path: Path | None = None
    helper_available = False
    try:
        git_path = _resolve_buzz_git_executable("git", repo)
    except (FileNotFoundError, RuntimeIdentityError):
        issues.append("Git executable is unavailable")
    try:
        _resolve_buzz_git_executable("git-credential-nostr", repo)
        helper_available = True
    except (FileNotFoundError, RuntimeIdentityError):
        issues.append("git-credential-nostr is unavailable")

    git_version = "unknown"
    if git_path is not None:
        code, output = _run_buzz_git_command((str(git_path), "--version"), repo)
        match = re.fullmatch(r"git version (\d+)\.(\d+)\.(\d+)(?:\.[0-9]+)?\s*", output)
        if code != 0 or match is None:
            issues.append("Git version could not be verified")
        else:
            version_tuple = tuple(int(part) for part in match.groups())
            git_version = ".".join(match.groups())
            if version_tuple < _MINIMUM_NIP98_GIT:
                issues.append("Git 2.46.0 or newer is required for NIP-98 authentication")

    remote_configured = False
    remote_host: str | None = None
    remote_url: str | None = None
    if git_path is not None:
        code, output = _run_buzz_git_command(
            (str(git_path), "remote", "get-url", "--all", remote), repo
        )
        urls = [line.strip() for line in output.splitlines() if line.strip()]
        if code != 0 or len(urls) != 1:
            issues.append("Buzz remote must have exactly one configured fetch URL")
        else:
            parsed = urlsplit(urls[0])
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
            ):
                issues.append("Buzz remote must be credential-free HTTPS without query or fragment")
            else:
                try:
                    port = parsed.port
                except ValueError:
                    issues.append("Buzz remote HTTPS authority is invalid")
                else:
                    host = parsed.hostname.lower()
                    if ":" in host:
                        host = f"[{host}]"
                    remote_configured = True
                    remote_host = f"{host}:{port}" if port is not None else host
                    remote_url = urls[0]

    helper_host_scoped = False
    use_http_path = False
    if git_path is not None and remote_url is not None and remote_host is not None:
        helper_key = f"credential.https://{remote_host}.helper"
        code, output = _run_buzz_git_command(
            (str(git_path), "config", "--get-all", helper_key), repo
        )
        helpers = [line.strip() for line in output.splitlines() if line.strip()]
        helper_host_scoped = code == 0 and helpers == ["nostr"]
        if not helper_host_scoped:
            issues.append("Nostr credential helper is not host-scoped to the Buzz remote")
        code, output = _run_buzz_git_command(
            (
                str(git_path),
                "config",
                "--get-urlmatch",
                "credential.useHttpPath",
                remote_url,
            ),
            repo,
        )
        use_http_path = code == 0 and output.strip().lower() == "true"
        if not use_http_path:
            issues.append("credential.useHttpPath must be true for the Buzz remote")

    key_source = "missing"
    key_ready = False
    if os.environ.get("NOSTR_PRIVATE_KEY"):
        key_source = "environment"
        key_ready = True
    elif git_path is not None:
        code, output = _run_buzz_git_command(
            (str(git_path), "config", "--get", "nostr.keyfile"), repo
        )
        values = [line.strip() for line in output.splitlines() if line.strip()]
        if code == 0 and len(values) == 1:
            key_source = "keyfile"
            key_ready = _secure_nostr_keyfile(values[0])
            if not key_ready:
                issues.append("Nostr key file permissions must be 0600 or stricter")
        else:
            issues.append("Nostr private key source is not configured")

    return {
        "ready": not issues,
        "git_version": git_version,
        "git_minimum": "2.46.0",
        "remote_host": remote_host,
        "remote_configured": remote_configured,
        "helper_available": helper_available,
        "helper_host_scoped": helper_host_scoped,
        "use_http_path": use_http_path,
        "key_source": key_source,
        "key_ready": key_ready,
        "issues": issues,
    }


def verify_connection(
    profile: ConnectionProfile,
    repo_path: str | Path,
    *,
    allow_network: bool,
    registry: _AdapterRegistry | None = None,
) -> dict[str, object]:
    """Validate a profile locally and optionally perform its read-only provider check."""
    from .adapters.base import AdapterContext
    from .adapters.registry import AdapterRegistry

    missing_check = sorted(
        name for name in profile.required_check_env_names() if not os.environ.get(name)
    )
    missing_deploy = sorted(
        name for name in profile.required_deploy_env_names() if not os.environ.get(name)
    )
    missing_executable: list[str] = []
    executable_name = {"git.ref": "git", "buzz.workflow": "buzz"}.get(profile.action)
    if executable_name:
        try:
            resolve_executable(executable_name, Path(repo_path).expanduser().resolve())
        except (FileNotFoundError, RuntimeIdentityError):
            missing_executable.append(executable_name)

    buzz_git_auth: dict[str, object] | None = None
    if profile.provider == "buzz-git":
        buzz_git_auth = inspect_buzz_git_auth(
            repo_path,
            str(profile.config["remote"]),
        )
    buzz_git_blocked = buzz_git_auth is not None and not bool(buzz_git_auth["ready"])

    payload: dict[str, object] = {
        "connection": profile.name,
        "provider": profile.provider,
        "action": profile.action,
        "destination": profile.destination,
        "profile_digest": profile.digest,
        "status": (
            "blocked"
            if missing_check or missing_executable or buzz_git_blocked
            else "configured"
        ),
        "network_checked": False,
        "mutation_performed": False,
        "missing_credential_env": missing_check,
        "missing_deploy_env": missing_deploy,
        "missing_executable": missing_executable,
    }
    if buzz_git_auth is not None:
        payload["buzz_git_auth"] = buzz_git_auth
    if missing_check or missing_executable or buzz_git_blocked or not allow_network:
        return payload

    configured_registry = registry or AdapterRegistry()
    adapter = configured_registry.get(profile.action)
    context = AdapterContext(
        run_id="connection-check",
        source_sha="0" * 40,
        provider=profile.provider,
        destination=profile.destination,
        config={**profile.config, "repo_path": str(Path(repo_path).expanduser().resolve())},
    )
    result = adapter.check(context)
    payload.update(
        {
            "status": result.status,
            "network_checked": True,
            "identity": result.identity,
            "evidence": result.evidence,
        }
    )
    return payload


def _toml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)
    raise ConnectionError("unsupported playbook configuration value")


def render_playbook(profile: ConnectionProfile, *, target: str = "production") -> str:
    normalized_target = target.strip()
    if not normalized_target or "\n" in normalized_target or "\r" in normalized_target:
        raise ConnectionError("playbook target must be a non-empty single-line string")
    lines = [
        "# Generated from a local Shipyard connection profile.",
        "# Credential values are not stored here; only environment-variable names are retained.",
        "schema_version = 2",
        f'name = {json.dumps(f"{profile.name}-{normalized_target}")}',
        f"target = {json.dumps(normalized_target)}",
        f"provider = {json.dumps(profile.provider)}",
        f"destination = {json.dumps(profile.destination)}",
        f"connection_profile = {json.dumps(profile.name)}",
        f"connection_digest = {json.dumps(profile.digest)}",
        "",
        "[[steps]]",
        'id = "deploy"',
        f"name = {json.dumps(f'Deploy through {profile.name}')}",
        'effect = "external"',
        f"action = {json.dumps(profile.action)}",
        "",
        "[steps.config]",
    ]
    lines.extend(f"{key} = {_toml_value(value)}" for key, value in sorted(profile.config.items()))
    return "\n".join(lines) + "\n"
