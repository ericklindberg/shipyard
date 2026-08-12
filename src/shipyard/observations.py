from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .adapters.base import AdapterStatus, ProviderReadback
from .safe_files import (
    SafeFileError,
    open_or_create_relative_directory,
    open_private_directory,
    open_relative_directory_at,
    open_relative_regular_at,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_SHA = re.compile(r"^[0-9a-f]{40}$")
_PROVIDER = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_SCHEMA = "shipyard.observation/v1"
_MAX_BYTES = 16 * 1024 * 1024


class ObservationError(ValueError):
    pass


def _canonical(payload: object) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _digest(payload: object) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _adapter_status(value: object) -> AdapterStatus:
    if value == "succeeded":
        return "succeeded"
    if value == "failed":
        return "failed"
    if value == "pending":
        return "pending"
    if value == "unknown":
        return "unknown"
    raise ObservationError("provider observation payload has an invalid status")


@dataclass(frozen=True)
class ReleaseObservation:
    provider: str
    project_digest: str
    source_sha: str
    status: str
    operation_id: str
    observed_sha: str | None
    evidence: dict[str, object]
    observed_at: str
    digest: str
    path: Path | None = None

    def core_payload(self) -> dict[str, object]:
        return {
            "schema_version": _SCHEMA,
            "provider": self.provider,
            "project_digest": self.project_digest,
            "source_sha": self.source_sha,
            "status": self.status,
            "operation_id": self.operation_id,
            "observed_sha": self.observed_sha,
            "evidence": self.evidence,
            "observed_at": self.observed_at,
        }

    def payload(self) -> dict[str, object]:
        return {**self.core_payload(), "observation_sha256": self.digest}

    @classmethod
    def create(
        cls,
        provider: str,
        project_digest: str,
        source_sha: str,
        readback: ProviderReadback,
        *,
        observed_at: str | None = None,
    ) -> ReleaseObservation:
        if _PROVIDER.fullmatch(provider) is None:
            raise ObservationError("observation provider is invalid")
        if _SHA256.fullmatch(project_digest) is None:
            raise ObservationError("observation project digest is invalid")
        if _SOURCE_SHA.fullmatch(source_sha) is None:
            raise ObservationError("observation source SHA is invalid")
        if readback.observed_sha is not None and readback.observed_sha != source_sha:
            raise ObservationError("observation provider SHA does not match release source SHA")
        if readback.status not in {"succeeded", "failed", "pending", "unknown"}:
            raise ObservationError("observation status is invalid")
        if not readback.operation_id or any(
            character in readback.operation_id for character in ("\x00", "\r", "\n")
        ):
            raise ObservationError("observation operation id is invalid")
        evidence = dict(readback.evidence)
        timestamp = observed_at or _timestamp()
        provisional = cls(
            provider,
            project_digest,
            source_sha,
            readback.status,
            readback.operation_id,
            readback.observed_sha,
            evidence,
            timestamp,
            "",
        )
        digest = _digest(provisional.core_payload())
        return cls(
            provisional.provider,
            provisional.project_digest,
            provisional.source_sha,
            provisional.status,
            provisional.operation_id,
            provisional.observed_sha,
            provisional.evidence,
            provisional.observed_at,
            digest,
        )

    @classmethod
    def from_payload(
        cls, payload: object, *, path: Path | None = None
    ) -> ReleaseObservation:
        if not isinstance(payload, dict):
            raise ObservationError("observation must be a JSON object")
        expected = {
            "schema_version",
            "provider",
            "project_digest",
            "source_sha",
            "status",
            "operation_id",
            "observed_sha",
            "evidence",
            "observed_at",
            "observation_sha256",
        }
        if set(payload) != expected or payload.get("schema_version") != _SCHEMA:
            raise ObservationError("observation fields or schema are invalid")
        provider = payload.get("provider")
        project_digest = payload.get("project_digest")
        source_sha = payload.get("source_sha")
        status = payload.get("status")
        operation_id = payload.get("operation_id")
        observed_sha = payload.get("observed_sha")
        evidence = payload.get("evidence")
        observed_at = payload.get("observed_at")
        digest = payload.get("observation_sha256")
        if (
            not isinstance(provider, str)
            or _PROVIDER.fullmatch(provider) is None
            or not isinstance(project_digest, str)
            or _SHA256.fullmatch(project_digest) is None
            or not isinstance(source_sha, str)
            or _SOURCE_SHA.fullmatch(source_sha) is None
            or status not in {"succeeded", "failed", "pending", "unknown"}
            or not isinstance(operation_id, str)
            or not operation_id
            or (observed_sha is not None and observed_sha != source_sha)
            or not isinstance(evidence, dict)
            or not isinstance(observed_at, str)
            or not observed_at.endswith("Z")
            or not isinstance(digest, str)
            or _SHA256.fullmatch(digest) is None
        ):
            raise ObservationError("observation identity is invalid")
        observation = cls(
            provider,
            project_digest,
            source_sha,
            status,
            operation_id,
            observed_sha,
            evidence,
            observed_at,
            digest,
            path,
        )
        if _digest(observation.core_payload()) != digest:
            raise ObservationError("observation digest does not match its contents")
        return observation


class ObservationStore:
    def __init__(self, state_dir: str | Path) -> None:
        self.root = Path(state_dir).expanduser() / "observations"

    def _root_path(self) -> Path:
        return Path(os.path.abspath(self.root))

    def _open_root(self, *, create: bool) -> tuple[Path, int]:
        root = self._root_path()
        try:
            return root, open_private_directory(root, create=create)
        except SafeFileError as exc:
            message = (
                "cannot create observation state root"
                if create
                else "observation state root is unavailable"
            )
            raise ObservationError(message) from exc

    def _ensure_root(self) -> Path:
        root, descriptor = self._open_root(create=True)
        os.close(descriptor)
        return root

    def _existing_root(self) -> Path | None:
        if not os.path.lexists(self._root_path()):
            return None
        root, descriptor = self._open_root(create=False)
        os.close(descriptor)
        return root

    @staticmethod
    def _read_descriptor(descriptor: int, path: Path) -> ReleaseObservation:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or mode & 0o177
            or metadata.st_size > _MAX_BYTES
            or (hasattr(os, "geteuid") and metadata.st_uid != os.geteuid())
        ):
            raise ObservationError("observation file must be a private user-owned regular file")
        raw = bytearray()
        while chunk := os.read(descriptor, min(65536, _MAX_BYTES + 1 - len(raw))):
            raw.extend(chunk)
            if len(raw) > _MAX_BYTES:
                raise ObservationError("observation exceeds the size limit")
        try:
            payload = json.loads(bytes(raw).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ObservationError("cannot read observation JSON") from exc
        return ReleaseObservation.from_payload(payload, path=path)

    def _load_relative(self, root: Path, root_descriptor: int, relative: str) -> ReleaseObservation:
        try:
            descriptor = open_relative_regular_at(root_descriptor, relative)
        except SafeFileError as exc:
            raise ObservationError("observation path is unavailable or outside state root") from exc
        try:
            path = root / relative
            observation = self._read_descriptor(descriptor, path)
        finally:
            os.close(descriptor)
        expected = (
            Path(observation.project_digest)
            / observation.source_sha
            / observation.provider
            / f"{observation.digest}.json"
        ).as_posix()
        if relative != expected:
            raise ObservationError("observation path does not match its identity")
        return observation

    def save(self, observation: ReleaseObservation) -> Path:
        root, root_descriptor = self._open_root(create=True)
        relative_directory = (
            Path(observation.project_digest) / observation.source_sha / observation.provider
        ).as_posix()
        destination_name = f"{observation.digest}.json"
        destination = root / relative_directory / destination_name
        temporary_name = f".observation-{secrets.token_hex(16)}"
        directory_descriptor = -1
        descriptor = -1
        try:
            directory_descriptor = open_or_create_relative_directory(
                root_descriptor, relative_directory
            )
            try:
                existing = os.open(
                    destination_name,
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_descriptor,
                )
            except FileNotFoundError:
                existing = -1
            if existing >= 0:
                try:
                    loaded = self._read_descriptor(existing, destination)
                finally:
                    os.close(existing)
                if loaded.payload() != observation.payload():
                    raise ObservationError("observation digest collision")
                return destination
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory_descriptor,
            )
            content = json.dumps(observation.payload(), indent=2, sort_keys=True) + "\n"
            encoded = content.encode("utf-8")
            if len(encoded) > _MAX_BYTES:
                raise ObservationError("observation exceeds the size limit")
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("observation write made no progress")
                view = view[written:]
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o600)
            os.close(descriptor)
            descriptor = -1
            os.link(
                temporary_name,
                destination_name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            os.unlink(temporary_name, dir_fd=directory_descriptor)
            os.fsync(directory_descriptor)
        except FileExistsError:
            with suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=directory_descriptor)
            loaded = self._load_relative(
                root,
                root_descriptor,
                f"{relative_directory}/{destination_name}",
            )
            if loaded.payload() != observation.payload():
                raise ObservationError("observation digest collision") from None
        except (OSError, SafeFileError, ObservationError) as exc:
            if directory_descriptor >= 0:
                with suppress(FileNotFoundError):
                    os.unlink(temporary_name, dir_fd=directory_descriptor)
            if isinstance(exc, ObservationError):
                raise
            raise ObservationError("cannot persist release observation") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if directory_descriptor >= 0:
                os.close(directory_descriptor)
            os.close(root_descriptor)
        return destination

    def load(self, path: str | Path) -> ReleaseObservation:
        candidate = Path(path).expanduser()
        root_path = self._root_path()
        if not os.path.lexists(root_path):
            raise ObservationError("observation path is unavailable or outside state root")
        try:
            absolute = candidate if candidate.is_absolute() else Path.cwd() / candidate
            absolute = Path(os.path.abspath(absolute))
            relative = absolute.relative_to(root_path).as_posix()
            root, root_descriptor = self._open_root(create=False)
        except (OSError, ValueError, ObservationError) as exc:
            raise ObservationError("observation path is unavailable or outside state root") from exc
        try:
            return self._load_relative(root, root_descriptor, relative)
        finally:
            os.close(root_descriptor)

    def list(
        self,
        *,
        project_digest: str | None = None,
        source_sha: str | None = None,
        provider: str | None = None,
        limit: int = 100,
    ) -> tuple[ReleaseObservation, ...]:
        if project_digest is not None and _SHA256.fullmatch(project_digest) is None:
            raise ObservationError("observation project digest filter is invalid")
        if source_sha is not None and _SOURCE_SHA.fullmatch(source_sha) is None:
            raise ObservationError("observation source SHA filter is invalid")
        if provider is not None and _PROVIDER.fullmatch(provider) is None:
            raise ObservationError("observation provider filter is invalid")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise ObservationError("observation list limit must be between 1 and 1000")
        if not os.path.lexists(self._root_path()):
            return ()
        root, root_descriptor = self._open_root(create=False)
        observations: list[ReleaseObservation] = []
        scanned = 0
        try:
            for project_name in sorted(os.listdir(root_descriptor)):
                if _SHA256.fullmatch(project_name) is None:
                    raise ObservationError("observation state contains an invalid project entry")
                if project_digest is not None and project_name != project_digest:
                    continue
                try:
                    project_descriptor = open_relative_directory_at(
                        root_descriptor, project_name
                    )
                except SafeFileError as exc:
                    raise ObservationError(
                        "observation state contains an unsafe project entry"
                    ) from exc
                try:
                    for source_name in sorted(os.listdir(project_descriptor)):
                        if _SOURCE_SHA.fullmatch(source_name) is None:
                            raise ObservationError(
                                "observation state contains an invalid source entry"
                            )
                        if source_sha is not None and source_name != source_sha:
                            continue
                        try:
                            source_descriptor = open_relative_directory_at(
                                project_descriptor, source_name
                            )
                        except SafeFileError as exc:
                            raise ObservationError(
                                "observation state contains an unsafe source entry"
                            ) from exc
                        try:
                            for provider_name in sorted(os.listdir(source_descriptor)):
                                if _PROVIDER.fullmatch(provider_name) is None:
                                    raise ObservationError(
                                        "observation state contains an invalid provider entry"
                                    )
                                if provider is not None and provider_name != provider:
                                    continue
                                try:
                                    provider_descriptor = open_relative_directory_at(
                                        source_descriptor, provider_name
                                    )
                                except SafeFileError as exc:
                                    raise ObservationError(
                                        "observation state contains an unsafe provider entry"
                                    ) from exc
                                try:
                                    for file_name in sorted(os.listdir(provider_descriptor)):
                                        scanned += 1
                                        if scanned > 10_000:
                                            raise ObservationError(
                                                "observation state exceeds the scan limit"
                                            )
                                        digest, separator, suffix = file_name.partition(".")
                                        if (
                                            separator != "."
                                            or suffix != "json"
                                            or _SHA256.fullmatch(digest) is None
                                        ):
                                            raise ObservationError(
                                                "observation state contains an invalid file"
                                            )
                                        relative = (
                                            Path(project_name)
                                            / source_name
                                            / provider_name
                                            / file_name
                                        ).as_posix()
                                        try:
                                            descriptor = open_relative_regular_at(
                                                provider_descriptor, file_name
                                            )
                                        except SafeFileError as exc:
                                            raise ObservationError(
                                                "observation state contains an unsafe file"
                                            ) from exc
                                        try:
                                            observation = self._read_descriptor(
                                                descriptor, root / relative
                                            )
                                        finally:
                                            os.close(descriptor)
                                        expected = (
                                            Path(observation.project_digest)
                                            / observation.source_sha
                                            / observation.provider
                                            / f"{observation.digest}.json"
                                        ).as_posix()
                                        if relative != expected:
                                            raise ObservationError(
                                                "observation path does not match its identity"
                                            )
                                        observations.append(observation)
                                finally:
                                    os.close(provider_descriptor)
                        finally:
                            os.close(source_descriptor)
                finally:
                    os.close(project_descriptor)
        finally:
            os.close(root_descriptor)
        observations.sort(
            key=lambda observation: (observation.observed_at, observation.digest),
            reverse=True,
        )
        return tuple(observations[:limit])


def observation_from_payload(
    provider: str,
    project_digest: str,
    source_sha: str,
    payload: Mapping[str, object],
) -> ReleaseObservation:
    status = _adapter_status(payload.get("status"))
    operation_id = payload.get("operation_id")
    observed_sha = payload.get("observed_sha")
    evidence = payload.get("evidence")
    if (
        not isinstance(operation_id, str)
        or (observed_sha is not None and not isinstance(observed_sha, str))
        or not isinstance(evidence, dict)
    ):
        raise ObservationError("provider observation payload is malformed")
    return ReleaseObservation.create(
        provider,
        project_digest,
        source_sha,
        ProviderReadback(
            status, operation_id, observed_sha, dict(evidence)
        ),
    )
