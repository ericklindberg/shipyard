from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .safe_files import (
    SafeFileError,
    open_or_create_relative_directory,
    open_private_directory,
    open_relative_regular,
    open_relative_regular_at,
)

_SCHEMA = "shipyard.release-gate/v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_SHA = re.compile(r"^[0-9a-f]{40}$")
_GATE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_MAX_EVIDENCE_BYTES = 2 * 1024 * 1024 * 1024
_MAX_ATTESTATION_BYTES = 16 * 1024 * 1024


class GateError(ValueError):
    pass


def _canonical(payload: object) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _digest(payload: object) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _open_artifact(path: str | Path) -> tuple[Path, int]:
    candidate = Path(path).expanduser()
    absolute = candidate if candidate.is_absolute() else Path.cwd() / candidate
    absolute = Path(os.path.abspath(absolute))
    try:
        relative = absolute.relative_to(Path("/")).as_posix()
        descriptor = open_relative_regular(Path("/"), relative)
    except (OSError, SafeFileError, ValueError) as exc:
        raise GateError(f"gate evidence is unavailable or unsafe: {candidate}") from exc
    return absolute, descriptor


def _artifact_from_descriptor(absolute: Path, descriptor: int) -> dict[str, object]:
    digest = hashlib.sha256()
    size = 0
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_EVIDENCE_BYTES:
        raise GateError("gate evidence must be a bounded regular file")
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
        size += len(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return {
        "name": absolute.name,
        "path": str(absolute),
        "size": size,
        "sha256": digest.hexdigest(),
    }


def _artifact(path: str | Path) -> dict[str, object]:
    absolute, descriptor = _open_artifact(path)
    try:
        return _artifact_from_descriptor(absolute, descriptor)
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class GateAttestation:
    gate: str
    project_digest: str
    source_sha: str
    status: str
    actor: str
    reason: str
    observed_at: str
    apple_observation_digest: str | None
    app_version: str | None
    build_number: str | None
    device: str | None
    os_version: str | None
    checks: tuple[str, ...]
    evidence: tuple[dict[str, object], ...]
    digest: str
    path: Path | None = None

    def core_payload(self, *, portable: bool = False) -> dict[str, object]:
        evidence = []
        for item in self.evidence:
            record = dict(item)
            if portable:
                record.pop("path", None)
            evidence.append(record)
        return {
            "schema_version": _SCHEMA,
            "gate": self.gate,
            "project_digest": self.project_digest,
            "source_sha": self.source_sha,
            "status": self.status,
            "actor": self.actor,
            "reason": self.reason,
            "observed_at": self.observed_at,
            "apple_observation_digest": self.apple_observation_digest,
            "app_version": self.app_version,
            "build_number": self.build_number,
            "device": self.device,
            "os_version": self.os_version,
            "checks": list(self.checks),
            "evidence": evidence,
        }

    def payload(self) -> dict[str, object]:
        return {**self.core_payload(), "attestation_sha256": self.digest}

    def portable_payload(self) -> dict[str, object]:
        core = self.core_payload(portable=True)
        return {**core, "attestation_sha256": _digest(core)}

    @classmethod
    def create(
        cls,
        *,
        gate: str,
        project_digest: str,
        source_sha: str,
        status: str,
        actor: str,
        reason: str,
        evidence_paths: Iterable[str | Path] = (),
        apple_observation_digest: str | None = None,
        app_version: str | None = None,
        build_number: str | None = None,
        device: str | None = None,
        os_version: str | None = None,
        checks: Iterable[str] = (),
        observed_at: str | None = None,
    ) -> GateAttestation:
        if _GATE.fullmatch(gate) is None:
            raise GateError("gate name is invalid")
        if _SHA256.fullmatch(project_digest) is None:
            raise GateError("gate project digest is invalid")
        if _SOURCE_SHA.fullmatch(source_sha) is None:
            raise GateError("gate source SHA is invalid")
        if status not in {"passed", "failed", "pending"}:
            raise GateError("gate status is invalid")
        if apple_observation_digest is not None and _SHA256.fullmatch(
            apple_observation_digest
        ) is None:
            raise GateError("gate Apple observation digest is invalid")
        normalized_actor = actor.strip()
        normalized_reason = reason.strip()
        if (
            not normalized_actor
            or not normalized_reason
            or any(character in normalized_actor + normalized_reason for character in ("\x00",))
        ):
            raise GateError("gate actor and reason are required")
        normalized_checks = tuple(dict.fromkeys(check.strip() for check in checks if check.strip()))
        if any(
            any(character in check for character in ("\x00", "\r", "\n"))
            for check in normalized_checks
        ):
            raise GateError("gate checks must be single-line values")
        artifacts = tuple(_artifact(path) for path in evidence_paths)
        if gate == "physical-device" and status == "passed" and (
            apple_observation_digest is None
            or not app_version
            or not build_number
            or not device
            or not os_version
            or not normalized_checks
            or not artifacts
        ):
            raise GateError(
                "passed physical-device gate requires Apple observation, version/build, "
                "device/OS, checks, and evidence"
            )
        provisional = cls(
            gate,
            project_digest,
            source_sha,
            status,
            normalized_actor,
            normalized_reason,
            observed_at or _timestamp(),
            apple_observation_digest,
            app_version,
            build_number,
            device,
            os_version,
            normalized_checks,
            artifacts,
            "",
        )
        digest = _digest(provisional.core_payload())
        return cls(
            provisional.gate,
            provisional.project_digest,
            provisional.source_sha,
            provisional.status,
            provisional.actor,
            provisional.reason,
            provisional.observed_at,
            provisional.apple_observation_digest,
            provisional.app_version,
            provisional.build_number,
            provisional.device,
            provisional.os_version,
            provisional.checks,
            provisional.evidence,
            digest,
        )

    @classmethod
    def from_payload(
        cls, payload: object, *, path: Path | None = None
    ) -> GateAttestation:
        if not isinstance(payload, dict):
            raise GateError("gate attestation must be a JSON object")
        expected = {
            "schema_version",
            "gate",
            "project_digest",
            "source_sha",
            "status",
            "actor",
            "reason",
            "observed_at",
            "apple_observation_digest",
            "app_version",
            "build_number",
            "device",
            "os_version",
            "checks",
            "evidence",
            "attestation_sha256",
        }
        if set(payload) != expected or payload.get("schema_version") != _SCHEMA:
            raise GateError("gate attestation fields or schema are invalid")
        gate = payload.get("gate")
        project_digest = payload.get("project_digest")
        source_sha = payload.get("source_sha")
        status = payload.get("status")
        actor = payload.get("actor")
        reason = payload.get("reason")
        observed_at = payload.get("observed_at")
        observation_digest = payload.get("apple_observation_digest")
        checks = payload.get("checks")
        evidence = payload.get("evidence")
        digest = payload.get("attestation_sha256")
        optional_strings = [
            payload.get("app_version"),
            payload.get("build_number"),
            payload.get("device"),
            payload.get("os_version"),
        ]
        if (
            not isinstance(gate, str)
            or _GATE.fullmatch(gate) is None
            or not isinstance(project_digest, str)
            or _SHA256.fullmatch(project_digest) is None
            or not isinstance(source_sha, str)
            or _SOURCE_SHA.fullmatch(source_sha) is None
            or status not in {"passed", "failed", "pending"}
            or not isinstance(actor, str)
            or not actor.strip()
            or not isinstance(reason, str)
            or not reason.strip()
            or not isinstance(observed_at, str)
            or not observed_at.endswith("Z")
            or (
                observation_digest is not None
                and (
                    not isinstance(observation_digest, str)
                    or _SHA256.fullmatch(observation_digest) is None
                )
            )
            or any(value is not None and not isinstance(value, str) for value in optional_strings)
            or not isinstance(checks, list)
            or any(not isinstance(check, str) or not check for check in checks)
            or len(set(checks)) != len(checks)
            or not isinstance(evidence, list)
            or not isinstance(digest, str)
            or _SHA256.fullmatch(digest) is None
        ):
            raise GateError("gate attestation identity is invalid")
        parsed_evidence: list[dict[str, object]] = []
        for item in evidence:
            if not isinstance(item, dict) or set(item) not in (
                {"name", "path", "size", "sha256"},
                {"name", "size", "sha256"},
            ):
                raise GateError("gate evidence entry is invalid")
            name = item.get("name")
            size = item.get("size")
            artifact_digest = item.get("sha256")
            item_path = item.get("path")
            if (
                not isinstance(name, str)
                or not name
                or "/" in name
                or "\\" in name
                or not isinstance(size, int)
                or isinstance(size, bool)
                or size < 0
                or not isinstance(artifact_digest, str)
                or _SHA256.fullmatch(artifact_digest) is None
                or (item_path is not None and not isinstance(item_path, str))
            ):
                raise GateError("gate evidence entry is invalid")
            parsed_evidence.append(dict(item))
        attestation = cls(
            gate,
            project_digest,
            source_sha,
            status,
            actor,
            reason,
            observed_at,
            observation_digest,
            payload.get("app_version"),
            payload.get("build_number"),
            payload.get("device"),
            payload.get("os_version"),
            tuple(checks),
            tuple(parsed_evidence),
            digest,
            path,
        )
        if _digest(attestation.core_payload()) != digest:
            raise GateError("gate attestation digest does not match its contents")
        if gate == "physical-device" and status == "passed" and (
            observation_digest is None
            or not attestation.app_version
            or not attestation.build_number
            or not attestation.device
            or not attestation.os_version
            or not attestation.checks
            or not attestation.evidence
        ):
            raise GateError("passed physical-device gate is incomplete")
        return attestation


def _load_gate_descriptor(descriptor: int, path: Path) -> GateAttestation:
    metadata = os.fstat(descriptor)
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size > _MAX_ATTESTATION_BYTES
        or mode & 0o177
        or (hasattr(os, "geteuid") and metadata.st_uid != os.geteuid())
    ):
        raise GateError("gate attestation must be a private user-owned regular file")
    raw = bytearray()
    while chunk := os.read(
        descriptor, min(65536, _MAX_ATTESTATION_BYTES + 1 - len(raw))
    ):
        raw.extend(chunk)
        if len(raw) > _MAX_ATTESTATION_BYTES:
            raise GateError("gate attestation exceeds the size limit")
    try:
        payload = json.loads(bytes(raw).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GateError("gate attestation is not valid JSON") from exc
    return GateAttestation.from_payload(payload, path=path)


def load_gate_attestation(path: str | Path) -> GateAttestation:
    candidate = Path(path).expanduser()
    absolute = candidate if candidate.is_absolute() else Path.cwd() / candidate
    absolute = Path(os.path.abspath(absolute))
    try:
        relative = absolute.relative_to(Path("/")).as_posix()
        descriptor = open_relative_regular(Path("/"), relative)
    except (SafeFileError, ValueError) as exc:
        raise GateError("gate attestation is unavailable or unsafe") from exc
    try:
        return _load_gate_descriptor(descriptor, absolute)
    finally:
        os.close(descriptor)


def open_verified_gate_evidence(attestation: GateAttestation) -> tuple[int, ...]:
    descriptors: list[int] = []
    try:
        for expected in attestation.evidence:
            path = expected.get("path")
            if not isinstance(path, str):
                raise GateError("gate attestation lacks local evidence paths")
            absolute, descriptor = _open_artifact(path)
            descriptors.append(descriptor)
            actual = _artifact_from_descriptor(absolute, descriptor)
            if (
                actual.get("name") != expected.get("name")
                or actual.get("size") != expected.get("size")
                or actual.get("sha256") != expected.get("sha256")
            ):
                raise GateError("gate evidence changed after attestation")
        return tuple(descriptors)
    except Exception:
        close_gate_evidence(descriptors)
        raise


def close_gate_evidence(descriptors: Iterable[int]) -> None:
    for descriptor in descriptors:
        os.close(descriptor)


def verify_gate_evidence(attestation: GateAttestation) -> None:
    descriptors = open_verified_gate_evidence(attestation)
    close_gate_evidence(descriptors)


class GateStore:
    def __init__(self, state_dir: str | Path) -> None:
        self.root = Path(state_dir).expanduser() / "gates"

    def _root_path(self) -> Path:
        return Path(os.path.abspath(self.root))

    def _open_root(self, *, create: bool) -> tuple[Path, int]:
        root = self._root_path()
        try:
            return root, open_private_directory(root, create=create)
        except SafeFileError as exc:
            raise GateError("gate state root is unavailable or unsafe") from exc

    def _root(self) -> Path:
        root, descriptor = self._open_root(create=True)
        os.close(descriptor)
        return root

    def _load_relative(self, root: Path, root_descriptor: int, relative: str) -> GateAttestation:
        try:
            descriptor = open_relative_regular_at(root_descriptor, relative)
        except SafeFileError as exc:
            raise GateError("gate path is unavailable or outside state root") from exc
        try:
            attestation = _load_gate_descriptor(descriptor, root / relative)
        finally:
            os.close(descriptor)
        expected = (
            Path(attestation.project_digest)
            / attestation.source_sha
            / attestation.gate
            / f"{attestation.digest}.json"
        ).as_posix()
        if relative != expected:
            raise GateError("gate path does not match its identity")
        return attestation

    def save(self, attestation: GateAttestation) -> Path:
        root, root_descriptor = self._open_root(create=True)
        relative_directory = (
            Path(attestation.project_digest) / attestation.source_sha / attestation.gate
        ).as_posix()
        destination_name = f"{attestation.digest}.json"
        destination = root / relative_directory / destination_name
        temporary_name = f".gate-{secrets.token_hex(16)}"
        directory_descriptor = -1
        content = (json.dumps(attestation.payload(), indent=2, sort_keys=True) + "\n").encode()
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
                    loaded = _load_gate_descriptor(existing, destination)
                finally:
                    os.close(existing)
                if loaded.payload() != attestation.payload():
                    raise GateError("gate attestation digest collision")
                return destination
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory_descriptor,
            )
            view = memoryview(content)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("gate write made no progress")
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
            if loaded.payload() != attestation.payload():
                raise GateError("gate attestation digest collision") from None
        except (OSError, SafeFileError, GateError) as exc:
            if directory_descriptor >= 0:
                with suppress(FileNotFoundError):
                    os.unlink(temporary_name, dir_fd=directory_descriptor)
            if isinstance(exc, GateError):
                raise
            raise GateError("cannot persist release gate") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if directory_descriptor >= 0:
                os.close(directory_descriptor)
            os.close(root_descriptor)
        return destination

    def load(self, path: str | Path) -> GateAttestation:
        candidate = Path(path).expanduser()
        try:
            absolute = candidate if candidate.is_absolute() else Path.cwd() / candidate
            absolute = Path(os.path.abspath(absolute))
            root_path = self._root_path()
            relative = absolute.relative_to(root_path).as_posix()
            root, root_descriptor = self._open_root(create=False)
        except (OSError, ValueError, GateError) as exc:
            raise GateError("gate path is unavailable or outside state root") from exc
        try:
            return self._load_relative(root, root_descriptor, relative)
        finally:
            os.close(root_descriptor)
