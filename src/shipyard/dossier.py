from __future__ import annotations

import hashlib
import io
import json
import os
import re
import secrets
import stat
import tarfile
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .evidence import verify_evidence_bundle
from .gates import GateAttestation, GateError
from .observations import ObservationError, ReleaseObservation
from .release_project import (
    ReleaseProject,
    ReleaseProjectError,
    load_release_project,
)
from .safe_files import SafeFileError, open_relative_regular

_SCHEMA = "shipyard.release-dossier/v1"
_SOURCE_SHA = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_MAX_BUNDLE_BYTES = 4 * 1024 * 1024 * 1024
_MAX_RECORD_BYTES = 32 * 1024 * 1024
_MAX_MEMBERS = 20_000


class DossierError(ValueError):
    pass


@dataclass(frozen=True)
class DossierInput:
    kind: str
    name: str
    path: Path
    size: int
    sha256: str
    metadata: dict[str, object]

    @property
    def member_name(self) -> str:
        suffix = ".tar" if self.kind == "run" else self.path.suffix or ".bin"
        return f"{self.kind}s/{self.name}{suffix}"

    def payload(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "name": self.name,
            "member": self.member_name,
            "size": self.size,
            "sha256": self.sha256,
            "metadata": self.metadata,
        }


def _canonical(payload: object) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _digest(payload: object) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _stream_digest(descriptor: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
        size += len(chunk)
        if size > _MAX_BUNDLE_BYTES:
            raise DossierError("dossier input exceeds the size limit")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest(), size


def _open_input(path: str | Path) -> tuple[Path, int, str, int]:
    candidate = Path(path).expanduser()
    absolute = candidate if candidate.is_absolute() else Path.cwd() / candidate
    absolute = Path(os.path.abspath(absolute))
    try:
        relative = absolute.relative_to(Path("/")).as_posix()
        descriptor = open_relative_regular(Path("/"), relative)
    except (OSError, SafeFileError, ValueError) as exc:
        raise DossierError(f"dossier input is unavailable or unsafe: {candidate}") from exc
    try:
        digest, size = _stream_digest(descriptor)
    except Exception:
        os.close(descriptor)
        raise
    return absolute, descriptor, digest, size


def _safe_name(value: str) -> str:
    normalized = value.strip().lower()
    if _NAME.fullmatch(normalized) is None:
        raise DossierError("dossier entry name is invalid")
    return normalized


def _run_input(name: str, path: str | Path, source_sha: str) -> DossierInput:
    resolved, descriptor, digest, size = _open_input(path)
    os.close(descriptor)
    verified = verify_evidence_bundle(resolved)
    if verified.get("valid") is not True:
        raise DossierError(f"run evidence is invalid: {resolved}")
    if verified.get("source_sha") != source_sha:
        raise DossierError("run evidence source SHA differs from dossier source SHA")
    run_id = verified.get("run_id")
    candidate_digest = verified.get("candidate_digest")
    if not isinstance(run_id, str) or not isinstance(candidate_digest, str):
        raise DossierError("run evidence identity is incomplete")
    return DossierInput(
        "run",
        _safe_name(name),
        resolved,
        size,
        digest,
        {
            "run_id": run_id,
            "status": verified.get("status"),
            "candidate_digest": candidate_digest,
            "receipts_verified": verified.get("receipts_verified"),
            "artifacts_verified": verified.get("artifacts_verified"),
        },
    )


def _observation_input(
    name: str,
    path: str | Path,
    source_sha: str,
    project_digest: str,
) -> DossierInput:
    resolved, descriptor, digest, size = _open_input(path)
    try:
        payload = json.loads(os.read(descriptor, size + 1).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, OSError) as exc:
        raise DossierError("observation input is not valid JSON") from exc
    finally:
        os.close(descriptor)
    try:
        observation = ReleaseObservation.from_payload(payload, path=resolved)
    except ObservationError as exc:
        raise DossierError(str(exc)) from exc
    if (
        observation.source_sha != source_sha
        or observation.project_digest != project_digest
    ):
        raise DossierError("observation identity differs from dossier identity")
    return DossierInput(
        "observation",
        _safe_name(name),
        resolved,
        size,
        digest,
        {
            "provider": observation.provider,
            "status": observation.status,
            "operation_id": observation.operation_id,
            "observed_sha": observation.observed_sha,
            "observation_sha256": observation.digest,
        },
    )


def _gate_input(
    path: str | Path,
    source_sha: str,
    project_digest: str,
) -> tuple[DossierInput, GateAttestation]:
    resolved, descriptor, digest, size = _open_input(path)
    try:
        payload = json.loads(os.read(descriptor, size + 1).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, OSError) as exc:
        raise DossierError("gate input is not valid JSON") from exc
    finally:
        os.close(descriptor)
    try:
        gate = GateAttestation.from_payload(payload, path=resolved)
    except GateError as exc:
        raise DossierError(str(exc)) from exc
    if gate.source_sha != source_sha or gate.project_digest != project_digest:
        raise DossierError("gate identity differs from dossier identity")
    return (
        DossierInput(
            "gate",
            _safe_name(gate.gate),
            resolved,
            size,
            digest,
            {
                "gate": gate.gate,
                "status": gate.status,
                "actor": gate.actor,
                "attestation_sha256": gate.digest,
                "apple_observation_digest": gate.apple_observation_digest,
                "app_version": gate.app_version,
                "build_number": gate.build_number,
            },
        ),
        gate,
    )


def _artifact_input(name: str, path: str | Path) -> DossierInput:
    resolved, descriptor, digest, size = _open_input(path)
    os.close(descriptor)
    return DossierInput(
        "artifact",
        _safe_name(name),
        resolved,
        size,
        digest,
        {"original_name": resolved.name},
    )


def _tar_info(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o600
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def export_release_dossier(
    *,
    project: ReleaseProject,
    source_sha: str,
    release_scope: str,
    run_bundles: Iterable[tuple[str, str | Path]],
    observations: Iterable[tuple[str, str | Path]],
    gates: Iterable[str | Path],
    artifacts: Iterable[tuple[str, str | Path]],
    output: str | Path,
) -> Path:
    if _SOURCE_SHA.fullmatch(source_sha) is None:
        raise DossierError("dossier source SHA must be a full lowercase Git SHA")
    entries: list[DossierInput] = []
    entries.extend(_run_input(name, path, source_sha) for name, path in run_bundles)
    entries.extend(
        _observation_input(name, path, source_sha, project.digest)
        for name, path in observations
    )
    parsed_gates: dict[str, GateAttestation] = {}
    for path in gates:
        entry, gate = _gate_input(path, source_sha, project.digest)
        if gate.gate in parsed_gates:
            raise DossierError(f"duplicate gate attestation: {gate.gate}")
        parsed_gates[gate.gate] = gate
        entries.append(entry)
        for index, evidence in enumerate(gate.evidence, 1):
            evidence_path = evidence.get("path")
            if not isinstance(evidence_path, str):
                raise DossierError(
                    f"gate {gate.gate} lacks a local evidence path for export"
                )
            artifact_entry = _artifact_input(
                f"gate-{gate.gate}-{index}", evidence_path
            )
            if (
                artifact_entry.size != evidence.get("size")
                or artifact_entry.sha256 != evidence.get("sha256")
            ):
                raise DossierError(
                    f"gate evidence changed after attestation: {gate.gate}"
                )
            entries.append(artifact_entry)
    entries.extend(_artifact_input(name, path) for name, path in artifacts)
    names = [(entry.kind, entry.name) for entry in entries]
    if len(set(names)) != len(names):
        raise DossierError("dossier contains duplicate entry names")
    try:
        required = set(project.required_gate_names(release_scope))
    except ReleaseProjectError as exc:
        raise DossierError(str(exc)) from exc
    missing = sorted(required - set(parsed_gates))
    failed = sorted(
        name
        for name in required
        if parsed_gates.get(name) is not None
        and parsed_gates[name].status != "passed"
    )
    if missing:
        raise DossierError(f"required release gate is missing: {missing[0]}")
    if failed:
        raise DossierError(f"required release gate has not passed: {failed[0]}")
    apple_observations = {
        entry.metadata.get("observation_sha256")
        for entry in entries
        if entry.kind == "observation" and entry.metadata.get("provider") == "apple"
    }
    for gate in parsed_gates.values():
        if (
            gate.apple_observation_digest is not None
            and gate.apple_observation_digest not in apple_observations
        ):
            raise DossierError(
                f"gate {gate.gate} references an Apple observation not included in dossier"
            )
    record: dict[str, object] = {
        "schema_version": _SCHEMA,
        "project": project.public_payload(),
        "project_digest": project.digest,
        "source_sha": source_sha,
        "release_scope": release_scope,
        "required_gates": sorted(required),
        "entries": [
            entry.payload()
            for entry in sorted(entries, key=lambda item: (item.kind, item.name))
        ],
    }
    record["record_sha256"] = _digest(record)
    record_bytes = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(record_bytes) > _MAX_RECORD_BYTES:
        raise DossierError("dossier record exceeds the size limit")
    project_path, project_descriptor, project_sha256, project_size = _open_input(project.path)
    os.close(project_descriptor)
    if project_sha256 != project.digest:
        raise DossierError("release project changed after it was loaded")
    total_size = len(record_bytes) + project_size + sum(entry.size for entry in entries)
    if total_size > _MAX_BUNDLE_BYTES:
        raise DossierError("dossier exceeds the size limit")
    destination = Path(output).expanduser()
    if destination.name in {"", ".", ".."}:
        raise DossierError("dossier output must name a file")
    try:
        parent = destination.parent.resolve(strict=True)
    except OSError as exc:
        raise DossierError("dossier output directory is unavailable") from exc
    destination = parent / destination.name
    if os.path.lexists(destination):
        raise DossierError(f"refusing to overwrite existing dossier: {destination}")
    temporary = parent / f".shipyard-dossier-{secrets.token_hex(16)}"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "w+b", closefd=False) as raw:
            with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as archive:
                archive.addfile(
                    _tar_info("dossier.json", len(record_bytes)), io.BytesIO(record_bytes)
                )
                project_descriptor = open_relative_regular(
                    Path("/"), project_path.relative_to(Path("/")).as_posix()
                )
                try:
                    digest, size = _stream_digest(project_descriptor)
                    if digest != project_sha256 or size != project_size:
                        raise DossierError("release project changed during dossier export")
                    with os.fdopen(project_descriptor, "rb", closefd=False) as source:
                        archive.addfile(_tar_info("project.toml", project_size), source)
                finally:
                    os.close(project_descriptor)
                for entry in sorted(entries, key=lambda item: (item.kind, item.name)):
                    source_descriptor = open_relative_regular(
                        Path("/"), entry.path.relative_to(Path("/")).as_posix()
                    )
                    try:
                        digest, size = _stream_digest(source_descriptor)
                        if digest != entry.sha256 or size != entry.size:
                            raise DossierError(f"dossier input changed during export: {entry.name}")
                        with os.fdopen(source_descriptor, "rb", closefd=False) as source:
                            archive.addfile(
                                _tar_info(entry.member_name, entry.size), source
                            )
                    finally:
                        os.close(source_descriptor)
            raw.flush()
            os.fsync(descriptor)
        os.fchmod(descriptor, 0o600)
        report = verify_release_dossier(temporary)
        if report.get("valid") is not True:
            failures = report.get("errors")
            detail = (
                "; ".join(str(error) for error in failures)
                if isinstance(failures, list)
                else "unknown verification failure"
            )
            raise DossierError("generated dossier failed verification: " + detail)
        os.link(temporary, destination, follow_symlinks=False)
        os.unlink(temporary)
        return destination
    except FileExistsError as exc:
        raise DossierError(f"refusing to overwrite existing dossier: {destination}") from exc
    except (OSError, tarfile.TarError) as exc:
        raise DossierError("cannot export release dossier") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _invalid(errors: list[str]) -> dict[str, object]:
    return {
        "schema_version": _SCHEMA,
        "valid": False,
        "source_sha": None,
        "release_scope": None,
        "project_digest": None,
        "runs_verified": 0,
        "observations_verified": 0,
        "gates_verified": 0,
        "artifacts_verified": 0,
        "errors": errors,
    }


def _load_json(raw: bytes) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise DossierError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=reject_duplicates)


def verify_release_dossier(bundle: str | Path) -> dict[str, object]:
    path = Path(bundle).expanduser()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        return _invalid([f"cannot open dossier: {exc.strerror}"])
    temporary_children: list[Path] = []
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_BUNDLE_BYTES:
            return _invalid(["dossier must be a bounded regular file"])
        with os.fdopen(descriptor, "rb", closefd=False) as raw:
            try:
                with tarfile.open(fileobj=raw, mode="r:") as archive:
                    members: dict[str, tarfile.TarInfo] = {}
                    total = 0
                    for index, member in enumerate(archive):
                        if index >= _MAX_MEMBERS:
                            return _invalid(["dossier contains too many members"])
                        pure = PurePosixPath(member.name)
                        if (
                            not member.isreg()
                            or pure.is_absolute()
                            or any(part in {"", ".", ".."} for part in pure.parts)
                            or member.name in members
                        ):
                            return _invalid([f"unsafe or duplicate dossier member: {member.name}"])
                        total += member.size
                        if total > _MAX_BUNDLE_BYTES:
                            return _invalid(["dossier contents exceed the size limit"])
                        members[member.name] = member
                    manifest_member = members.get("dossier.json")
                    if manifest_member is None or manifest_member.size > _MAX_RECORD_BYTES:
                        return _invalid(["dossier.json is missing or oversized"])
                    manifest_file = archive.extractfile(manifest_member)
                    if manifest_file is None:
                        return _invalid(["cannot read dossier.json"])
                    try:
                        record = _load_json(manifest_file.read())
                    except (DossierError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                        return _invalid([f"invalid dossier JSON: {exc}"])
                    if not isinstance(record, dict):
                        return _invalid(["dossier record must be an object"])
                    digest = record.get("record_sha256")
                    unsigned = dict(record)
                    unsigned.pop("record_sha256", None)
                    errors: list[str] = []
                    if (
                        record.get("schema_version") != _SCHEMA
                        or not isinstance(digest, str)
                        or _SHA256.fullmatch(digest) is None
                        or _digest(unsigned) != digest
                    ):
                        errors.append("dossier record digest or schema is invalid")
                    source_sha = record.get("source_sha")
                    project_digest = record.get("project_digest")
                    release_scope = record.get("release_scope")
                    if (
                        not isinstance(source_sha, str)
                        or _SOURCE_SHA.fullmatch(source_sha) is None
                        or not isinstance(project_digest, str)
                        or _SHA256.fullmatch(project_digest) is None
                        or release_scope not in {"internal", "external", "production"}
                    ):
                        errors.append("dossier identity is invalid")
                    project = record.get("project")
                    if not isinstance(project, dict) or project.get("digest") != project_digest:
                        errors.append("dossier project identity is invalid")
                    entries = record.get("entries")
                    if not isinstance(entries, list):
                        errors.append("dossier entries must be an array")
                        entries = []
                    expected_members = {"dossier.json", "project.toml"}
                    counts = {"run": 0, "observation": 0, "gate": 0, "artifact": 0}
                    gate_status: dict[str, str] = {}
                    gate_evidence: dict[str, tuple[dict[str, object], ...]] = {}
                    artifact_hashes: dict[str, tuple[int, str]] = {}
                    apple_observation_digests: set[str] = set()
                    gate_observation_refs: list[tuple[str, str]] = []
                    seen_entries: set[tuple[str, str]] = set()
                    with tempfile.TemporaryDirectory(
                        prefix="shipyard-dossier-verify-"
                    ) as directory:
                        temp_root = Path(directory).resolve(strict=True)
                        recomputed_required: tuple[str, ...] = ()
                        project_member = members.get("project.toml")
                        if project_member is None or project_member.size > 1024 * 1024:
                            errors.append("hash-bound release project is missing or oversized")
                        else:
                            extracted_project = archive.extractfile(project_member)
                            assert extracted_project is not None
                            project_bytes = extracted_project.read()
                            project_path = temp_root / "project.toml"
                            project_path.write_bytes(project_bytes)
                            project_path.chmod(0o600)
                            try:
                                parsed_project = load_release_project(project_path)
                                if (
                                    parsed_project.digest != project_digest
                                    or parsed_project.public_payload() != project
                                ):
                                    errors.append("dossier project identity is invalid")
                                elif isinstance(release_scope, str):
                                    recomputed_required = parsed_project.required_gate_names(
                                        release_scope
                                    )
                            except ReleaseProjectError as exc:
                                errors.append(f"dossier release project is invalid: {exc}")
                        for entry in entries:
                            if not isinstance(entry, dict):
                                errors.append("dossier entry is not an object")
                                continue
                            kind = entry.get("kind")
                            name = entry.get("name")
                            member_name = entry.get("member")
                            size = entry.get("size")
                            expected_digest = entry.get("sha256")
                            entry_metadata = entry.get("metadata")
                            if (
                                kind not in counts
                                or not isinstance(name, str)
                                or _NAME.fullmatch(name) is None
                                or not isinstance(member_name, str)
                                or not isinstance(size, int)
                                or isinstance(size, bool)
                                or size < 0
                                or not isinstance(expected_digest, str)
                                or _SHA256.fullmatch(expected_digest) is None
                                or not isinstance(entry_metadata, dict)
                                or (kind, name) in seen_entries
                            ):
                                errors.append("dossier entry identity is invalid")
                                continue
                            seen_entries.add((kind, name))
                            expected_members.add(member_name)
                            member = members.get(member_name)
                            if member is None:
                                errors.append(f"dossier member is missing: {member_name}")
                                continue
                            extracted = archive.extractfile(member)
                            if extracted is None:
                                errors.append(f"cannot read dossier member: {member_name}")
                                continue
                            digest_stream = hashlib.sha256()
                            read_size = 0
                            child_path: Path | None = None
                            child_file = None
                            if kind == "run":
                                child_path = temp_root / f"run-{len(temporary_children)}.tar"
                                child_file = child_path.open("wb")
                                temporary_children.append(child_path)
                            try:
                                while chunk := extracted.read(1024 * 1024):
                                    digest_stream.update(chunk)
                                    read_size += len(chunk)
                                    if child_file is not None:
                                        child_file.write(chunk)
                            finally:
                                if child_file is not None:
                                    child_file.close()
                            if read_size != size or digest_stream.hexdigest() != expected_digest:
                                errors.append(f"dossier member hash mismatch: {member_name}")
                                continue
                            if kind == "run" and child_path is not None:
                                child_report = verify_evidence_bundle(child_path)
                                if (
                                    child_report.get("valid") is not True
                                    or child_report.get("source_sha") != source_sha
                                    or child_report.get("run_id") != entry_metadata.get("run_id")
                                ):
                                    errors.append(f"child run evidence is invalid: {name}")
                                    continue
                            elif kind == "observation":
                                extracted_again = archive.extractfile(member)
                                assert extracted_again is not None
                                try:
                                    observation = ReleaseObservation.from_payload(
                                        _load_json(extracted_again.read())
                                    )
                                except (
                                    ObservationError,
                                    DossierError,
                                    json.JSONDecodeError,
                                ) as exc:
                                    errors.append(f"observation is invalid: {name}: {exc}")
                                    continue
                                if (
                                    observation.source_sha != source_sha
                                    or observation.project_digest != project_digest
                                    or observation.digest
                                    != entry_metadata.get("observation_sha256")
                                ):
                                    errors.append(f"observation identity is invalid: {name}")
                                    continue
                                if observation.provider == "apple":
                                    apple_observation_digests.add(observation.digest)
                            elif kind == "gate":
                                extracted_again = archive.extractfile(member)
                                assert extracted_again is not None
                                try:
                                    gate = GateAttestation.from_payload(
                                        _load_json(extracted_again.read())
                                    )
                                except (GateError, DossierError, json.JSONDecodeError) as exc:
                                    errors.append(f"gate is invalid: {name}: {exc}")
                                    continue
                                if (
                                    gate.source_sha != source_sha
                                    or gate.project_digest != project_digest
                                ):
                                    errors.append(f"gate identity is invalid: {name}")
                                    continue
                                gate_status[gate.gate] = gate.status
                                gate_evidence[gate.gate] = gate.evidence
                                if gate.apple_observation_digest is not None:
                                    gate_observation_refs.append(
                                        (gate.gate, gate.apple_observation_digest)
                                    )
                            if kind == "artifact":
                                artifact_hashes[name] = (size, expected_digest)
                            counts[kind] += 1
                        undeclared = set(members) - expected_members
                        if undeclared:
                            errors.append(
                                f"dossier contains undeclared member: {sorted(undeclared)[0]}"
                            )
                    required = record.get("required_gates")
                    if not isinstance(required, list) or any(
                        not isinstance(name, str) for name in required
                    ):
                        errors.append("required gate list is invalid")
                        required = []
                    elif tuple(required) != recomputed_required:
                        errors.append(
                            "dossier required gate policy does not match embedded project"
                        )
                    for gate_name in recomputed_required:
                        if gate_status.get(gate_name) != "passed":
                            errors.append(f"required release gate has not passed: {gate_name}")
                    for gate_name, evidence_records in gate_evidence.items():
                        for index, evidence in enumerate(evidence_records, 1):
                            expected = artifact_hashes.get(
                                f"gate-{gate_name}-{index}"
                            )
                            if expected != (
                                evidence.get("size"),
                                evidence.get("sha256"),
                            ):
                                errors.append(
                                    f"gate {gate_name} evidence is missing from dossier"
                                )
                    for gate_name, observation_digest in gate_observation_refs:
                        if observation_digest not in apple_observation_digests:
                            errors.append(
                                f"gate {gate_name} references a missing Apple observation"
                            )
                    return {
                        "schema_version": _SCHEMA,
                        "valid": not errors,
                        "source_sha": source_sha if isinstance(source_sha, str) else None,
                        "release_scope": release_scope if isinstance(release_scope, str) else None,
                        "project_digest": (
                            project_digest if isinstance(project_digest, str) else None
                        ),
                        "runs_verified": counts["run"],
                        "observations_verified": counts["observation"],
                        "gates_verified": counts["gate"],
                        "artifacts_verified": counts["artifact"],
                        "required_gates": list(recomputed_required),
                        "errors": errors,
                    }
            except (OSError, tarfile.TarError) as exc:
                return _invalid([f"invalid dossier archive: {exc}"])
    finally:
        os.close(descriptor)
