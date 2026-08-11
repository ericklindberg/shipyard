"""Deterministic, offline evidence report rendering."""

from __future__ import annotations

import html
import json
import os
import shutil
import stat
import tarfile
import tempfile
from pathlib import Path
from typing import Any

from .evidence import verify_evidence_bundle

_INVALID_REPORT = {
    "valid": False,
    "errors": ["verified evidence could not be parsed from a regular bundle snapshot"],
}
_FIELDS = (
    ("Run", "run_id"),
    ("Status", "status"),
    ("Source SHA", "source_sha"),
    ("Candidate digest", "candidate_digest"),
    ("Approval", "approval_present"),
    ("Destination", "destination"),
)


def _snapshot_bundle(source: Path, target: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError("bundle must be a regular file")
        with (
            os.fdopen(descriptor, "rb", closefd=False) as source_file,
            target.open("wb") as target_file,
        ):
            shutil.copyfileobj(source_file, target_file)
            target_file.flush()
            os.fsync(target_file.fileno())
    finally:
        os.close(descriptor)


def load_verified_report(bundle: str | Path) -> dict[str, Any]:
    """Verify and parse one immutable local snapshot of an evidence bundle."""
    if not isinstance(bundle, (str, Path)):
        raise ValueError("evidence report input must be a bundle path")
    try:
        with tempfile.TemporaryDirectory(prefix="shipyard-report-") as directory:
            snapshot = Path(directory) / "bundle.tar"
            _snapshot_bundle(Path(bundle).expanduser(), snapshot)
            result = verify_evidence_bundle(snapshot)
            if result.get("valid") is not True:
                return dict(result)
            with tarfile.open(snapshot, "r:") as archive:
                member = archive.extractfile("evidence.json")
                if member is None:
                    raise ValueError("missing evidence.json")
                envelope = json.load(member)
            if not isinstance(envelope, dict) or not isinstance(envelope.get("run"), dict):
                raise ValueError("evidence run record is malformed")
            bound = dict(result)
            bound["record"] = envelope["run"]
            return bound
    except (
        OSError,
        tarfile.TarError,
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ):
        return dict(_INVALID_REPORT)


def render_report(bundle: str | Path, *, format: str = "markdown") -> str:
    """Verify a bundle snapshot and render it as Markdown or standalone HTML."""
    if format not in {"markdown", "html"}:
        raise ValueError("format must be markdown or html")
    evidence = load_verified_report(bundle)
    return render_markdown(evidence) if format == "markdown" else render_html(evidence)


def _record(evidence: dict[str, Any]) -> dict[str, Any]:
    record = evidence.get("record")
    return record if isinstance(record, dict) else {}


def _value(evidence: dict[str, Any], record: dict[str, Any], key: str) -> Any:
    return record.get(key, evidence.get(key, "—"))


def render_markdown(evidence: dict[str, Any]) -> str:
    valid = evidence.get("valid") is True
    record = _record(evidence)
    lines = ["# Shipyard evidence report", "", f"**Verdict:** {'VERIFIED' if valid else 'INVALID'}"]
    lines.extend(
        f"- **{label}:** {_markdown(_value(evidence, record, key))}"
        for label, key in _FIELDS
    )
    lines.extend(
        [
            "",
            "## Verification",
            f"- Audit chain: {_markdown(evidence.get('audit_chain_valid', False))}",
            f"- Receipts: {_markdown(evidence.get('receipts_verified', 0))}",
            "- Artifacts: "
            f"{_markdown(evidence.get('artifacts_verified', 0))}/"
            f"{_markdown(evidence.get('artifacts_declared', 0))}",
            "",
            "## Timeline / steps",
        ]
    )
    steps = record.get("steps", [])
    if isinstance(steps, list):
        for index, step in enumerate(steps, 1):
            if isinstance(step, dict):
                name = step.get("name", step.get("id", "step"))
                lines.append(
                    f"{index}. {_markdown(name)} — {_markdown(step.get('status', ''))}"
                )
    lines.extend(["", "## Errors"])
    errors = evidence.get("errors", [])
    if isinstance(errors, list):
        lines.extend(f"- {_markdown(error)}" for error in errors)
    return "\n".join(lines) + "\n"


def render_html(evidence: dict[str, Any]) -> str:
    valid = evidence.get("valid") is True
    record = _record(evidence)

    def escaped(value: Any) -> str:
        return html.escape(str(value), quote=True)

    rows = "".join(
        f"<tr><th>{escaped(label)}</th><td>{escaped(_value(evidence, record, key))}</td></tr>"
        for label, key in _FIELDS
    )
    steps = record.get("steps", [])
    step_items = ""
    if isinstance(steps, list):
        step_items = "".join(
            f"<li>{escaped(step.get('name', step.get('id', 'step')))} — "
            f"{escaped(step.get('status', ''))}</li>"
            for step in steps
            if isinstance(step, dict)
        )
    errors = evidence.get("errors", [])
    error_items = ""
    if isinstance(errors, list):
        error_items = "".join(f"<li>{escaped(error)}</li>" for error in errors)
    verdict = "VERIFIED" if valid else "INVALID"
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        "<title>Shipyard evidence report</title><style>"
        "body{font:16px sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}"
        "table{border-collapse:collapse;width:100%}"
        "th,td{padding:.4rem;text-align:left;border-bottom:1px solid #ccc}"
        "</style></head><body><main><h1>Shipyard evidence report</h1>"
        f"<p><strong>Verdict:</strong> {verdict}</p><table>{rows}</table>"
        "<h2>Verification</h2>"
        f"<p>Audit chain: {escaped(evidence.get('audit_chain_valid', False))}; "
        f"receipts: {escaped(evidence.get('receipts_verified', 0))}; "
        f"artifacts: {escaped(evidence.get('artifacts_verified', 0))}/"
        f"{escaped(evidence.get('artifacts_declared', 0))}</p>"
        f"<h2>Timeline / steps</h2><ol>{step_items}</ol>"
        f"<h2>Errors</h2><ul>{error_items}</ul></main></body></html>\n"
    )


def _markdown(value: Any) -> str:
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("`", "\\`")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", " ")
        .replace("\r", " ")
    )
