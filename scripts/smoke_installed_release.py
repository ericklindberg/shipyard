from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path


class SmokeError(RuntimeError):
    pass


_SOURCE_SHA = re.compile(r"^[0-9a-f]{40}$")


def _run(
    executable: Path,
    *arguments: str,
    cwd: Path | None = None,
    accepted_returncodes: tuple[int, ...] = (0,),
) -> dict[str, object]:
    result = subprocess.run(
        [str(executable), *arguments, "--json"],
        cwd=cwd,
        env={
            "HOME": os.environ.get("HOME", str(Path.home())),
            "PATH": os.environ.get("PATH", ""),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        },
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
        check=False,
        timeout=120,
    )
    if result.returncode not in accepted_returncodes:
        raise SmokeError(
            f"installed command failed ({result.returncode}): "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    try:
        envelope = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SmokeError("installed command did not emit valid JSON") from exc
    if not isinstance(envelope, dict) or envelope.get("api_version") != "shipyard.cli/v1":
        raise SmokeError("installed command emitted the wrong JSON API version")
    if envelope.get("ok") is not True:
        raise SmokeError("installed command returned an unsuccessful JSON envelope")
    data = envelope.get("data")
    if not isinstance(data, dict):
        raise SmokeError("installed command JSON data is malformed")
    return data


def _run_help(executable: Path, *arguments: str) -> None:
    result = subprocess.run(
        [str(executable), *arguments, "--help"],
        env={
            "HOME": os.environ.get("HOME", str(Path.home())),
            "PATH": os.environ.get("PATH", ""),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        },
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0 or "usage: shipyard" not in result.stdout:
        raise SmokeError("installed standalone command namespace is unavailable")


def _write_project(path: Path) -> None:
    content = '''schema_version = 1
name = "installed-wheel-smoke"
source_remote = "https://github.com/example/example.git"

[github]
owner = "example"
repo = "example"
repository_id = "1234"
required_workflow_ids = ["101"]
token_env = "GITHUB_ACTIONS_TOKEN"

[apple]
workflow_id = "workflow-1"
source_remote = "https://github.com/example/example.git"
source_git_remote = "origin"
bundle_id = "com.example.app"
beta_group_name = "Testing"
expected_marketing_version = "1.0"
token_env = "APPLE_ASC_TOKEN"

[[gates]]
name = "physical-device"
required_for = ["external", "production"]
'''
    path.write_text(content, encoding="utf-8")
    path.chmod(0o644)


def smoke(executable: Path, expected_version: str, expected_source_sha: str) -> None:
    if not executable.is_file() or executable.is_symlink():
        raise SmokeError("installed Shipyard executable must be a regular file")
    if _SOURCE_SHA.fullmatch(expected_source_sha) is None:
        raise SmokeError("expected source SHA must be a full lowercase Git identity")
    root = Path(tempfile.mkdtemp(prefix="shipyard-installed-smoke-")).resolve(strict=True)
    try:
        version = _run(executable, "version")
        if version.get("package_version") != expected_version:
            raise SmokeError("installed Shipyard version does not match the built wheel")
        if version.get("source_sha") != expected_source_sha:
            raise SmokeError("installed Shipyard source SHA does not match the built wheel")

        for command in (
            ("app-review", "init"),
            ("release",),
            ("release", "project", "init"),
            ("release", "wait"),
            ("release", "inspect"),
            ("release", "playbook"),
            ("release", "observation", "list"),
            ("release", "gate", "attest"),
            ("release", "dossier", "export"),
            ("release", "dossier", "verify"),
        ):
            _run_help(executable, *command)

        app_review_manifest = root / "app-review.json"
        app_review = _run(
            executable,
            "app-review", "init", "--output", str(app_review_manifest),
        )
        if (
            app_review.get("secrets_stored") is not False
            or app_review.get("network_access") is not False
            or app_review.get("provider_mutations") != 0
        ):
            raise SmokeError("installed App Review scaffold crossed its local-only boundary")
        if stat.S_IMODE(app_review_manifest.stat().st_mode) != 0o600:
            raise SmokeError("installed App Review scaffold is not private")
        app_review_preflight = _run(
            executable,
            "app-review", "preflight", str(app_review_manifest),
            accepted_returncodes=(1,),
        )
        if (
            app_review_preflight.get("status") != "blocked"
            or app_review_preflight.get("network_access") is not False
            or app_review_preflight.get("provider_mutations") != 0
        ):
            raise SmokeError("installed App Review scaffold was not conservatively blocked")

        quickstart = _run(executable, "quickstart", str(root / "quickstart"))
        if (
            quickstart.get("status") != "succeeded"
            or quickstart.get("evidence_verified") is not True
        ):
            raise SmokeError("installed quickstart did not complete with verified evidence")
        source_sha = quickstart.get("source_sha")
        evidence_path = quickstart.get("evidence_path")
        if not isinstance(source_sha, str) or not isinstance(evidence_path, str):
            raise SmokeError("installed quickstart returned incomplete identity evidence")
        evidence = _run(executable, "evidence", "verify", evidence_path)
        if evidence.get("valid") is not True or evidence.get("source_sha") != source_sha:
            raise SmokeError("installed offline evidence verification failed")

        project = root / "shipyard.release.toml"
        initialized = _run(executable, "release", "project", "init", str(project))
        if initialized.get("secrets_stored") is not False:
            raise SmokeError("release project initialization stored unexpected secret data")
        _write_project(project)
        validated = _run(executable, "release", "project", "validate", str(project))
        if validated.get("valid") is not True or validated.get("provider_mutations") != 0:
            raise SmokeError("release project validation was not offline and valid")

        dossier = root / "release-dossier.tar"
        exported = _run(
            executable,
            "release",
            "dossier",
            "export",
            "--project",
            str(project),
            "--source-sha",
            source_sha,
            "--scope",
            "internal",
            "--run",
            f"quickstart={evidence_path}",
            "--output",
            str(dossier),
        )
        if exported.get("valid") is not True or exported.get("release_scope") != "internal":
            raise SmokeError("installed aggregate dossier export failed")
        verified = _run(executable, "release", "dossier", "verify", str(dossier))
        if verified.get("valid") is not True or verified.get("source_sha") != source_sha:
            raise SmokeError("installed aggregate dossier verification failed")
        if stat.S_IMODE(dossier.stat().st_mode) != 0o600:
            raise SmokeError("installed aggregate dossier is not private")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke-test an installed Shipyard wheel")
    parser.add_argument("--shipyard", required=True, type=Path)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-source-sha", required=True)
    args = parser.parse_args()
    smoke(
        args.shipyard.expanduser().resolve(strict=True),
        args.expected_version,
        args.expected_source_sha,
    )
    print(f"installed Shipyard {args.expected_version} smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
