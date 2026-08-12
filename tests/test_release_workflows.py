from __future__ import annotations

from pathlib import Path

from shipyard import __version__

ROOT = Path(__file__).parents[1]


def test_readme_install_url_tracks_the_release_version():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    release_url = (
        "https://github.com/ericklindberg/shipyard/releases/download/"
        f"v{__version__}/shipyard_release-{__version__}-py3-none-any.whl"
    )

    assert release_url in readme
    assert f"[v{__version__} release]" in readme


def test_standalone_release_guide_covers_complete_explicit_control_lifecycle():
    guide = (ROOT / "docs" / "STANDALONE_RELEASE.md").read_text(encoding="utf-8")
    normalized = " ".join(guide.split())

    for contract in (
        "shipyard release project init",
        "shipyard release wait",
        "--phase xcode-build",
        "--phase testflight",
        "shipyard release gate attest",
        "physical-device",
        "shipyard release dossier export",
        "shipyard release dossier verify",
        "No physical-device pass means no external TestFlight mutation",
    ):
        assert contract in guide
    assert "shipyard release wait . --project .shipyard/release.toml" in normalized
    assert "shipyard release inspect . --project .shipyard/release.toml" in normalized
    assert "shipyard release gate attest physical-device --project" in normalized
    assert "--repo ." not in guide
    assert "--gate physical-device" not in guide


def test_installed_smoke_uses_the_runtime_identity_package_version() -> None:
    smoke = (ROOT / "scripts" / "smoke_installed_release.py").read_text(
        encoding="utf-8"
    )

    assert 'version.get("package_version") != expected_version' in smoke
    assert 'version.get("source_sha") != expected_source_sha' in smoke
    assert "--expected-source-sha" in smoke
    assert "_run_help(executable, *command)" in smoke
    assert '("release", "project", "init")' in smoke
    assert '("release", "dossier", "verify")' in smoke
    assert 'version.get("version")' not in smoke
    assert (
        'Path(tempfile.mkdtemp(prefix="shipyard-installed-smoke-")).resolve(strict=True)'
        in smoke
    )


def test_github_actions_example_exposes_shipyard_dispatch_contract_without_mutation():
    example_path = ROOT / "examples/github-actions/release.yml"
    assert example_path.exists()
    workflow = example_path.read_text(encoding="utf-8")

    assert "workflow_dispatch:" in workflow
    assert "shipyard_candidate_sha:" in workflow
    assert "shipyard_run_id:" in workflow
    assert 'test "$GITHUB_SHA" = "$APPROVED_SHA"' in workflow
    assert "contents: read" in workflow
    assert "deploy" not in workflow.casefold()
    assert "publish" not in workflow.casefold()


def test_shipyard_dogfood_workflow_runs_the_complete_exact_sha_gate():
    workflow_path = ROOT / ".github/workflows/shipyard-contract.yml"
    assert workflow_path.exists()
    workflow = workflow_path.read_text(encoding="utf-8")

    for required in (
        "workflow_dispatch:",
        "shipyard_candidate_sha:",
        "shipyard_candidate_tag:",
        "shipyard_run_id:",
        "uv sync --extra dev --locked",
        "uv run pytest -q",
        "uv run ruff check src tests scripts",
        "uv run ty check src scripts",
        "uv run bandit",
        "uv run pip-audit",
        "scripts/scan_tracked_secrets.py",
        "scripts/build_release_artifacts.py --directory dist",
        "scripts/resolve_release_artifacts.py",
        "scripts/smoke_installed_release.py",
        "uv export --no-emit-project --locked",
        "--require-hashes -r dist/runtime-requirements.txt",
        ".installed-smoke/bin/shipyard",
        "SHIPYARD_WHEEL",
        "SHIPYARD_SDIST",
        "SHIPYARD_RUNTIME_SBOM",
        "SHIPYARD_BUILD_SBOM",
        "scripts/write_checksums.py",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    ):
        assert required in workflow
    assert "0.3.0" not in workflow
    assert "ref: ${{ inputs.shipyard_candidate_tag }}" in workflow
    assert 'test "$EXPECTED_TAG" = "shipyard-candidate-$EXPECTED_SHA"' in workflow
    assert (
        'test "$(git rev-parse "refs/tags/$EXPECTED_TAG^{commit}")" = "$EXPECTED_SHA"'
        in workflow
    )
    assert "deploy" not in workflow.casefold()
    assert "publish" not in workflow.casefold()


def test_build_isolation_dependencies_are_exactly_pinned():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert '"setuptools==84.0.0"' in pyproject
    assert '"wheel==0.47.0"' in pyproject
    assert '"packaging==26.3"' in pyproject
    assert '"setuptools>=75"' not in pyproject
    assert 'dynamic = ["version"]' in pyproject
    assert '[tool.setuptools.dynamic]' in pyproject
    assert 'version = { attr = "shipyard.__version__" }' in pyproject
    assert '\nversion = "0.3.0"' not in pyproject


def test_source_distribution_manifest_includes_operator_and_contributor_material():
    manifest_path = ROOT / "MANIFEST.in"
    assert manifest_path.exists()
    manifest = manifest_path.read_text(encoding="utf-8")

    for required in (
        "include CHANGELOG.md CONTRIBUTING.md SECURITY.md ROADMAP.md",
        "recursive-include docs *.md",
        "recursive-include examples *.yml",
        "recursive-include scripts *.py",
        "recursive-include .github/ISSUE_TEMPLATE *.yml",
    ):
        assert required in manifest


def test_ci_covers_linux_and_macos_with_locked_security_gates():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "ubuntu-latest" in workflow
    assert "macos-14" in workflow
    assert 'python-version: "3.11"' in workflow
    assert 'python-version: "3.13"' in workflow
    assert "uv sync --extra dev --locked" in workflow
    assert "uv run pip-audit" in workflow
    assert "scripts/scan_tracked_secrets.py" in workflow
    assert "uv run cyclonedx-py" in workflow
    assert ".runtime-sbom/bin/python" in workflow
    assert "scripts/smoke_installed_release.py" in workflow
    assert "scripts/build_release_artifacts.py --directory dist" in workflow
    assert "- run: uv build" not in workflow
    assert "uv export --no-emit-project --locked" in workflow
    assert "--require-hashes -r dist/runtime-requirements.txt" in workflow
    assert ".installed-smoke/bin/shipyard" in workflow
    assert "scripts/resolve_release_artifacts.py" in workflow
    assert "SHIPYARD_RUNTIME_SBOM" in workflow
    assert "SHIPYARD_BUILD_SBOM" in workflow
    assert "0.3.0" not in workflow
    assert "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a" in workflow
    assert "git diff --exit-code" in workflow


def test_release_evidence_workflow_attests_without_publishing():
    workflow_path = ROOT / ".github/workflows/release-evidence.yml"
    assert workflow_path.exists()
    workflow = workflow_path.read_text(encoding="utf-8")

    assert "workflow_dispatch:" in workflow
    assert "candidate_tag:" in workflow
    assert "id-token: write" in workflow
    assert "attestations: write" in workflow
    assert "actions/attest-build-provenance@43d14bc2b83dec42d39ecae14e916627a18bb661" in workflow
    assert "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a" in workflow
    assert "scripts/write_checksums.py" in workflow
    assert "uv run cyclonedx-py" in workflow
    assert ".runtime-sbom/bin/python" in workflow
    assert "scripts/smoke_installed_release.py" in workflow
    assert "scripts/build_release_artifacts.py --directory dist" in workflow
    assert "- run: uv build" not in workflow
    assert "uv export --no-emit-project --locked" in workflow
    assert "--require-hashes -r dist/runtime-requirements.txt" in workflow
    assert ".installed-smoke/bin/shipyard" in workflow
    assert "scripts/resolve_release_artifacts.py" in workflow
    assert "SHIPYARD_RUNTIME_SBOM" in workflow
    assert "SHIPYARD_BUILD_SBOM" in workflow
    assert "ref: ${{ inputs.candidate_tag }}" in workflow
    assert 'test "$EXPECTED_TAG" = "shipyard-candidate-$EXPECTED_SHA"' in workflow
    assert (
        'test "$(git rev-parse "refs/tags/$EXPECTED_TAG^{commit}")" = "$EXPECTED_SHA"'
        in workflow
    )
    assert "0.3.0" not in workflow
    assert "twine upload" not in workflow
    assert "uv publish" not in workflow
    assert "gh release create" not in workflow
