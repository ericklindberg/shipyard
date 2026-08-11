from __future__ import annotations

import re
from dataclasses import dataclass

_SHA = re.compile(r"^[0-9a-f]{40}$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_NUMERIC = re.compile(r"^[1-9][0-9]*$")
_WORKFLOW_FILE = re.compile(r"^[A-Za-z0-9_.-]+\.ya?ml$")

# Exact commit already used and reviewed by this repository's workflows (checkout v7).
_CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"


class BootstrapInputError(ValueError):
    pass


@dataclass(frozen=True)
class BootstrapBundle:
    owner: str
    repo: str
    source_sha: str
    files: dict[str, str]


def _canonical_name(value: str, label: str) -> None:
    if not value or not _NAME.fullmatch(value) or value.endswith(".git"):
        raise BootstrapInputError(f"invalid canonical {label}")


def plan_github_bootstrap(
    owner: str,
    repo: str,
    source_sha: str,
    *,
    repository_id: str,
    workflow_id: str,
    workflow_file: str = "shipyard.yml",
) -> BootstrapBundle:
    """Generate deterministic local files; perform no GitHub calls or writes."""
    _canonical_name(owner, "owner")
    _canonical_name(repo, "repo")
    if not _SHA.fullmatch(source_sha):
        raise BootstrapInputError("source_sha must be an immutable 40-character commit SHA")
    if not _NUMERIC.fullmatch(repository_id) or not _NUMERIC.fullmatch(workflow_id):
        raise BootstrapInputError(
            "repository_id and workflow_id must be canonical numeric ids"
        )
    if not _WORKFLOW_FILE.fullmatch(workflow_file):
        raise BootstrapInputError("workflow_file must be a workflow YAML file name")

    target = f"{owner}/{repo}"
    destination = (
        f"github-actions:{repository_id}:{workflow_id}:"
        "refs/tags/shipyard-candidate-{source_sha}"
    )
    workflow = f'''name: Shipyard exact-source contract

on:
  workflow_dispatch:
    inputs:
      source_sha:
        description: Exact approved source SHA
        required: true
        type: string

permissions:
  contents: read

jobs:
  exact-source:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{_CHECKOUT_SHA} # v7
        with:
          ref: ${{{{ inputs.source_sha }}}}
          persist-credentials: false
      - name: Verify immutable dispatched source
        env:
          EXPECTED_SHA: ${{{{ inputs.source_sha }}}}
          DISPATCH_SHA: ${{{{ github.sha }}}}
        run: |
          case "$EXPECTED_SHA" in
            ""|*[!0-9a-f]*) echo "source_sha is not hexadecimal" >&2; exit 1 ;;
          esac
          test "${{#EXPECTED_SHA}}" -eq 40
          test "$DISPATCH_SHA" = "$EXPECTED_SHA"
          test "$(git rev-parse HEAD)" = "$EXPECTED_SHA"
          echo "Exact source identity verified; this workflow performs no provider mutation."
'''
    readme = f'''# Shipyard GitHub bootstrap

Target: `{target}`
Initial exact source: `{source_sha}`
Repository ID: `{repository_id}`
Workflow ID: `{workflow_id}`

These files were generated locally without GitHub access. The workflow validates source
identity only. The Shipyard playbook dispatch remains an external action and therefore
requires exact-candidate approval plus explicit execution.
'''
    playbook = f'''schema_version = 2
name = "github-bootstrap"
target = "{target}"
provider = "github-actions"
destination = "{destination}"
allow_dirty = false

[[steps]]
id = "github-workflow"
name = "Dispatch the exact approved workflow"
effect = "external"
action = "github.workflow"

[steps.config]
owner = "{owner}"
repo = "{repo}"
repository_id = "{repository_id}"
workflow_id = "{workflow_id}"
workflow_file = "{workflow_file}"
ref = "refs/tags/shipyard-candidate-{{source_sha}}"
token_env = "GITHUB_ACTIONS_TOKEN"
'''
    return BootstrapBundle(
        owner,
        repo,
        source_sha,
        {
            f".github/workflows/{workflow_file}": workflow,
            "SHIPYARD_BOOTSTRAP.md": readme,
            "shipyard.toml": playbook,
        },
    )
