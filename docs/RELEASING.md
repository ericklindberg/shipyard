# Releasing Shipyard

Shipyard releases are exact-SHA evidence exercises. CI never deploys providers or publishes packages.

## Candidate gates

1. Freeze the source tree and run `git diff --check`.
2. Run Ruff, ty, selected Bandit, the complete test suite, and
   `python scripts/build_release_artifacts.py --directory dist` from a clean
   exact-SHA worktree. The builder derives `SOURCE_DATE_EPOCH` from the commit
   and normalizes archive metadata for reproducible artifacts. Wheel normalization
   intentionally accepts only non-ZIP64 ZIP32 archives with Unix metadata, plain
   stored/deflated members, regular-file/directory types, and matching contiguous
   local/central records. It rejects ambiguous or special-file archive semantics
   instead of rewriting them.
3. Run `python scripts/scan_tracked_secrets.py --root .`.
4. Export the locked development dependency set and audit it:

   ```sh
   requirements="$(mktemp)"
   trap 'rm -f "$requirements"' EXIT
   uv export --extra dev --no-emit-project --locked --output-file "$requirements"
   uv run pip-audit --requirement "$requirements" --require-hashes \
     --disable-pip --strict --progress-spinner off
   ```

5. Commit once and record the full SHA.
6. Create a detached, clean worktree at that SHA and repeat all gates there.
7. Build the wheel and source archive only from that detached worktree.
8. Export the locked runtime dependency closure with hashes, install it into a fresh virtual environment, then install the exact canonical wheel with `--no-deps` so no resolver can substitute the artifact. Run `scripts/smoke_installed_release.py` against that installed executable on Linux and macOS.
9. Run `python scripts/resolve_release_artifacts.py --directory dist` after the build. It derives the exact wheel, source archive, runtime-SBOM, and build-SBOM names from Shipyard's canonical source version and fails if build outputs are missing, ambiguous, or version-mismatched.
10. Generate the two SBOMs and `dist/SHA256SUMS` using only the resolver-provided names; verify the checksum file names exactly the expected wheel, source archive, runtime SBOM, and build-environment SBOM.
11. Export a representative completed run with `shipyard evidence export` and verify it from a directory with no ledger access using `shipyard evidence verify`. Also export and offline-verify an internal-scope aggregate release dossier.

## Buzz-first promotion

Shipyard development is promoted to Buzz first. GitHub is a CI/distribution mirror:

1. Push the exact validated candidate SHA to the protected Buzz repository branch.
2. Read back that branch from Buzz and compare the full SHA.
3. Push that same SHA—not a rebuilt or amended commit—to GitHub.
4. Read back `refs/heads/main` from GitHub and compare the full SHA.
5. Wait for GitHub CI to pass at that SHA.

Do not develop directly on the GitHub mirror or treat a GitHub-only commit as deployable.

## Attested evidence

The `Release evidence` workflow is manual and consumes the two fields emitted by
Shipyard's typed GitHub workflow adapter: `shipyard_candidate_sha` and
`shipyard_run_id`. Before any build step, `scripts/verify_candidate_tag.py` proves
that the dispatch ref resolves to an annotated candidate tag object named
`shipyard-candidate-<SHA>` that directly references the approved commit. It rejects
lightweight and nested tags. The workflow then:

- checks out and independently verifies that exact SHA;
- reruns formatting, typing, security, test, dependency, secret, and build gates;
- generates separate reproducible runtime and build-environment CycloneDX SBOMs plus a deterministic SHA-256 file;
- creates GitHub artifact attestations using OIDC; and
- uploads the attested release artifacts without publishing them to a package registry.

The workflow pins every third-party action to an immutable commit. CI and evidence workflows have no provider credentials and no deployment steps.

## Privacy gate

Before broad promotion, inspect all reachable Git objects and release artifacts—not only the working tree—for credentials, personal contact information, local paths, and account-specific destinations. Historical remediation is a repository-owner decision because deleting/recreating or rewriting a public repository changes commit identity and can disrupt consumers.

## Provider status

Provider support remains beta until the exact candidate passes the live sandbox process in [PROVIDER_VALIDATION.md](PROVIDER_VALIDATION.md). Missing profiles, targets, or credential references are recorded as unavailable, never converted into passing evidence.
