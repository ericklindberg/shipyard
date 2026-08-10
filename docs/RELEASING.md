# Releasing Shipyard

Shipyard releases are exact-SHA evidence exercises. CI never deploys providers or publishes packages.

## Candidate gates

1. Freeze the source tree and run `git diff --check`.
2. Run Ruff, ty, selected Bandit, the complete test suite, and `uv build`.
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
8. Install the exact wheel in a fresh virtual environment with `pip --no-index` and run the onboarding smoke.
9. Generate `dist/shipyard-0.3.0.cdx.json` and `dist/SHA256SUMS` with the locked tools and repository scripts.
10. Verify the checksum file names exactly the expected wheel, source archive, and SBOM.

## Buzz-first promotion

Shipyard development is promoted to Buzz first. GitHub is a CI/distribution mirror:

1. Push the exact validated candidate SHA to the protected Buzz repository branch.
2. Read back that branch from Buzz and compare the full SHA.
3. Push that same SHA—not a rebuilt or amended commit—to GitHub.
4. Read back `refs/heads/main` from GitHub and compare the full SHA.
5. Wait for GitHub CI to pass at that SHA.

Do not develop directly on the GitHub mirror or treat a GitHub-only commit as deployable.

## Attested evidence

The `Release evidence` workflow is manual and requires a full 40-character `candidate_sha`. It:

- checks out and independently verifies that exact SHA;
- reruns formatting, typing, security, test, dependency, secret, and build gates;
- generates the reproducible CycloneDX SBOM and deterministic SHA-256 file;
- creates GitHub artifact attestations using OIDC; and
- uploads the evidence bundle without publishing it to a package registry.

The workflow pins every third-party action to an immutable commit. CI and evidence workflows have no provider credentials and no deployment steps.

## Privacy gate

Before broad promotion, inspect all reachable Git objects and release artifacts—not only the working tree—for credentials, personal contact information, local paths, and account-specific destinations. Historical remediation is a repository-owner decision because deleting/recreating or rewriting a public repository changes commit identity and can disrupt consumers.

## Provider status

Provider support remains beta until the exact candidate passes the live sandbox process in [PROVIDER_VALIDATION.md](PROVIDER_VALIDATION.md). Missing profiles, targets, or credential references are recorded as unavailable, never converted into passing evidence.
