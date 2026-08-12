# Standalone release lifecycle

Shipyard 0.6.0 can operate a governed release from one installed local CLI without a hosted control plane, helper scripts, copied provider resource IDs, or stored credential values. It remains explicit-control software: read-only discovery may be repeated, but every provider mutation is a separately planned, exact-SHA-approved, one-attempt run.

## 1. Install the canonical artifact

Use the original wheel filename from the signed GitHub release. Do not rename it:

```bash
uv tool install \
  https://github.com/ericklindberg/shipyard/releases/download/v0.6.0/shipyard_release-0.6.0-py3-none-any.whl
shipyard version --json
```

The repository release gate installs that same canonical wheel plus its hash-locked runtime dependency closure into a clean Linux and macOS environment. It runs the installed binary through quickstart, child-evidence verification, release-project validation, aggregate dossier export, and offline dossier verification.

## 2. Create one non-secret release project

```bash
shipyard release project init .shipyard/release.toml --repo . --json
# The source remote and GitHub owner/repository are derived locally.
# Edit only the reported remaining provider IDs and environment-variable names.
shipyard release project validate .shipyard/release.toml --json
shipyard release project show .shipyard/release.toml --json
```

The manifest stores stable repository, workflow, bundle, group, policy, and credential-*reference* names. It never stores tokens, issuer/key values, or private-key bytes. Commit the reviewed manifest with the repository.

For App Store Connect, choose either:

- `token_env` referencing a short-lived bearer token; or
- `issuer_id_env`, `key_id_env`, and `private_key_path_env` referencing user-scoped values. Shipyard reads a user-owned mode-`0400`/`0600` P-256 private key and creates a bounded ES256 JWT in memory.

## 3. Render and approve forge phases

Shipyard renders each mutation as its own schema-v2 playbook:

```bash
SHA="$(git rev-parse HEAD)"
shipyard release playbook --project .shipyard/release.toml \
  --phase github-candidate --source-sha "$SHA" \
  --output .shipyard/github-candidate.toml --json
shipyard release playbook --project .shipyard/release.toml \
  --phase buzz-candidate --source-sha "$SHA" \
  --output .shipyard/buzz-candidate.toml --json
shipyard release playbook --project .shipyard/release.toml \
  --phase buzz-main --source-sha "$SHA" \
  --output .shipyard/buzz-main.toml --json
shipyard release playbook --project .shipyard/release.toml \
  --phase github-main --source-sha "$SHA" \
  --output .shipyard/github-main.toml --json
```

GitHub candidate publication uses an immutable annotated `shipyard-candidate-<SHA>` tag. Buzz candidate publication is lightweight because Buzz does not support Shipyard's annotated-tag contract. Invalid provider/action/options fail during project/playbook parsing, before a release run exists.

Execute every playbook through the existing `shipyard run`/`resume` approval contract. Never combine stages merely to avoid a second approval.

## 4. Adopt automatic CI and Apple runs read-only

After GitHub promotion triggers CI and Xcode Cloud:

```bash
shipyard release wait . --project .shipyard/release.toml \
  --source-sha "$SHA" --provider github \
  --allow-network --timeout 900 --interval 10 --json

shipyard release wait . --project .shipyard/release.toml \
  --source-sha "$SHA" --provider apple \
  --allow-network --timeout 1800 --interval 15 --json
```

`release wait` performs bounded GET-only polling and writes no ledger or observation state. Persist the authoritative terminal provider state explicitly:

```bash
shipyard release inspect . --project .shipyard/release.toml \
  --source-sha "$SHA" --provider github --allow-network --json
shipyard release inspect . --project .shipyard/release.toml \
  --source-sha "$SHA" --provider apple --allow-network --json
shipyard release observation list --project .shipyard/release.toml \
  --source-sha "$SHA" --json
```

GitHub adoption binds the configured owner/name and immutable numeric repository ID, exact workflow IDs, run IDs/attempts, and `head_sha`. Apple adoption binds workflow → watched SCM repository → exact candidate ref → run → source commit → build → app → prerelease version → beta group, using official-origin relationship paths and bounded pagination. App Store Connect does not support server-side source-SHA filtering for this path, so Shipyard lists/paginates and filters locally.

If Apple reports no exact-SHA run, generate a separately approved build playbook from the verified absent observation:

```bash
shipyard release playbook --project .shipyard/release.toml \
  --phase xcode-build --source-sha "$SHA" \
  --apple-observation /private/path/apple-observation.json \
  --output .shipyard/xcode-build.toml --json
```

The renderer refuses this phase when an exact-SHA run already exists.

## 5. Attach an internal TestFlight canary

When the Apple observation proves the exact source, successful Xcode run, valid build, app, version, build number, and intended internal beta group:

```bash
shipyard release playbook --project .shipyard/release.toml \
  --phase testflight --source-sha "$SHA" --target internal \
  --apple-observation /private/path/apple-observation.json \
  --output .shipyard/testflight-internal.toml --json
```

The resulting TestFlight mutation still requires the normal candidate approval. The adapter revalidates every relationship immediately before POST and performs authoritative relationship readback afterward.

## 6. Record physical-device acceptance

Internal availability does not prove installed behavior. Test the exact version/build on an enrolled physical device, preserve evidence, and record the gate:

```bash
shipyard release gate attest physical-device --project .shipyard/release.toml \
  --source-sha "$SHA" --status passed \
  --actor operator@example.com \
  --reason "Exact internal build passed enrolled-device acceptance" \
  --apple-observation /private/path/apple-observation.json \
  --app-version 1.0 --build-number 609 \
  --device "iPhone model / stable device label" --os-version "iOS version" \
  --check launch --check first-capture --check relaunch-readback \
  --evidence /private/path/device-evidence.txt --json
```

A passed physical-device gate requires an exact Apple observation, version/build/device/OS identity, at least one named check, and at least one immutable regular evidence file. Pending gates remain honest without fabricated proof.

## 7. External promotion is fail-closed

For an external TestFlight group, provide the passed physical-device attestation when generating the playbook. The TestFlight adapter independently reloads and hashes the attestation/evidence immediately before mutation. A hand-written playbook cannot bypass this check.

No physical-device pass means no external TestFlight mutation. Internal, external, and App Store production remain separate scopes and approvals.

## 8. Export one offline-verifiable release dossier

Export all governed child runs, read-only observations, gate attestations, native/CI artifacts, and device proof as one dossier:

```bash
shipyard release dossier export --project .shipyard/release.toml \
  --source-sha "$SHA" --scope internal \
  --run github-candidate=/private/evidence/github-candidate.tar \
  --run buzz-main=/private/evidence/buzz-main.tar \
  --observation github=/private/state/github-observation.json \
  --observation apple=/private/state/apple-observation.json \
  --artifact native-tests=/private/evidence/native-tests.log \
  --output /private/evidence/release-dossier.tar --json

shipyard release dossier verify /private/evidence/release-dossier.tar --json
```

External/production dossiers fail closed unless every required project gate is present and passed. Every dossier includes the exact non-secret `project.toml` as a mandatory hash-bound member; offline verification reparses it and recomputes required gates from the release scope instead of trusting the dossier's gate list. Verification rejects changed child bundles, source/project mismatches, changed artifacts/gate proof, links, traversal, duplicates, undeclared members, malformed policy, and invalid child evidence.

## Reproducible distribution artifacts

Build release artifacts only from a clean exact-SHA worktree:

```bash
python scripts/build_release_artifacts.py --directory dist
python scripts/resolve_release_artifacts.py --directory dist
```

The builder derives `SOURCE_DATE_EPOCH` from the commit, rejects dirty source and
nonempty output directories, and normalizes sdist tar/gzip metadata. Independent
builds of the same candidate must produce byte-identical wheel and source archive.

## Safety boundary

Shipyard deliberately does not provide ambient credentials, automatic external retries, implicit approval, hidden provider mutation, browser mutation controls, a hosted control plane, or a substitute for physical-device behavior evidence. It governs those boundaries; it does not erase them.
