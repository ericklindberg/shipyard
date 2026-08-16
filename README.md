# Shipyard

Shipyard is a local-first, POSIX release control plane for exact-source deployments. It separates verification and builds from external mutation, requires approval of a canonical release-candidate digest, and records every attempt, provider receipt, and semantic readback in a durable SQLite ledger.

Shipyard coordinates deployment tools; it does not bypass repository governance, provider protections, mobile-store gates, or runtime verification.

**Project status:** pre-1.0 beta. The local ledger, exact-SHA authorization, Git/GitHub/Buzz promotion, GitHub Actions adoption, Xcode Cloud/TestFlight internal-canary path, physical-device gate contract, and offline evidence/dossier verifiers are exercised by deterministic tests and release dogfood. OCI, Kubernetes, Render, Heroku, Vercel, and Buzz workflow adapters remain beta pending operator-run live-target validation.

**Review status:** version 0.6.0 is the next local release candidate from the exact `main` commit under review. The [latest published release](https://github.com/ericklindberg/shipyard/releases/latest) is authoritative for what is publicly released; candidate source and local artifacts are not publication claims. Candidate evidence records the exact source SHA, artifact hashes, validation results, and intentionally unavailable provider claims.

## Why Shipyard

A deployment is more than a command exiting zero. Shipyard binds authorization to:

- the exact Git source SHA and clean-worktree identity;
- the playbook schema, policy, target, and typed provider configuration;
- declared artifact hashes;
- provider destination and resolved Git remote identity;
- Shipyard/package/runtime identity and executable hashes;
- an attributed operator and approval reason.

If any bound evidence changes, the approval becomes invalid. Ambiguous external outcomes are quarantined as `uncertain` and are never automatically retried.

## Install and review

Python 3.11+ on a POSIX host is required.

For the current public distribution, open https://github.com/ericklindberg/shipyard/releases/latest and download the original wheel plus `SHA256SUMS`. Keep the canonical wheel filename unchanged, verify its checksum, then install that local file:

```bash
uv tool install ./shipyard_release-VERSION-py3-none-any.whl
shipyard version --json
shipyard doctor /path/to/repository --json
```

If the release includes GitHub artifact attestations, verify the downloaded wheel before installation:

```bash
gh attestation verify ./shipyard_release-VERSION-py3-none-any.whl \
  --repo ericklindberg/shipyard
```

Starting with version 0.6.0, the Linux/macOS release gate installs the canonical wheel with its hash-locked runtime dependencies, requires `shipyard version --json` to report the embedded exact source SHA, and exercises the installed CLI through governed quickstart and aggregate-dossier verification. Shipyard's workflows generate evidence but never publish or deploy automatically.

For normal development from a source checkout:

```bash
uv sync --extra dev --locked
uv run pytest -q
uv run ruff check src tests scripts
uv run ty check src scripts
python scripts/build_release_artifacts.py --directory dist
```

Prove the complete governed path without credentials or network access:

```bash
shipyard quickstart ./shipyard-quickstart --json
```

This creates disposable local Git repositories, prepares and approves an exact
candidate, performs one real local ref mutation, reads it back independently,
exports evidence, and verifies that evidence offline.

Screen an iOS submission manifest for common, deterministic App Review rejection
risks without credentials, network access, or App Store Connect mutation:

```bash
shipyard app-review init --output ./app-review.json --json
# Edit every non-secret submission fact; the untouched scaffold is deliberately blocked.
# Privacy/support links must be public HTTPS without credentials, query, or fragment.
shipyard app-review preflight ./app-review.json --json
```

The result is `ready`, `review`, or `blocked` and includes stable finding IDs,
severity, evidence, and remediation. Checks cover review access, metadata/screenshots,
privacy/support URLs and disclosures, in-app account deletion, digital-goods payment,
purchase restoration, Sign in with Apple parity, special hardware, encryption export
compliance, and user-generated-content safeguards. This is advisory risk screening:
it does not inspect a signed binary or live App Store Connect record, submit an app,
interpret every guideline exception, predict discretionary review, or guarantee approval.

## Five-minute workflow

Configure a reusable, per-user connection without storing its credential value:

```bash
export RENDER_API_KEY='from your shell or secret manager'
shipyard connection add render-production \
  --provider render \
  --service-id srv-your-service \
  --json
shipyard connection check render-production --json
shipyard connection check render-production --allow-network --json
shipyard connection playbook render-production --output shipyard.toml --json
```

Connection creation and the first check are offline. `--allow-network` performs an explicit read-only provider check; it never mutates the provider. Profiles live in the current OS user's private XDG configuration directory and retain only destination identifiers and environment-variable names—not credential values.

Alternatively, generate a typed provider template without saving a profile:

```bash
shipyard init github --output shipyard.toml
```

Edit the destination and provider identifiers, then inspect and plan without mutation:

```bash
shipyard inspect . --json
shipyard plan . --playbook shipyard.toml --json
shipyard doctor . --playbook shipyard.toml --json
```

Prepare a run. Local verification/build steps run, but Shipyard stops before the first external action:

```bash
shipyard run . --playbook shipyard.toml --json
```

The response includes `run_id`, `source_sha`, and `candidate_digest`. Review the candidate payload, then authorize that exact candidate:

```bash
shipyard resume RUN_ID \
  --execute-external \
  --confirm-sha EXACT_40_CHARACTER_SHA \
  --approve-candidate EXACT_64_CHARACTER_CANDIDATE_DIGEST \
  --approval-actor "$USER" \
  --approval-reason "Reviewed production candidate and gates" \
  --json
```

Read or reconcile state:

```bash
shipyard status RUN_ID --json
shipyard wait RUN_ID --timeout 300 --interval 5 --json
shipyard resolve RUN_ID --json
shipyard list --json
shipyard adapters --json
```

`resolve` performs provider readback only. It never repeats an external mutation.

## Typed adapters

Schema version 2 is the production path. It forbids raw external argv and routes external operations through allowlisted adapters:

- `git.ref` — exact-SHA Git ref update with `ls-remote` readback; suitable for GitHub and Buzz Git remotes;
- `github.workflow` — exact-SHA GitHub Actions dispatch with durable run-ID and workflow-run readback;
- `buzz.workflow` — workflow trigger with run/input readback;
- `render.deploy` — exact commit deployment and deploy readback;
- `heroku.build` — source-blob build with version readback;
- `vercel.deploy` — exact Git SHA deployment and deployment readback.
- `xcodecloud.build` — candidate-tag-bound Xcode Cloud dispatch and source-commit readback;
- `appstoreconnect.testflight` — identity-bound TestFlight build/group adoption and readback;
- `app-review preflight` — offline advisory rejection-risk screening from an explicit
  secret-free submission manifest; it is not a provider adapter or submission action;
- `oci.promote` — exact manifest/config/source verification, one tag PUT, and digest readback;
- `kubernetes.deploy` — independent OCI source verification plus UID/resourceVersion-bound immutable-image rollout.

`git.ref`, GitHub/Buzz forge promotion, GitHub workflow adoption, Xcode Cloud exact-SHA adoption, and internal TestFlight group attachment are release-dogfooded paths. Meridian build 609 provided the live Apple internal-canary mutation/readback acceptance case; this does not prove physical-device behavior, external TestFlight, App Store submission, OCI, or Kubernetes production readiness.

Use `shipyard connection add`, `check`, and `playbook` for reusable per-user onboarding, or `shipyard init PROVIDER` to generate an unconfigured provider example. Connection profiles and playbooks store environment-variable names, never values. See [Per-user service connections](docs/CONNECTIONS.md).

Legacy schema version 1 remains available for reviewed local commands. Raw external execution is disabled by default and requires `SHIPYARD_ENABLE_LEGACY_EXTERNAL=1`; it is not recommended for production.

## GitHub Actions as an evidence-producing runner

Shipyard does not replace GitHub Actions. It makes a reviewed GitHub workflow one typed step in an exact-candidate release. Before dispatch, Shipyard expands `{source_sha}` in the configured candidate-tag template, rejects mutable branch refs, verifies the canonical repository ID and active workflow ID/path, and proves the resulting tag resolves to the approved SHA. GitHub's durable workflow-run ID is saved before semantic readback verifies the same repository, workflow, event, and `head_sha`. Protect the candidate-tag namespace against update and deletion on the GitHub mirror; tag naming alone cannot provide server-side immutability.

Start with the non-mutating contract in [`examples/github-actions/release.yml`](examples/github-actions/release.yml). Shipyard extends that contract in [its active dogfood workflow](.github/workflows/shipyard-contract.yml) with the complete locked test, static-analysis, security, dependency-audit, build, SBOM, checksum, and artifact gate. Both declare the two inputs Shipyard sends and reject a workflow event whose `GITHUB_SHA` differs from the approved candidate. Add your own build, signing, TestFlight, package, or infrastructure jobs after the identity gate, using pinned actions and provider-native protections.

This is the practical boundary: GitHub remains the build/CI environment; Shipyard controls which exact source may enter a release workflow and records what GitHub says happened. Typed Apple release projects can discover and adopt provider-created Xcode Cloud runs by exact SHA, resolve build/app/version/group identities, and render separately approved internal TestFlight actions without copied opaque IDs. External TestFlight additionally requires adapter-verified physical-device evidence.

## State model

Default configuration directory: `~/.config/shipyard` (or the XDG/`SHIPYARD_CONFIG_DIR` override).

- `connections.json` — private, mode-`0600`, non-secret provider profile metadata;
- `connections.lock` — private POSIX lock for atomic profile updates.

Default release-state directory: `~/.local/state/shipyard`

- `shipyard.sqlite3` — authoritative runs, attempts, approvals, receipts, readbacks, and hash-chained audit events;
- `runs/<run-id>.json` — derived, atomic, mode-`0600` operator manifests;
- `locks/` — per-run and canonical destination locks.
- `observations/` — immutable private GET-only provider observations, keyed by project digest, exact SHA, provider, and observation digest;
- `gates/` — immutable exact-SHA operator attestations and bound evidence hashes.

The ledger migrates historical schemas transactionally using SQLite `user_version`. JSON manifests are rebuilt from SQLite and advance monotonically.

## Portable offline evidence

Export a governed run, its canonical manifest projection, provider receipt/readback evidence, audit chain, and approved artifacts into one deterministic bundle:

```bash
shipyard evidence export RUN_ID --output shipyard-evidence.tar --json
shipyard evidence verify shipyard-evidence.tar --json
shipyard evidence report shipyard-evidence.tar --format html --output report.html --json
```

Verification is offline and does not need the original ledger, checkout, credentials, or provider. It checks the evidence schema, canonical record digest, candidate/approval/source identity, audit chain, operation receipts and semantic readback, archive safety, and every artifact byte against its approved SHA-256 digest. The bundle is self-verifying but not signed; use authenticated transport or external provenance when third parties must establish who supplied it. See [Portable evidence](docs/EVIDENCE.md).

## Local web view

```bash
shipyard serve --port 8787
```

The web view is read-only, binds only to loopback, and rejects non-loopback Host headers. It exposes redacted run/audit data plus connection-profile readiness without credential values. Shipyard intentionally does not expose browser mutation endpoints.

## Exit codes

- `0` — requested operation succeeded;
- `1` — deterministic failure;
- `2` — invalid configuration, authorization, provenance, runtime, or ledger state;
- `3` — waiting for candidate authorization or provider completion;
- `4` — uncertain external outcome requiring read-only reconciliation.

## Security

Read [SECURITY.md](SECURITY.md) for the threat model and reporting process. Important boundaries:

- Shipyard is not an OS sandbox and does not defend against a privileged host attacker.
- Reviewed scripts and custom executables remain a trusted-playbook boundary.
- Provider-native protections and distributed locks remain authoritative across different machines or direct provider operators.
- No external mutation happens without an exact candidate approval.
- A successful mutation receipt is not success; semantic readback must confirm the intended source identity.

## Project documentation

- [Security model](SECURITY.md)
- [Contributor guide](CONTRIBUTING.md)
- [Per-user service connections](docs/CONNECTIONS.md)
- [Versioned JSON CLI contract](docs/JSON_API.md)
- [Provider sandbox contract validation](docs/PROVIDER_VALIDATION.md)
- [Exact-SHA release and provenance process](docs/RELEASING.md)
- [Adapter contract and roadmap](docs/ADAPTERS.md)
- [Portable offline evidence](docs/EVIDENCE.md)
- [Standalone release lifecycle](docs/STANDALONE_RELEASE.md)
- [Adoption guide: quickstart, signed approvals, Apple, OCI, and Kubernetes](docs/ADOPTION.md)
- [MVP acceptance contract](docs/MVP.md)

Licensed under the [MIT License](LICENSE).
