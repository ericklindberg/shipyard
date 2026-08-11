# Changelog

All notable changes to Shipyard will be documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The public API remains pre-1.0.

## [Unreleased]

## [0.5.1] - 2026-08-11

### Fixed

- Portable evidence verification now accepts the explicitly supported `git.ref` provider identities (`git`, `github`, and `buzz-git`) while continuing to reject action/provider mismatches. This restores export and offline verification for governed Buzz Git runs.

## [0.5.0] - 2026-08-10

### Added

- Added a credential-free governed quickstart, deterministic offline Markdown/HTML evidence reports, bounded read-only provider waiting, and local-only GitHub Actions bootstrap planning.
- Added canonical candidate-review packets, OpenSSH-signed portable approvals, ledger-bound import, verified provenance, and configurable distinct-principal approval quorum.
- Added typed source-bound Xcode Cloud and TestFlight adapters with exact candidate-tag, App Store relationship, and authoritative source/build/group readback.
- Added typed OCI manifest promotion and Kubernetes deployment adapters with OCI config-label source binding, exact digest verification, deployment UID/resource-version fencing, and rollout readback.
- Added a public adoption guide, roadmap, adapter contract harness, and structured GitHub issue forms.
- Added offline Buzz Git/NIP-98 readiness inspection for Git version, named HTTPS remote, host-scoped credential helper, `useHttpPath`, and non-secret key-source state.

### Changed

- Renamed the Python distribution from `gary-shipyard` to `shipyard-release` while preserving the `shipyard` command.
- Typed external adapters now execute from a state-owned detached snapshot rebuilt against the approved candidate before provider mutation.
- Refactored portable evidence verification into bounded, side-effect-free identity, audit, step, readback, receipt, and orchestration stages while preserving the `shipyard.evidence/v1` report contract and fail-closed validation order.
- Refactored external-command policy classification into bounded wrapper and command-family stages while preserving existing classifications, recursive normalization, and default-deny behavior.

### Security

- Offline evidence verification now rejects non-string run, step, and provider-readback statuses as invalid evidence instead of allowing unhashable JSON arrays or objects to escape as verifier exceptions.
- Approval/review loaders reject symlinks and non-regular files; signing and allowed-signers verification use single-open snapshots to prevent pathname replacement races.
- Apple mutation preflight now proves configured Git remote, exact candidate tag/SHA, Apple canonical reference, build/app identity, and beta-group/app ownership before POST.
- OCI and Kubernetes mutations use bounded HTTPS transports with ambient proxies and redirects disabled, exact provider identity checks, no automatic retries, and fail-closed source/digest drift handling.
- Buzz Git authentication requires Git 2.46+, a host-scoped request-aware `git-credential-nostr` helper, and a secure environment or `0600` key source; static authorization headers and credential-bearing remotes remain forbidden.
- Buzz Git operations reset ambient credential-helper chains, bind the exact HTTPS authority including nondefault ports, use descriptor-snapshotted private key files, rebind copied key references after atomic snapshot relocation, and canonicalize process-owned temporary roots for macOS-safe no-follow traversal.
- SSH approval signing uses a bounded process-private temporary key copy so the same no-follow-opened operator key works portably on Linux and macOS without persistent credential storage.
- Candidate and execution-snapshot artifact reads now traverse every repository-relative path component without following symlinks; reconstructed remotes and reusable frozen snapshots are revalidated against approved evidence; all snapshot symlink descendants and dangling snapshot paths fail closed; and approved-artifact plus private-credential destinations use descriptor-anchored creation and rename operations. Successful runs remove snapshots after authoritative readback, while uncertain runs retain them for reconciliation; cleanup failures preserve provider success but append durable `snapshot.cleanup_failed` audit evidence requiring local remediation.
- Buzz Git operations reset both generic and exact authority-scoped credential-helper chains before the sole `nostr` helper, preventing ambient host-scoped helper commands from participating.
- Hosted exact-SHA and release-evidence workflows require the immutable `shipyard-candidate-<sha>` tag separately from the approved SHA, check out that tag, peel it to the SHA, and reject disagreement before build or attestation.
- OCI reconciliation validates provider, action, source SHA, operation ID, destination, tag, and manifest digest against the durable mutation receipt before readback.

## [0.4.0] - 2026-08-10

### Added

- Added deterministic portable run-evidence bundles with offline schema, candidate, approval, source, audit-chain, provider receipt/readback, archive-safety, and artifact-byte verification.

### Changed

- Release workflows now resolve package, SBOM, checksum, and attestation filenames from the canonical package version and exact build outputs instead of duplicating a hard-coded version across three workflows.
- Package metadata now takes its version from `shipyard.__version__`, leaving one release-version source of truth.
- Upgraded the pinned `actions/upload-artifact` dependency to the Node 24-based v7.0.1 release.

### Security

- Candidate preparation, approval, and provider readback persistence now commit atomically with their hash-chained audit events; an audit-write failure rolls those governed state changes back.
- External mutation receipts use deliberate write-ahead durability: the provider operation ID commits before its audit event because the mutation may already exist, and recovery reconstructs a missing receipt event before read-only reconciliation. Receipt events bind to their step ordinal; ambiguous legacy collisions fail closed.
- Ledger integrity readback now rejects an empty audit chain instead of treating missing audit evidence as valid.
- Evidence export refuses changed approved artifacts and existing destinations; verification rejects links, traversal, duplicate/undeclared members, malformed identity bindings, and drifted provider readback.

## [0.3.0] - 2026-08-10

### Added

- Added a typed `github.workflow` adapter, private reusable `github-actions` profiles, SHA-suffixed immutable candidate-tag dispatch fencing, durable workflow-run receipts, semantic run readback, and a non-mutating workflow contract example.
- Added a versioned `shipyard.cli/v1` success/error envelope for every handled `--json` command result.
- Added Linux and macOS CI coverage, a locked dependency audit, a tracked-candidate secret scan, separate reproducible runtime/build CycloneDX SBOMs, deterministic checksums, and exact-SHA GitHub artifact attestations.
- Pinned the isolated setuptools/wheel build environment to prevent release artifacts drifting as package indexes change.
- Included operator, contributor, workflow, script, and example material in source distributions.
- Added an explicitly gated provider sandbox-validation harness and status matrix.

- Private, user-scoped connection profiles for GitHub/Git, Buzz, Render, Heroku, and Vercel.
- Offline connection readiness checks plus explicit `--allow-network` read-only identity verification.
- Standalone schema-v2 playbook generation bound to a non-secret connection-profile digest.
- Loopback API readback for redacted connection readiness.
- Immutable candidate-bound deployment authorization.
- Typed Git, Buzz, Render, Heroku, and Vercel adapters with semantic readback.
- SQLite migrations, backups, approval records, provider receipts, and hash-chained audit events.
- Bounded subprocess output, sanitized environments, signal cleanup, and stale-attempt recovery.
- Agent-friendly JSON commands and a loopback-only read-only web view.
- Open-source documentation, security policy, contributor guide, and CI.

### Security

- Restricted reusable Git profiles and typed Git playbooks to named remotes so credential-bearing URLs cannot be persisted.
- Restricted typed HTTP adapters to official provider API bases, disabled ambient HTTP proxies and redirects, and enforced provider-prefixed credential references.
- Hardened profile storage and generated playbook writes with pinned directory descriptors, atomic replacement, symlink refusal, and private file modes.
- Required read-only checks to return the configured Render service, Heroku app, Vercel project/team, or Buzz workflow identity.
- Added loopback Host validation and same-origin resource policy to block DNS-rebinding reads.
- Pinned GitHub Actions dependencies to immutable commit SHAs.

## 0.2.0 - 2026-08-08

### Added

- Production-hardening candidate for local validation.

### Security

- Disabled legacy raw external mutation by default.
- Bound approvals to source, policy, target, artifact, runtime, executable, and provider evidence.
- Required provider semantic readback before recording external success.

## 0.1.0 - 2026-08-08

### Added

- Initial local-first exact-SHA release orchestration MVP.

[Unreleased]: https://github.com/ericklindberg/shipyard/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/ericklindberg/shipyard/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/ericklindberg/shipyard/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ericklindberg/shipyard/releases/tag/v0.3.0

Versions 0.1.0 and 0.2.0 were pre-public development snapshots. The sanitized public history does not contain tags for those versions.
