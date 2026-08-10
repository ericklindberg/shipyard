# Changelog

All notable changes to Shipyard will be documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The public API remains pre-1.0.

## [Unreleased]

### Changed

- Refactored portable evidence verification into bounded, side-effect-free identity, audit, step, readback, receipt, and orchestration stages while preserving the `shipyard.evidence/v1` report contract and fail-closed validation order.

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

[Unreleased]: https://github.com/ericklindberg/shipyard/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/ericklindberg/shipyard/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ericklindberg/shipyard/releases/tag/v0.3.0

Versions 0.1.0 and 0.2.0 were pre-public development snapshots. The sanitized public history does not contain tags for those versions.
