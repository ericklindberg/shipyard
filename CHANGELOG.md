# Changelog

All notable changes to Shipyard will be documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project intends to use [Semantic Versioning](https://semver.org/spec/v2.0.0.html) after the pre-1.0 API stabilizes.

## [Unreleased]

## [0.3.0] - 2026-08-09

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

[Unreleased]: https://github.com/ericklindberg/shipyard/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/ericklindberg/shipyard/releases/tag/v0.3.0

Versions 0.1.0 and 0.2.0 were pre-public development snapshots. The sanitized public history does not contain tags for those versions.
