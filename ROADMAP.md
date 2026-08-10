# Shipyard roadmap

Shipyard is the local release gate between a green build and production. It binds an exact source candidate to explicit approval, one-shot provider mutation, authoritative readback, and portable evidence.

This roadmap describes direction, not a promise of dates. Provider support remains beta until its live sandbox contract is published with exact-SHA evidence.

## Adoption foundation

- A **credential-free quickstart** that performs a real mutation against a disposable local Git remote and verifies its evidence without network access.
- Distribution as `shipyard-release` while preserving the `shipyard` command and historical release artifacts.
- Deterministic Markdown and self-contained HTML evidence reports.
- A local-only GitHub Actions bootstrap generator and an adapter contract test kit for contributors.
- Bounded read-only waiting for provider reconciliation; waiting never executes or retries a mutation.

## Portable trust

- Deterministic candidate-review packets and **portable signed approvals** that can cross machines without a hosted account.
- Approval signatures bound to candidate digest, exact source SHA, destination, actor, reason, and policy identity.
- Interoperability with in-toto/DSSE, Sigstore/Cosign, GitHub artifact attestations, and SLSA provenance without storing signing keys in Shipyard.
- Human-readable evidence reports that remain independently verifiable offline.

## Mobile release adoption

- Exact-source Xcode Cloud build identity and readback.
- **Apple release adoption** across Xcode Cloud, App Store Connect processing, and explicit TestFlight group attachment.
- Evidence linking source SHA, immutable build/run identifiers, bundle ID, marketing version, build number, signing/artifact identity, and observed distribution state.
- EAS Build and EAS Update adoption after the Apple contract is stable.

## Digest-native infrastructure

- Existing-manifest OCI adoption and tag readback by immutable digest.
- **OCI and Kubernetes** release identity based on manifest/image digest, observed rollout generation, and declared destination.
- Explicit rollback candidates based on prior observed state; no automatic rollback.

## Stable project boundaries

- **No hosted control plane.** State remains local and exportable.
- No credential vault or signing-key storage.
- No browser mutation controls, OAuth callback server, or non-loopback daemon.
- No provider-mutating CI.
- **No automatic provider retries.** Ambiguous external outcomes remain uncertain until authoritative readback.
- No broad runtime plugin ABI before the in-repository adapter contract is proven.
- Shipyard complements CI, fastlane, GoReleaser, and provenance systems; it does not replace them.

## How to contribute

The most useful contributions are reproducible provider fixtures, fail-closed contract tests, documentation corrections, accessibility of evidence reports, and disposable sandbox validation. Use the adapter proposal issue form before implementing a new provider. Security reports belong in GitHub private vulnerability reporting, never a public issue.
