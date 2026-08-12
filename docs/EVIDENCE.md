# Portable offline evidence

Shipyard can export one governed run as a deterministic POSIX tar bundle and verify it on another machine without the original SQLite ledger, repository checkout, provider credentials, or network access.

## Export

```sh
shipyard evidence export RUN_ID \
  --state-dir "$HOME/.local/state/shipyard" \
  --output "shipyard-RUN_ID-evidence.tar" \
  --json
```

Export is fail-closed. Shipyard refuses the bundle when:

- the run has no prepared and approved candidate;
- the stored candidate digest no longer matches its canonical payload;
- the ledger audit chain is invalid;
- a declared artifact is missing, is a symlink or non-regular file, escapes the repository, or differs from the size/hash approved in the candidate; or
- the destination already exists.

The output is mode `0600`. Two exports of unchanged run state and artifact bytes are byte-identical.

## Verify offline

```sh
shipyard evidence verify shipyard-RUN_ID-evidence.tar --json
```

Verification performs no network access and needs no Shipyard state directory. It checks:

- the exact `shipyard.evidence/v1` envelope and canonical run-record digest;
- candidate digest and source-SHA binding;
- mandatory approval-to-candidate binding;
- every hash-chained audit event;
- successful-run/step consistency;
- provider receipt, operation ID, submitted SHA, semantic readback, and observed-SHA consistency;
- safe, unique archive member names with no links, traversal, duplicate, or undeclared files; and
- every bundled artifact's approved relative path, byte size, and SHA-256 digest.

A valid report exits `0`. A structurally readable but invalid bundle exits `1`. Invalid command/configuration or export state exits `2` through the normal CLI error contract.

## Bundle layout

```text
evidence.json
artifacts/<approved repository-relative path>
```

`evidence.json` contains a portable projection of the authoritative run manifest. Host-local source paths and captured output previews are omitted. Candidate data is retained exactly because changing it would break the approved candidate digest. Declared artifacts are copied into `artifacts/`; undeclared files are rejected by the verifier.

## Trust boundary

The offline verifier proves bundle self-consistency, exact artifact hashes, and consistency with the evidence recorded by that Shipyard run. It does **not** establish who supplied the bundle. SHA-256 and the local audit chain are integrity mechanisms, not signatures or an external trust root.

For third-party distribution, pair the bundle with an authenticated transport, detached signature, Sigstore/SLSA attestation, or provider release provenance. Verify that external proof separately before treating the bundle as authentic.

Bundles can contain release binaries and exact operational metadata. Inspect their contents and use an appropriate secure sharing channel before distributing them.

## Aggregate release dossiers

`shipyard release dossier export` creates a `shipyard.release-dossier/v1` archive spanning multiple governed run bundles, immutable GET-only provider observations, exact-SHA gate attestations, gate proof bytes, and declared native/CI artifacts. `shipyard release dossier verify` is offline and re-verifies every child run plus the dossier's complete policy/member manifest.

External and production scopes fail closed when any project-required gate is missing or not passed. The verifier rejects cross-SHA/project substitutions, changed child bundles, changed observation/gate/artifact bytes, missing gate proof, links, traversal, duplicates, undeclared members, and malformed verdict policy. Like a child bundle, a dossier proves self-consistency—not authorship—unless paired with separately verified signature/provenance.
