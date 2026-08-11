# Adoption guide

Shipyard is a local release gate. It binds one exact Git source candidate to explicit approval, one bounded provider mutation, authoritative readback, and portable evidence. It is not a hosted deployment service and does not store credential or signing-key values.

## Trust status

The credential-free local path is exercised end to end. Git and GitHub Actions are release-dogfooded. Apple, OCI registry, and Kubernetes adapters have deterministic contract tests but **No live provider validation** is included in this repository yet. Treat those adapters as beta until a disposable provider sandbox produces reviewed receipts and readback evidence.

Shipyard never automatically retries a provider mutation. A transport failure after dispatch becomes uncertain and requires read-only reconciliation.

## Credential-free proof

Run a real governed release against disposable local Git repositories, export evidence, and verify it offline:

```bash
shipyard quickstart ./shipyard-quickstart --json
```

The directory must be absent or empty and must not be a symlink. Shipyard creates it, mutates only its local bare remote, records the exact source/candidate/receipt/readback chain, and leaves a verified evidence bundle for inspection.

## GitHub bootstrap without mutation

Generate a reviewed workflow, schema-v2 playbook, and operator README locally:

```bash
shipyard bootstrap github-actions OWNER REPOSITORY EXACT_40_CHAR_SHA \
  --repository-id NUMERIC_REPOSITORY_ID \
  --workflow-id NUMERIC_WORKFLOW_ID \
  --workflow-file shipyard.yml \
  --output-dir ./shipyard-bootstrap \
  --json
```

Bootstrap does not call GitHub or use credentials. The generated workflow validates the `source_sha` input, checks out that revision, and compares `git rev-parse HEAD` to the input. Its Shipyard destination uses the immutable candidate-tag namespace rather than a raw branch or mutable dispatch context.

## Portable evidence and reports

```bash
shipyard evidence export RUN_ID --output shipyard-evidence.tar --json
shipyard evidence verify shipyard-evidence.tar --json
shipyard evidence report shipyard-evidence.tar \
  --format markdown --output report.md --json
shipyard evidence report shipyard-evidence.tar \
  --format html --output report.html --json
```

Report rendering first snapshots one regular-file bundle, verifies that immutable snapshot, and renders escaped Markdown or self-contained HTML without network, provider, ledger, or checkout access. Invalid, symlinked, malformed, or corrupt bundles fail closed.

## Bounded read-only waiting

```bash
shipyard wait RUN_ID --timeout 300 --interval 5 --json
```

`shipyard wait` performs bounded provider readback only. It does not append ledger events, continue execution, repeat mutation, or convert uncertain state into an approval. Use explicit `shipyard resolve RUN_ID --json` when an operator intends to persist authoritative reconciliation.

## Portable SSH approvals and quorum

Set a bounded quorum in schema-v2 playbooks; omission preserves the compatible default of one:

```toml
schema_version = 2
approval_quorum = 2
```

Each quorum slot must be a distinct verified SSH principal bound to the same canonical candidate review. Duplicate principals do not count twice. Inline `resume --approve-candidate` authorization is rejected when `approval_quorum` is greater than one.

Export, sign on an operator-controlled machine, verify, and import:

```bash
shipyard approval export RUN_ID \
  --state-dir "$SHIPYARD_STATE" \
  --output candidate-review.json --json

shipyard approval sign candidate-review.json \
  --key ~/.ssh/release_approval \
  --actor alice@example.com \
  --reason "Reviewed exact candidate and provider gates" \
  --approved-at 2026-08-10T20:00:00Z \
  --output alice-approval.json --json

shipyard approval verify candidate-review.json alice-approval.json \
  --allowed-signers allowed_signers --json

shipyard approval import RUN_ID \
  --state-dir "$SHIPYARD_STATE" \
  --review candidate-review.json \
  --signed alice-approval.json \
  --allowed-signers allowed_signers --json
```

The OpenSSH allowed-signers principal must equal `--actor`. Shipyard opens key and signer inputs without following symlinks, snapshots verification inputs, and never reads or stores private-key bytes. Imported approval time and signature provenance come from the verified signed statement and are committed atomically with quorum state.

Shipyard does not yet authenticate a separate candidate-preparer principal. Do not claim cryptographic preparer/approver separation until a signed preparation or workload-identity contract is implemented.

## Apple beta adapters

### Xcode Cloud

`xcodecloud.build` requires an exact immutable candidate tag on a canonical named Git remote. Before Apple mutation, Shipyard verifies:

1. the Apple workflow and SCM reference resource identities;
2. Apple `canonicalName` equals `refs/tags/shipyard-candidate-<source_sha>`;
3. `git ls-remote` on the governed checkout's named remote resolves that tag, including annotated-tag peeling, to the approved SHA.

Create the candidate reference as a separately approved `git.ref` run. For GitHub-backed Xcode Cloud repositories, request an annotated candidate tag so Apple can index the SCM reference:

```toml
[[steps]]
id = "candidate-tag"
name = "Publish annotated Xcode candidate tag"
effect = "external"
action = "git.ref"

[steps.config]
remote = "origin"
ref = "refs/tags/shipyard-candidate-0123456789abcdef0123456789abcdef01234567"
tag_kind = "annotated"
```

Annotated mode is accepted only for the exact `shipyard-candidate-<source_sha>` GitHub tag. Shipyard creates the tag object in a disposable writable clone of the frozen execution snapshot, performs one non-forced push, and readbacks both the tag-object SHA and peeled approved commit. It does not modify the governed checkout.

Example step configuration:

```toml
[[steps]]
id = "xcode-build"
name = "Start Xcode Cloud build"
effect = "external"
action = "xcodecloud.build"

[steps.config]
workflow_id = "APPLE_WORKFLOW_RESOURCE_ID"
git_reference_id = "APPLE_SCM_REFERENCE_ID"
git_reference_name = "refs/tags/shipyard-candidate-0123456789abcdef0123456789abcdef01234567"
source_remote = "origin"
token_env = "APPLE_CONNECT_API_TOKEN"
```

The run receipt stores the Apple build-run ID. Readback requires Apple `sourceCommit.commitSha` to equal the approved SHA. Live Xcode Cloud run resources can omit workflow and source-reference relationships entirely, and Apple forbids those direct relationship endpoints. When that occurs, Shipyard revalidates the configured workflow and SCM reference, re-resolves the exact Git source SHA, and requires the receipt run to appear in the configured workflow's bounded build-run collection. A mutable or mismatched reference is rejected before `POST /v1/ciBuildRuns`.

### TestFlight

`appstoreconnect.testflight` binds the exact app, bundle ID, build, marketing version, build number, Xcode Cloud run, source SHA, and beta group. Apple may omit inline relationship data from live resources; Shipyard resolves those identities through canonical official related-resource endpoints and bounded Apple-hosted pagination before mutation. It performs one build/group relationship mutation and drains only bounded Apple-hosted relationship pagination before declaring adoption.

Keep Xcode Cloud and TestFlight as separately approved runs when they have different destination locks. Do not use the adapters with production credentials until disposable live validation confirms current App Store Connect resource semantics.

## OCI registry beta adapter

`oci.promote` is a separate run whose global destination is the exact registry tag:

```toml
schema_version = 2
name = "promote-image"
target = "production"
provider = "oci"
destination = "registry.example.com/team/app:stable"

[[steps]]
id = "promote"
name = "Promote immutable image"
effect = "external"
action = "oci.promote"

[steps.config]
registry = "registry.example.com"
repository = "team/app"
manifest_digest = "sha256:REPLACE_WITH_64_LOWERCASE_HEX"
target_tag = "stable"
token_env = "OCI_REGISTRY_TOKEN"
```

Before the one tag `PUT`, Shipyard:

- HEADs and GETs the exact manifest digest over HTTPS;
- hashes the returned manifest bytes;
- rejects multi-architecture indexes for now;
- fetches and hashes the manifest's exact image-config blob;
- requires `org.opencontainers.image.revision` to equal the approved Git SHA.

Readback HEADs the target tag and succeeds only when `Docker-Content-Digest` equals the approved digest.

## Kubernetes beta adapter

`kubernetes.deploy` is a separate run globally locked to one cluster/namespace/Deployment/container identity. It re-verifies the OCI image before any Kubernetes request, so it does not depend on an earlier run or unsafe multi-destination locking:

```toml
schema_version = 2
name = "deploy-image"
target = "production"
provider = "kubernetes"
destination = "prod-cluster:production:web:web"

[[steps]]
id = "deploy"
name = "Deploy immutable image"
effect = "external"
action = "kubernetes.deploy"

[steps.config]
api_base = "https://kubernetes.example.com"
cluster_id = "prod-cluster"
namespace = "production"
namespace_uid = "EXPECTED_NAMESPACE_UID"
deployment = "web"
deployment_uid = "EXPECTED_DEPLOYMENT_UID"
container = "web"
image_repository = "registry.example.com/team/app"
manifest_digest = "sha256:REPLACE_WITH_64_LOWERCASE_HEX"
registry = "registry.example.com"
repository = "team/app"
registry_token_env = "OCI_REGISTRY_TOKEN"
token_env = "KUBERNETES_API_TOKEN"
```

Before the one strategic-merge PATCH, Shipyard verifies the OCI manifest/config/source revision, namespace UID, Deployment UID, named container, and current `resourceVersion`. The patch sets only that container to `image_repository@manifest_digest` and includes the observed resource version. Readback requires the same Deployment UID, exact image digest, observed generation, replica completion, and rollout conditions; a scaled-to-zero Deployment reconciles once the exact image spec and generation are observed.

Shipyard calls Kubernetes directly over bounded HTTPS. It does not invoke `kubectl` or `helm`, use ambient kubeconfig credentials, retry a PATCH, or perform automatic rollback.

## Production gate

Before using any beta adapter in production:

1. exercise it against a disposable provider target;
2. preserve the exact candidate, signed approval, external receipt, and authoritative readback;
3. export and verify portable evidence offline;
4. independently review identity and uncertainty behavior;
5. protect provider-side tag/ref/resource identities and destination concurrency;
6. promote only the exact reviewed Shipyard SHA through the Buzz-first release process.
