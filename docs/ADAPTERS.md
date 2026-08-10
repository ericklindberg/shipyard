# Adapter contract and roadmap

## Production contract

A Shipyard adapter has three deliberately separate operations:

1. `check(context) -> ConnectionCheck` performs an explicitly authorized, read-only connectivity/identity check and never mutates the provider.
2. `execute(context) -> MutationReceipt` performs one authorized mutation and returns a durable provider operation ID.
3. `readback(context, receipt) -> ProviderReadback` performs no mutation and determines whether the provider adopted the authorized source identity.

A receipt is never sufficient evidence of success. The executor marks a step successful only when readback reports `succeeded` for the submitted SHA. Unknown readback preserves an uncertain or waiting state and does not trigger mutation retry.

## Included profiles

| Action | Provider use | Immutable input | Semantic readback |
|---|---|---|---|
| `git.ref` | GitHub, Buzz Git, other Git servers | full Git SHA + canonical ref | exact `ls-remote` ref SHA |
| `github.workflow` | GitHub Actions on GitHub.com | full Git SHA + canonical repository/workflow IDs + SHA-suffixed candidate tag | durable run ID, exact repository/workflow/event/head SHA, status and conclusion |
| `buzz.workflow` | Buzz workflows | candidate source SHA input | matching workflow run and input |
| `render.deploy` | Render services | commit ID | deploy status and commit ID |
| `heroku.build` | Heroku builds | source-blob version | build status and source version |
| `vercel.deploy` | Vercel projects | Git ref/SHA | deployment state and Git SHA |

These adapters have deterministic fake-provider contract tests. The GitHub Actions adapter uses the GitHub REST API version `2026-03-10` workflow-dispatch response so a mutation returns a durable workflow-run ID. Activation against a real account remains an operator decision and requires provider credentials plus an authorized sandbox validation.

## Recommended next profiles

The following are intentionally not represented as production-ready until their immutable submission and authoritative readback contracts are implemented and tested:

- Docker/OCI: publish by manifest digest and read back the registry descriptor digest;
- Fly.io: deploy an OCI digest and read back the active machine/release image digest;
- Cloudflare Pages/Workers: publish an immutable artifact manifest and read back deployment version plus artifact identity;
- Kubernetes: apply an image-by-digest rollout plus source annotation and read back deployment generation, image digest, and availability;
- EAS Update/Build: bind runtime version, channel/branch, update group, artifact hashes, and source SHA;
- App Store Connect/TestFlight: bind exact Xcode Cloud/build source, bundle/version/build identity, processing state, and tester-group adoption.

These platforms have materially different uncertainty and adoption semantics. A generic “run command and trust exit zero” adapter would weaken Shipyard, so shallow wrappers are not accepted.

## Plugin direction

Until a stable plugin ABI is published, adapters are registered in `shipyard.adapters.registry.AdapterRegistry` and actions are allowlisted by the playbook parser. New adapters should remain dependency-injected so tests can use fake transports or command runners without credentials or network access.
