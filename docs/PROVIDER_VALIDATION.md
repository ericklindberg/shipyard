# Provider sandbox contract validation

Shipyard's unit and fake-provider contracts are necessary but do not prove a live provider account. This gate validates read-only identity first and permits one mutation only after exact destination, exact SHA, candidate digest, actor, and rationale are supplied.

## Harness

Run from a clean source repository whose `HEAD` is the candidate to deploy:

```sh
uv run python scripts/validate_provider_sandbox.py sandbox-profile \
  --repo /path/to/clean/source \
  --config-dir "$XDG_CONFIG_HOME/shipyard" \
  --state-dir /private/evidence/shipyard-sandbox \
  --confirm-destination 'provider:exact-resource'
```

This performs only the profile's explicit read-only connection check. To perform one sandbox mutation after reviewing that result:

```sh
uv run python scripts/validate_provider_sandbox.py sandbox-profile \
  --repo /path/to/clean/source \
  --config-dir "$XDG_CONFIG_HOME/shipyard" \
  --state-dir /private/evidence/shipyard-sandbox \
  --confirm-destination 'provider:exact-resource' \
  --execute-mutation \
  --confirm-sha 'FULL_40_CHARACTER_SHA' \
  --approval-actor 'operator-name' \
  --approval-reason 'sandbox contract validation'
```

The harness:

1. Requires an exact destination match before contacting the provider.
2. Requires the current repository SHA to equal `--confirm-sha` before mutation.
3. Runs the provider's read-only identity check and stops unless it returns `verified`.
4. Generates a schema-v2 playbook with target `sandbox`.
5. Prepares a candidate without mutation.
6. Resumes only with exact-SHA confirmation and exact candidate approval.
7. Persists receipt and semantic readback evidence in the selected state directory.
8. Emits redacted metadata only.

Failures and uncertain outcomes are not retried automatically.

## Validation status through 0.3.0

| Provider path | Automated contract | Retained evidence through 2026-08-10 | Release claim |
|---|---|---|---|
| Git/GitHub named remote | Unit, integration, and exact-ref readback | Passed against a disposable local bare Git remote, including one exact-SHA mutation and readback | Implementation verified; live GitHub account contract still operator-dependent |
| GitHub Actions | Fake HTTPS transport verifies stable repository/workflow identity, exact ref-to-SHA fencing, durable dispatch run ID, and run readback | Exact-SHA non-deploying workflow dispatch and semantic readback succeeded during release dogfood against the public Shipyard repository | Beta and release-dogfooded; downstream deployment semantics remain operator-specific |
| Buzz-hosted Git | Same `git.ref` contract | Covered by named-remote Git path; no live Buzz-hosted repository target configured | Beta |
| Buzz workflow | Fake runner verifies `workflows get`; execute/readback contract covered | No sandbox workflow profile or `BUZZ_PRIVATE_KEY` available | Beta; live validation required |
| Render | Fake HTTPS transport, exact service identity, mutation/readback contract | No sandbox service profile or credential reference available | Beta; live validation required |
| Heroku | Fake HTTPS transport, exact app identity, mutation/readback contract | No sandbox app profile or credential/source-blob references available | Beta; live validation required |
| Vercel | Fake HTTPS transport, exact project/team identity, mutation/readback contract | No sandbox project profile or credential reference available | Beta; live validation required |

Do not convert an unavailable live-account gate into a pass. Update this matrix only from retained, redacted evidence tied to the exact Shipyard candidate SHA and disposable provider target.
