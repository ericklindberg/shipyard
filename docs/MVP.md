# Shipyard MVP Contract

## Goal

Create a working local release orchestrator that makes exact source identity, verification evidence, retries, and external-action authorization durable and inspectable.

## Acceptance criteria

1. A repository can be inspected without mutation.
2. A TOML playbook produces a deterministic ordered plan.
3. Verification/build steps run directly as argv and stop on failure.
4. External steps never run by default.
5. External execution requires an explicit flag and an exact source-SHA confirmation.
6. Shipyard rechecks HEAD and cleanliness immediately before an external step.
7. A failed or blocked run can resume without rerunning successful steps.
8. Concurrent execution of the same run or external repository/target is rejected across state directories.
9. Interrupted or nonzero external attempts become uncertain and are never automatically retried.
   Shipyard terminates the step's POSIX process group before returning from a local timeout or interruption.
10. Every execution attempt remains in the evidence history.
11. SQLite is the source of truth; JSON manifests are rebuilt from it during readback after interruption.
12. Common secret shapes are rejected from argv or redacted before persistence.
13. A real end-to-end self-run passes tests, lint, package build, and manifest readback.

## Connected slice

```text
Git repository
  -> immutable source snapshot
  -> validated TOML playbook
  -> guarded executor
  -> subprocess result
  -> redaction + output digest
  -> SQLite run/attempt ledger
  -> atomic JSON manifest
  -> CLI status/readback
```

## Intentional boundaries

- The ledger coordinates existing release tools; it does not replace GitHub, EAS, Xcode Cloud, App Store Connect, Docker, or platform-specific gates.
- A command's declared effect is reviewed policy. Shipyard catches common misclassifications and treats dynamic evaluator forms as external, but it cannot statically prove arbitrary script files or custom executables are side-effect free and is not a sandbox.
- Runtime/device behavior remains a separate evidence level and must be represented by an explicit playbook step.
- External rollback is not automatic in this MVP.

## Next adapters

1. GitHub exact-ref push/check/readback.
2. EAS OTA publication and update-group readback.
3. Xcode Cloud/App Store Connect exact-SHA build adoption and TestFlight group readback.
4. Docker build/checksum/cutover/health/rollback.
5. Telegram/Buzz delivery of the final manifest summary.
