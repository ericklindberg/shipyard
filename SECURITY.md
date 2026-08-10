# Security Policy

## Supported versions

Shipyard is pre-1.0. Security fixes are applied to the current `main` branch and the latest published release candidate only.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use the repository's [private vulnerability reporting form](https://github.com/ericklindberg/shipyard/security/advisories/new) and include:

- affected version or commit;
- reproduction steps;
- expected and observed safety boundary;
- whether any provider mutation occurred;
- relevant redacted logs.

Never include credentials, tokens, private keys, signed URLs, or customer data. You should receive acknowledgement within seven days.

## Threat model

Shipyard protects an operator from accidental, stale, ambiguous, or insufficiently authorized deployment actions on a trusted POSIX host.

### Defended boundaries

- external mutation is default-deny;
- production external actions use an allowlisted typed adapter;
- authorization binds to source, plan, destination, artifacts, runtime, and executable evidence;
- credentials are environment references, not candidate or ledger values;
- raw argv is classified fail-closed and legacy raw external execution is disabled by default;
- process output is bounded, decoded safely, redacted, and persisted with a digest;
- external timeout, interruption, launch failure, adapter failure, and malformed readback remain uncertain;
- ambiguous mutations are never automatically retried;
- SQLite is authoritative and manifests are atomic projections;
- per-run and canonical destination locks prevent local concurrent execution.

### Trusted boundaries

- the host OS, current user account, Python runtime, installed Shipyard package, and underlying provider tools;
- reviewed playbooks, scripts, and custom executables;
- provider credential stores and provider-native authorization;
- provider APIs/CLIs returning authentic data.

### Explicit non-guarantees

- Shipyard is not a sandbox and cannot stop a privileged or same-user attacker from changing memory, kernel behavior, provider credentials, or a running process.
- Local locks are not distributed locks. Separate machines, state directories, CI systems, or direct provider operators require provider-native concurrency/fencing controls.
- A preflight source check cannot make an arbitrary external script deterministic. Typed adapters minimize this boundary by submitting immutable source identifiers and requiring semantic readback.
- Shipyard does not replace branch protection, signed artifacts, SBOMs, SLSA provenance, mobile signing, App Store review, health checks, or rollback plans.

## Credential handling

- Per-user connection profiles are stored under the current user's XDG config directory with `0700`/`0600` permissions, locking, atomic replacement, ownership checks, pinned directory identity, and symlink rejection.
- Generated playbooks use atomic no-follow writes, reject symlink targets, and are created mode `0600`.
- Profile creation and default checks are offline; a real read-only provider check requires `--allow-network`.
- HTTP checks use only official provider HTTPS origins, ignore ambient proxy variables, and do not follow redirects.
- HTTP credential references must use the provider's prefix to prevent cross-provider ambient-secret confusion.
- Store only environment-variable names in connection profiles and playbooks.
- Never place secret values in argv, destinations, remote URLs, playbooks, or approval reasons.
- Shipyard never serializes its process environment.
- Provider responses persisted by adapters must contain allowlisted evidence only, not raw response bodies or headers.

## Safe incident response

For an `uncertain` run:

1. Do not retry the mutation.
2. Use `shipyard status RUN_ID --json` and `shipyard resolve RUN_ID --json`.
3. Verify the provider target directly using a read-only API or CLI.
4. Preserve the SQLite ledger and manifest.
5. Create a new candidate only after the prior provider outcome is understood.
