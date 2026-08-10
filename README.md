# Shipyard

Shipyard is a local-first, POSIX release control plane for exact-source deployments. It separates verification and builds from external mutation, requires approval of a canonical release-candidate digest, and records every attempt, provider receipt, and semantic readback in a durable SQLite ledger.

Shipyard coordinates deployment tools; it does not bypass repository governance, provider protections, mobile-store gates, or runtime verification.

## Why Shipyard

A deployment is more than a command exiting zero. Shipyard binds authorization to:

- the exact Git source SHA and clean-worktree identity;
- the playbook schema, policy, target, and typed provider configuration;
- declared artifact hashes;
- provider destination and resolved Git remote identity;
- Shipyard/package/runtime identity and executable hashes;
- an attributed operator and approval reason.

If any bound evidence changes, the approval becomes invalid. Ambiguous external outcomes are quarantined as `uncertain` and are never automatically retried.

## Install

Python 3.11+ on a POSIX host is required.

```bash
uv tool install .
shipyard version --json
shipyard doctor /path/to/repository --json
```

For development:

```bash
uv sync --extra dev
uv run pytest -q
uv run ruff check src tests
uv run ty check src
uv build
```

## Five-minute workflow

Configure a reusable, per-user connection without storing its credential value:

```bash
export RENDER_API_KEY='from your shell or secret manager'
shipyard connection add render-production \
  --provider render \
  --service-id srv-your-service \
  --json
shipyard connection check render-production --json
shipyard connection check render-production --allow-network --json
shipyard connection playbook render-production --output shipyard.toml --json
```

Connection creation and the first check are offline. `--allow-network` performs an explicit read-only provider check; it never mutates the provider. Profiles live in the current OS user's private XDG configuration directory and retain only destination identifiers and environment-variable names—not credential values.

Alternatively, generate a typed provider template without saving a profile:

```bash
shipyard init github --output shipyard.toml
```

Edit the destination and provider identifiers, then inspect and plan without mutation:

```bash
shipyard inspect . --json
shipyard plan . --playbook shipyard.toml --json
shipyard doctor . --playbook shipyard.toml --json
```

Prepare a run. Local verification/build steps run, but Shipyard stops before the first external action:

```bash
shipyard run . --playbook shipyard.toml --json
```

The response includes `run_id`, `source_sha`, and `candidate_digest`. Review the candidate payload, then authorize that exact candidate:

```bash
shipyard resume RUN_ID \
  --execute-external \
  --confirm-sha EXACT_40_CHARACTER_SHA \
  --approve-candidate EXACT_64_CHARACTER_CANDIDATE_DIGEST \
  --approval-actor "$USER" \
  --approval-reason "Reviewed production candidate and gates" \
  --json
```

Read or reconcile state:

```bash
shipyard status RUN_ID --json
shipyard resolve RUN_ID --json
shipyard list --json
shipyard adapters --json
```

`resolve` performs provider readback only. It never repeats an external mutation.

## Typed adapters

Schema version 2 is the production path. It forbids raw external argv and routes external operations through allowlisted adapters:

- `git.ref` — exact-SHA Git ref update with `ls-remote` readback; suitable for GitHub and Buzz Git remotes;
- `buzz.workflow` — workflow trigger with run/input readback;
- `render.deploy` — exact commit deployment and deploy readback;
- `heroku.build` — source-blob build with version readback;
- `vercel.deploy` — exact Git SHA deployment and deployment readback.

Use `shipyard connection add`, `check`, and `playbook` for reusable per-user onboarding, or `shipyard init PROVIDER` to generate an unconfigured provider example. Connection profiles and playbooks store environment-variable names, never values. See [Per-user service connections](docs/CONNECTIONS.md).

Legacy schema version 1 remains available for reviewed local commands. Raw external execution is disabled by default and requires `SHIPYARD_ENABLE_LEGACY_EXTERNAL=1`; it is not recommended for production.

## State model

Default configuration directory: `~/.config/shipyard` (or the XDG/`SHIPYARD_CONFIG_DIR` override).

- `connections.json` — private, mode-`0600`, non-secret provider profile metadata;
- `connections.lock` — private POSIX lock for atomic profile updates.

Default release-state directory: `~/.local/state/shipyard`

- `shipyard.sqlite3` — authoritative runs, attempts, approvals, receipts, readbacks, and hash-chained audit events;
- `runs/<run-id>.json` — derived, atomic, mode-`0600` operator manifests;
- `locks/` — per-run and canonical destination locks.

The ledger migrates historical schemas transactionally using SQLite `user_version`. JSON manifests are rebuilt from SQLite and advance monotonically.

## Local web view

```bash
shipyard serve --port 8787
```

The web view is read-only, binds only to loopback, and rejects non-loopback Host headers. It exposes redacted run/audit data plus connection-profile readiness without credential values. Shipyard intentionally does not expose browser mutation endpoints.

## Exit codes

- `0` — requested operation succeeded;
- `1` — deterministic failure;
- `2` — invalid configuration, authorization, provenance, runtime, or ledger state;
- `3` — waiting for candidate authorization or provider completion;
- `4` — uncertain external outcome requiring read-only reconciliation.

## Security

Read [SECURITY.md](SECURITY.md) for the threat model and reporting process. Important boundaries:

- Shipyard is not an OS sandbox and does not defend against a privileged host attacker.
- Reviewed scripts and custom executables remain a trusted-playbook boundary.
- Provider-native protections and distributed locks remain authoritative across different machines or direct provider operators.
- No external mutation happens without an exact candidate approval.
- A successful mutation receipt is not success; semantic readback must confirm the intended source identity.

## Project documentation

- [Security model](SECURITY.md)
- [Contributor guide](CONTRIBUTING.md)
- [Per-user service connections](docs/CONNECTIONS.md)
- [Versioned JSON CLI contract](docs/JSON_API.md)
- [Provider sandbox contract validation](docs/PROVIDER_VALIDATION.md)
- [Exact-SHA release and provenance process](docs/RELEASING.md)
- [Adapter contract and roadmap](docs/ADAPTERS.md)
- [MVP acceptance contract](docs/MVP.md)

Licensed under the [MIT License](LICENSE).
