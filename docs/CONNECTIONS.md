# Per-user service connections

Shipyard connection profiles make provider setup reusable without turning Shipyard into a hosted control plane or credential store. Every OS user gets a private local profile store, and every external mutation still requires a generated schema-v2 playbook, an immutable candidate, and explicit approval.

## Safety model

A connection profile stores only:

- a local profile name;
- provider and typed adapter action;
- destination identifiers such as a service, app, project, workflow, remote, or ref;
- environment-variable **names** used to obtain credentials at runtime;
- timestamps and a canonical non-secret profile digest.

It never stores or prints environment-variable values. The profile directory is mode `0700`, the JSON and lock files are mode `0600`, writes are locked and atomic, and symlinked or non-user-owned profile storage is rejected.

Default location:

```text
${SHIPYARD_CONFIG_DIR:-${XDG_CONFIG_HOME:-~/.config}/shipyard}/connections.json
```

Connection creation is offline. `connection check` is also offline unless `--allow-network` is supplied. Network checks are read-only and never call an adapter's mutation method. HTTP profiles use only the official GitHub.com, Render, Heroku, and Vercel API hosts; custom API-base overrides, environment-configured HTTP proxies, and cross-host redirects are rejected or disabled so authorization headers cannot be rerouted to another service. Credential references must use the corresponding provider prefix (`GITHUB_`, `RENDER_`, `HEROKU_`, or `VERCEL_`) to prevent cross-provider ambient-secret confusion.

## Quick start

Create a profile once:

```bash
export RENDER_API_KEY='set this through your shell or secret manager'
shipyard connection add render-production \
  --provider render \
  --service-id srv-your-service \
  --json
```

Inspect it without printing the credential:

```bash
shipyard connection list --json
shipyard connection show render-production --json
shipyard connection check render-production --json
```

The offline check reports missing environment references and required executables. To make a real read-only provider request:

```bash
shipyard connection check render-production --allow-network --json
```

Generate a standalone, inspectable playbook snapshot:

```bash
shipyard connection playbook render-production \
  --output shipyard.toml \
  --json
shipyard plan . --playbook shipyard.toml --json
shipyard run . --playbook shipyard.toml --json
```

The generated file is created atomically with mode `0600` and contains the profile name and digest, destination identifiers, and environment-variable names—but no secret values. Its bytes and resolved action configuration are bound into the release candidate. Later edits to the local profile do not silently change an existing playbook or approved run; regenerate and review the playbook explicitly.

## Provider setup

### GitHub or another Git remote

Shipyard uses installed Git authentication (SSH agent or Git credential helper). It does not store a GitHub token or credential-bearing remote URL. Connection profiles accept only a named Git remote such as `origin`; configure that remote in each repository with normal Git tooling.

```bash
shipyard connection add github-production \
  --provider github \
  --remote origin \
  --ref refs/heads/main
shipyard connection check github-production --repo . --allow-network --json
```

The read-only check first proves the name resolves through local Git configuration, then runs exact-ref `git ls-remote`; a same-named filesystem path is not accepted as a profile remote. The mutation adapter can only push the candidate's full SHA to the canonical configured ref.

### GitHub Actions workflow

The `github-actions` provider controls a workflow dispatch on GitHub.com. It does not store a token, clone a repository, or treat a successful HTTP request as release success. The profile binds both the human-readable repository/workflow names and GitHub's stable numeric IDs.

Your workflow must accept Shipyard's required `workflow_dispatch` inputs:

- `shipyard_candidate_sha` — the exact approved 40-character source SHA;
- `shipyard_run_id` — the local ledger correlation ID.

Copy [`examples/github-actions/release.yml`](../examples/github-actions/release.yml) into your repository as a safe starting contract. Its first job proves the workflow event resolved to the approved SHA and performs no release mutation.

Discover the stable IDs without putting a token on argv:

```bash
gh api repos/OWNER/REPOSITORY --jq .id
gh api repos/OWNER/REPOSITORY/actions/workflows/release.yml --jq .id
```

Supply a fine-grained token through your secret manager with repository metadata/content read access and Actions write access, then create and check the local profile:

```bash
export GITHUB_ACTIONS_TOKEN='from your secret manager'
shipyard connection add mobile-release \
  --provider github-actions \
  --owner OWNER \
  --repo-name REPOSITORY \
  --repository-id NUMERIC_REPOSITORY_ID \
  --workflow-id NUMERIC_WORKFLOW_ID \
  --workflow-file release.yml \
  --ref 'refs/tags/shipyard-candidate-{source_sha}' \
  --token-env GITHUB_ACTIONS_TOKEN
shipyard connection check mobile-release --allow-network --json
shipyard connection playbook mobile-release --output shipyard.toml --json
```

`{source_sha}` is expanded only when an approved run executes. GitHub's dispatch API accepts a branch or tag name, not a raw commit ID, so Shipyard rejects branch refs and requires a unique candidate tag whose name ends in the approved SHA. Configure a GitHub ruleset that prevents updates and deletion for `shipyard-candidate-*`; tag naming alone is not server-side immutability.

The expanded tag must already resolve to the local candidate SHA. Before mutation, Shipyard rechecks the repository ID, workflow ID/path/state, and tag resolution. It then dispatches with GitHub REST API version `2026-03-10`, records the returned workflow-run ID, and reads the run back. A queued or in-progress run remains unresolved until `shipyard resolve RUN_ID` observes a terminal result. A run succeeds only when GitHub reports the same repository, workflow, event, and source SHA with a successful conclusion.

GitHub Enterprise Server and older GitHub API versions are intentionally unsupported because their dispatch endpoint may not return a durable run ID. Shipyard will not substitute a heuristic “latest run” lookup after mutation.

For a Buzz-hosted Git repository, use HTTPS with Buzz's request-aware NIP-98 credential helper. Git smart HTTP performs separate discovery and pack-transfer requests, so static `http.extraHeader` values and credential-bearing remote URLs are unsafe and unsupported.

Requirements:

- Git 2.46 or newer (`authtype` credential capability);
- `git-credential-nostr` on `PATH`;
- exactly one credential-free HTTPS URL for the named remote;
- a Nostr key supplied by `NOSTR_PRIVATE_KEY` at process launch or by a current-user-owned key file with mode `0600` or stricter.
- managed-agent identities also supply `BUZZ_AUTH_TAG` at process launch; member-owned keys can omit it. Never persist the attestation in Git config.

Scope the helper to the Buzz host rather than enabling it for every Git service:

```bash
git remote add buzz https://relay.example.com/git/OWNER/REPOSITORY.git
git config --local credential.https://relay.example.com.helper nostr
git config --local credential.https://relay.example.com.useHttpPath true

# Optional key-file integration. Create this file through your secret manager;
# never put the key on argv or in the repository.
install -d -m 700 ~/.config/nostr
your-secret-manager read buzz-nostr-key > ~/.config/nostr/buzz.key
chmod 600 ~/.config/nostr/buzz.key
git config --local nostr.keyfile ~/.config/nostr/buzz.key

shipyard connection add buzz-git-production \
  --provider buzz-git \
  --remote buzz \
  --ref refs/heads/main

# Offline: reports Git/helper/remote/key-source readiness without reading key bytes.
shipyard connection check buzz-git-production --repo . --json

# Explicit read-only network proof. This invokes ls-remote, never push.
shipyard connection check buzz-git-production --repo . --allow-network --json
```

The offline result includes `buzz_git_auth` with the Git version, remote host, host-scoped-helper state, `useHttpPath`, key-source kind, and allowlisted issues. It never includes the remote's full path, key-file path, private key, authorization event, or signed header. Each smart-HTTP request receives a fresh method/URL-bound NIP-98 proof from Git's credential protocol.

For managed automation, launch Shipyard through your secret manager so `BUZZ_AUTH_TAG` exists only in the process environment. Shipyard forwards only `NOSTR_PRIVATE_KEY` and `BUZZ_AUTH_TAG` to `git` for `buzz-git`; other Git providers receive neither variable.

### Buzz workflow

Shipyard uses the installed `buzz` CLI. `BUZZ_PRIVATE_KEY` is required for authenticated checks and execution; `BUZZ_RELAY_URL` overrides the CLI's relay default, and `BUZZ_AUTH_TAG` is forwarded when your workspace requires owner attestation. Values remain runtime-only.

```bash
shipyard connection add buzz-production \
  --provider buzz \
  --workflow-id your-workflow-id
shipyard connection check buzz-production --allow-network --json
```

The check reads the configured workflow's metadata; it never triggers the workflow. Authorized execution injects the candidate SHA and Shipyard run ID, then reads back the matching workflow run.

### Render

```bash
export RENDER_API_KEY='from your secret manager'
shipyard connection add render-production \
  --provider render \
  --service-id srv-your-service
```

The check performs `GET /v1/services/{service_id}`. Authorized execution creates a deploy for the exact candidate commit and reads the deploy back until its live commit matches.

### Heroku

```bash
export HEROKU_API_KEY='from your secret manager'
export HEROKU_SOURCE_BLOB_URL='short-lived source archive URL for this candidate'
shipyard connection add heroku-production \
  --provider heroku \
  --app your-app
```

The API token is required for the read-only app check. The source-blob URL is required only when executing a build and is never persisted. Generate a new least-lived source URL for each candidate; do not place signed URLs in playbooks, argv, approval reasons, or logs.

### Vercel

```bash
export VERCEL_TOKEN='from your secret manager'
shipyard connection add vercel-production \
  --provider vercel \
  --project your-project \
  --repo-id your-provider-repository-id \
  --team-id your-team-id
```

`--team-id` is optional. The check reads the configured project. Authorized execution submits the exact candidate Git SHA and requires deployment readback to report that same SHA.

## Updating and removing profiles

Updates are explicit:

```bash
shipyard connection add render-production \
  --provider render \
  --service-id srv-replacement \
  --replace
```

Existing generated playbooks and candidates remain unchanged. Generate a new playbook after replacing a profile.

Remove only the reusable local profile:

```bash
shipyard connection remove render-production --json
```

Removal does not revoke provider credentials, delete generated playbooks, or alter historical Shipyard ledgers. Revoke credentials with the provider when needed.

## Operational rules

- Treat profile files and generated playbooks as configuration, even though they contain no secret values.
- Supply credentials through the current process environment or an external secret manager that launches Shipyard with environment references.
- Never commit `.env` files, provider CLI sessions, signed source URLs, or Shipyard state.
- Use `--allow-network` only when you intend a real read-only provider check.
- Review the generated playbook and `plan` output before creating a run.
- External execution still requires the exact source SHA, candidate digest, actor, and reason.
- If a mutation becomes uncertain, do not retry it; use provider readback and `shipyard resolve`.
