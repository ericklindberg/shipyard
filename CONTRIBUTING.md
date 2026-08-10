# Contributing to Shipyard

Shipyard controls external side effects. Safety regressions are release blockers.

## Development setup

```bash
uv sync --extra dev
uv run pytest -q
uv run ruff check src tests
uv run ty check src
uv build
```

## Change requirements

1. Add a failing regression test before changing safety or execution behavior.
2. Keep SQLite authoritative; JSON manifests are projections only.
3. Never add an automatic retry for an ambiguous external mutation.
4. Never persist credentials, raw authorization headers, signed URLs, or provider response dumps.
5. Bind new external behavior to a schema-v2 typed adapter.
6. Implement mutation and semantic readback separately.
7. Require immutable source/artifact identity in provider requests.
8. Preserve POSIX process-group cleanup and bounded output handling.
9. Document migrations and test upgrades from every supported schema version.
10. Update the threat model when a trust boundary changes.

## Adapter checklist

A production adapter must:

- expose a unique allowlisted action;
- validate all configuration before mutation;
- submit an immutable SHA or digest;
- return a durable provider operation identifier;
- persist only allowlisted, redacted evidence;
- perform authoritative read-only semantic readback;
- distinguish `succeeded`, `failed`, `pending`, and `unknown`;
- treat mutation exceptions, nonzero exits, timeouts, and malformed receipts as uncertain;
- have fake-provider contract tests for success, mismatch, pending, malformed data, missing credentials, and transport failure;
- have an authorized sandbox integration test before being advertised as production-supported.

## Pull requests

Include:

- safety impact and threat-model changes;
- test evidence;
- migration impact;
- compatibility impact;
- whether any external provider was contacted.

Do not include generated `build/`, `dist/`, caches, local state, credentials, or private manifests.
