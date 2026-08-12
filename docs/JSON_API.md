# Versioned JSON CLI contract

Every command that accepts `--json` emits one JSON document. Human-readable output remains unchanged when `--json` is omitted.

## Version

The current contract identifier is:

```json
"shipyard.cli/v1"
```

Consumers must verify `api_version` before interpreting `data` or `error`. Additive fields may be introduced within v1; removals, renames, type changes, or semantic changes require a new contract version.

## Success envelope

Successful results, including nonzero operational states such as a blocked check or a run awaiting authorization, use:

```json
{
  "api_version": "shipyard.cli/v1",
  "ok": true,
  "status": "command-specific stable status",
  "data": {}
}
```

`data` is command-specific. The additive top-level `status` mirrors `data.status`, `data.state`, `data.verdict`, or a deterministic fallback and avoids command-specific envelope traversal. Process exit status remains authoritative for automation; `ok` means Shipyard produced a valid command result, not that a deployment occurred or a provider adopted it.

Verification commands are stricter: a parsed but invalid evidence or dossier verdict uses
`ok: false`, `status: invalid`, preserves the complete verifier report in `data`, and exits
nonzero.

`app-review preflight` is a valid advisory result when `data.status` is `ready`,
`review`, or `blocked`. A blocked result exits `1` while retaining `ok: true` because
the manifest was successfully assessed; configuration/schema errors use the error
envelope and exit `2`. Consumers must not interpret any preflight status as an Apple
approval prediction, App Store Connect readback, or submission result.

## Error envelope

Handled Shipyard errors are written to standard error:

```json
{
  "api_version": "shipyard.cli/v1",
  "ok": false,
  "status": "error",
  "error": {
    "code": "STABLE_MACHINE_CODE",
    "message": "redacted operator-safe message",
    "phase": "config|authorization|execution|reconciliation|verification",
    "retryable": false,
    "provider_mutation": false
  }
}
```

Errors never include credential values. When `--json` is present, argument-parser failures also emit exactly one JSON error document on stderr with code `INVALID_ARGUMENT`; stdout remains empty.

## Compatibility

- Consumers should ignore unknown additive fields.
- Consumers must not infer mutation success from exit code zero, `ok: true`, a connection check, or a submission receipt.
- Continue to use candidate, approval, receipt, and semantic-readback fields for release decisions.
- The loopback web API has its own HTTP resource shapes and is not wrapped in this CLI envelope.
