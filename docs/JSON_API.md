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
  "data": {}
}
```

`data` is command-specific. Process exit status remains authoritative for automation; `ok` means Shipyard produced a valid command result, not that a deployment occurred or a provider adopted it.

## Error envelope

Handled Shipyard errors are written to standard error:

```json
{
  "api_version": "shipyard.cli/v1",
  "ok": false,
  "error": {
    "message": "redacted operator-safe message"
  }
}
```

Errors never include credential values. Argument-parser usage errors that occur before Shipyard can establish the selected command remain standard `argparse` diagnostics.

## Compatibility

- Consumers should ignore unknown additive fields.
- Consumers must not infer mutation success from exit code zero, `ok: true`, a connection check, or a submission receipt.
- Continue to use candidate, approval, receipt, and semantic-readback fields for release decisions.
- The loopback web API has its own HTTP resource shapes and is not wrapped in this CLI envelope.
