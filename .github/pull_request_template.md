## Summary

<!-- What changed and why? -->

## Safety impact

- [ ] No external-mutation or trust boundary changes
- [ ] Candidate/provenance behavior changed
- [ ] Provider adapter behavior changed
- [ ] SQLite migration or recovery behavior changed

## Verification

<!-- Paste exact commands and results. Do not include secrets. -->

## Provider contact

- [ ] This change made no external provider mutation
- [ ] Any authorized sandbox/provider operation is described with redacted evidence

## Checklist

- [ ] Regression tests added or updated
- [ ] `uv run pytest -q` passes
- [ ] `uv run ruff check src tests` passes
- [ ] `uv run ty check src` passes
- [ ] Security and migration documentation updated when applicable
- [ ] No credentials, signed URLs, private manifests, or customer data included
