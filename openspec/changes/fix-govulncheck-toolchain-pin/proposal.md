## Why

The `govulncheck` CI step added in `bump-toolchain-and-age-dependency` (merged in PR #13) was intended to scan under the pinned `go1.25.14` toolchain (`go-version-file: go.mod`), but the merged CI run (`https://github.com/afriemann/aged/actions/runs/35148615851`) showed `##[warning]Both go-version and go-version-file inputs are specified, only go-version will be used`, resolving Go `1.27.1` ("stable") instead. Root cause, confirmed by reading `golang/govulncheck-action`'s `action.yml` directly at the pinned commit: its `go-version-input` input defaults to `'stable'` and is always passed as `go-version` to the wrapped `actions/setup-go` call alongside `go-version-file`; `actions/setup-go` gives `go-version` priority whenever it is non-empty, silently overriding the file-based resolution.

This does not break anything (the scan still runs and CI is green), but it defeats the stated intent of pinning the toolchain and diverges from what was reviewed and approved as "correctly configured" in the prior change.

## What Changes

- Add `go-version-input: ''` to the `govulncheck` step in `.github/workflows/ci.yml`, blanking out the action's `'stable'` default so `go-version-file: go.mod` is honoured (and, in turn, the `go1.25.14` `toolchain` directive) exactly as originally intended.

## Capabilities

No spec-level behaviour changes. This is a CI-configuration bug fix with no change to `aged`'s own observable behaviour — `skip_specs: true` is set in `.openspec.yaml`.

### New Capabilities

None.

### Modified Capabilities

None.

## Impact

- **Affected files**: `.github/workflows/ci.yml` only (single input added to the existing `govulncheck` step).
- **No behavioural change** to `aged`'s server or CLI — this only corrects which Go toolchain version CI's vulnerability-scan step resolves and runs under.
