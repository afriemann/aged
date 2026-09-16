## Why

The `govulncheck` CI step added in `bump-toolchain-and-age-dependency` (merged in PR #13) resolved Go `1.27.1` ("stable") to build and run `govulncheck` itself, rather than this project's own pinned `go1.25.14` toolchain, emitting `##[warning]Both go-version and go-version-file inputs are specified, only go-version will be used`.

**Revision note:** this change originally (PR #14, first commit) attempted to "fix" this by adding `go-version-input: ''` so `go-version-file: go.mod` would take effect. That attempt was itself wrong and broke CI — see below. The corrected fix is: leave the step's Go-version resolution alone entirely.

**Root cause, fully diagnosed (not guessed) after the first attempt failed in CI:**
1. `golang/govulncheck-action`'s `go-version-input` input defaults to `'stable'` and is always passed as `go-version` to its internal `actions/setup-go` call; `actions/setup-go` prioritizes `go-version` over `go-version-file` whenever it is non-empty. Blanking `go-version-input` does make `go-version-file` take effect.
2. However, `actions/setup-go`'s own `parseGoVersionFile()` (read directly from its source at the pinned commit — not inferred) has a documented compatibility exception:
   ```js
   // for backwards compatibility: use version from go directive if
   // 'GOTOOLCHAIN' has been explicitly set
   if (process.env[GOTOOLCHAIN_ENV_VAR] !== GOTOOLCHAIN_LOCAL_VAL) {
       const matchToolchain = contents.match(/^toolchain go.../m);
       if (matchToolchain) return matchToolchain[1];
   }
   ```
   It only honours a `toolchain` directive in `go.mod` when the `GOTOOLCHAIN` environment variable is not already `'local'`. This job's first `Set up Go` step (for the main build) sets `GOTOOLCHAIN=local` as a job-level env var — confirmed present in that step's own logged environment dump — which persists into `govulncheck-action`'s internal second `setup-go` call. The live CI log for the (reverted) first attempt independently corroborates this: it resolved `1.25.0` (the `go` directive), not `1.25.14` (the `toolchain` directive), exactly matching this code path.
3. This is moot regardless: CI's actual failure (`go: golang.org/x/vuln/cmd/govulncheck@latest: golang.org/x/vuln@v1.8.0 requires go >= 1.26.0 (running go 1.25.0)`) shows the **latest `govulncheck` package now requires Go ≥ 1.26** — newer than this project's own pinned `1.25.x` line. `govulncheck-action`'s install step is hardcoded to `@latest` with no version-pin input to work around this.

So `govulncheck-action`'s default (`'stable'`, resolving a Go new enough to satisfy `x/vuln`'s own build requirement) is necessary, not a defect — the scanner tool needs a modern-enough Go to build and run itself; it does not need to match the project's own pinned toolchain to analyse the project's source and dependency graph.

## What Changes

- Revert the `go-version-input`/`go-version-file` overrides added in the first commit of this branch. The `govulncheck` step goes back to using the action's own default Go-version resolution (`'stable'`), which is what actually passed in the original merged `bump-toolchain-and-age-dependency` change.
- Document the reasoning inline in `.github/workflows/ci.yml` so a future maintainer doesn't repeat the same incorrect "fix."

## Capabilities

No spec-level behaviour changes. This is a CI-configuration correction with no change to `aged`'s own observable behaviour — `skip_specs: true` is set in `.openspec.yaml`.

### New Capabilities

None.

### Modified Capabilities

None.

## Impact

- **Affected files**: `.github/workflows/ci.yml` only (revert to no `go-version-input`/`go-version-file` override on the `govulncheck` step, plus an explanatory comment).
- **No behavioural change** to `aged`'s server or CLI.
