## Context

See `proposal.md` — Why, including the revision note. This is a two-step diagnosis: an initial (wrong) attempt was made to force the `govulncheck` step onto this project's pinned toolchain, which broke CI; the actual, corrected fix is documented here.

## Goals / Non-Goals

**Goals:**
- Restore the `govulncheck` CI step to a working, green state.
- Document why the step intentionally does NOT use this project's own pinned toolchain, so this isn't "fixed" the same wrong way again.

**Non-Goals:**
- No attempt to force `govulncheck` to build/run under this project's exact pinned Go version — confirmed infeasible while `golang.org/x/vuln`'s `@latest` release requires Go ≥ 1.26 and this project pins `1.25.x`.

## Decisions

1. Remove `go-version-input: ''` and `go-version-file: go.mod` from the `govulncheck` step's `with:` block, reverting to the action's default (`go-version-input: 'stable'`).
2. Add an inline comment explaining the two compounding reasons this is deliberate (job-level `GOTOOLCHAIN=local` persistence across chained `setup-go` calls, and `x/vuln`'s own Go-version floor), so a future reader doesn't rediscover this by trial and error.

**Alternative considered and rejected:** pinning `go-version-input` to an explicit version ≥ 1.26 (e.g. `'1.26'`) instead of leaving it at the default `'stable'`. Rejected because it adds a second, independent version pin to maintain (alongside `go.mod`'s own toolchain pin) for no real benefit over just using `'stable'` — the action's default already satisfies `x/vuln`'s requirement and needs no maintenance as `x/vuln`'s own floor rises over time.

## Risks / Trade-offs

- **[Risk]** The vulnerability scan analyzes this project's dependency graph using whatever Go version `'stable'` resolves to at scan time (currently `1.27.1`), not the project's own pinned `1.25.14`. This means stdlib-CVE reachability results may not perfectly reflect the exact stdlib version `aged` is actually built and deployed with. → **Mitigation**: none needed — this is an accepted, inherent trade-off of using `golang/govulncheck-action`'s default configuration, and is more conservative in practice (a newer Go's stdlib fixes are a superset of an older one's, so this is unlikely to produce false negatives; it could in principle report a false positive if a stdlib API's vulnerability status differs between versions, which would be visible and correctable at review time).
