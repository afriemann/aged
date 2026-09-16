## Context

See `proposal.md` — Why. This is a version-pin/dependency-bump/CI-tooling maintenance change addressing `SECURITY_REVIEW.md` findings F3 and F4. Per this project's design-doc criteria, none of the triggers for a full design document apply: no cross-cutting or multi-module change, no new external dependency (only a version bump of an already-required one), no data-model or migration complexity, and no architectural ambiguity — every technical detail was already resolved and verified during investigation (see proposal's "What Changes"). The user explicitly confirmed no architect design review is needed for this class of version-update change.

## Goals / Non-Goals

**Goals:**
- Apply the exact, already-verified edits from the proposal with no further design decisions required.

**Non-Goals:**
- No architectural review or alternative-approach analysis — none is warranted for a dependency/toolchain version bump.

## Decisions

All decisions were already resolved and verified during investigation (source diffs, `go.dev/dl` release index, `actions/setup-go` toolchain-directive support, `golang/govulncheck-action` release SHA) and are recorded in `proposal.md`. No open technical choices remain:

1. `go.mod`: add `toolchain go1.25.14` directive alongside the existing `go 1.25.0` line.
2. `go.mod`: bump `filippo.io/age` require line to `v1.3.2`; run `go mod tidy` to regenerate `go.sum`.
3. `.github/workflows/ci.yml`: add a new step running `golang/govulncheck-action@032d45514ae346b1db93c04b0c90b841c370344f # v1.1.0` with `go-version-file: go.mod` and `repo-checkout: false` (the job already checks out the repo via `actions/checkout` earlier in the same job), placed after the existing `Test (race detector)` step.

## Risks / Trade-offs

- **[Risk]** `govulncheck` was observed to intermittently fail with an internal `go/packages` type-resolution error in the local sandbox during investigation. → **Mitigation**: this is a local build-cache artifact of the sandbox, not a defect in govulncheck itself or in `aged`'s dependency graph — GitHub Actions runs each job in a clean container with no pre-existing cache, so this flakiness is not expected to reproduce there. Watch the first CI run of this new step; if it errors identically, investigate as a `govulncheck-action` cache/environment issue rather than assuming a real vulnerability finding.
- **[Risk]** A future `govulncheck` run surfacing a real reachable vulnerability will fail CI. → This is the intended purpose of adding the step (F3's stated remediation goal), not a regression to guard against.
