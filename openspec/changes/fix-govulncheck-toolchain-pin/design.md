## Context

See `proposal.md` — Why. This is a one-line correction to a CI action input, fixing a defect introduced by the previous `bump-toolchain-and-age-dependency` change. Per this project's design-doc criteria, none of the triggers for a full design document apply: it is a pure bug fix with no architectural dimension, touches a single input on a single existing CI step, introduces no new dependency, and there is no ambiguity requiring a technical decision — the root cause and fix were already fully diagnosed by reading `golang/govulncheck-action`'s `action.yml` directly. The user previously confirmed (earlier in this same working session) that this class of small, mechanical CI/version-maintenance change does not need an architect design review.

## Goals / Non-Goals

**Goals:**
- Make the `govulncheck` CI step actually honour `go.mod`'s `go-version-file`/`toolchain` pin, as originally intended.

**Non-Goals:**
- No broader review of the CI workflow or the govulncheck-action's other inputs.

## Decisions

Single decision, already fully resolved: add `go-version-input: ''` to the step's `with:` block. This blanks the action's `'stable'` default for that input so the value passed through to the wrapped `actions/setup-go` call is empty, letting `go-version-file: go.mod` take effect per `actions/setup-go`'s own precedence rule (non-empty `go-version` wins over `go-version-file`; an empty `go-version` defers to `go-version-file`).

## Risks / Trade-offs

- **[Risk]** None of substance — this narrows the step's Go-version resolution to exactly what was already documented as intended in the prior change's `design.md`. If the fix is wrong, CI will surface it immediately (the step will either fail to resolve a version or resolve the wrong one, both visibly).
