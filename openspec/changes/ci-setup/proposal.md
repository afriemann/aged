## Why

`aged` currently has no CI: every merged PR (including dependency bumps merged by Dependabot) lands without any automated build, vet, format, or test check. This is about to matter more, not less — the repo is being made public shortly, and a public repo without CI signals unmaintained code and lets a broken PR merge silently (as nearly happened with the multi-user-support and set-value-arg branches, which each had to be manually verified with `go build && go vet && gofmt -l . && go test -race ./...` before every commit in this session).

## What Changes

- Adds `.github/workflows/ci.yml`: runs on every push to `main` and every pull request, building, vetting, format-checking, and race-testing the Go module using the toolchain version pinned in `go.mod` (currently 1.25.0).
- No deployment automation is added — the homebox deploy stays a manual, human-run step, as it is today; this change is CI (verification) only, not CD.
- Branch protection (a `protect-main` ruleset requiring this CI check and a PR, mirroring the `opencode-use` repo's existing ruleset with a repository-admin bypass) is **out of scope for this change** — GitHub's API refuses to create a ruleset on a private repository on the free plan; it will be added once the repo is made public, as a separate action, not part of this OpenSpec change.

## Capabilities

This is a pure tooling change with no effect on `aged`'s own runtime behavior — `skip_specs: true` is set in `.openspec.yaml`.

## Impact

- New file: `.github/workflows/ci.yml`.
- No changes to `cmd/aged/`, `go.mod`, or any runtime behavior.
- No new secrets or credentials required (the workflow only builds and tests; it does not deploy or publish anything).
