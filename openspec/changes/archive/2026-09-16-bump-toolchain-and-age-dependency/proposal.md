## Why

A source-code security review (`SECURITY_REVIEW.md`, 2026-09-16) identified two Low/Informational findings grounded in first-party tooling output and upstream release notes:

- **F3** — `go.mod` pins `go 1.25.0` with no `toolchain` directive, so both local builds and CI resolve exactly `1.25.0`, missing all `1.25.1`–`1.25.14` stdlib patch releases. `govulncheck` reported 26 statically-reachable stdlib CVEs (mostly DoS-class) fixed in those later patches.
- **F4** — `filippo.io/age` is pinned at `v1.2.1`; upstream `v1.3.0`–`v1.3.2` added parser-hardening (header-size cap, recipient-count cap, malformed-key rejection) relevant to `aged`'s "blind server" threat model, where `aged get` decrypts ciphertext returned by a server that must not be able to compromise the client.

Neither finding has a disclosed CVE against the currently pinned versions, but both are inexpensive, low-risk maintenance fixes worth applying now rather than deferring to an incident-driven fix later.

## What Changes

- Pin the Go toolchain to the latest `1.25.x` patch (`toolchain go1.25.14`, verified as latest via the official `go.dev/dl` release index) so `GOTOOLCHAIN=auto` self-updates within the `1.25` line for both local builds and CI (`actions/setup-go@v7.0.0`, already pinned in this repo, is confirmed to honor the `toolchain` directive over the `go` directive as of `setup-go` v6.0.0+).
- Bump `filippo.io/age` from `v1.2.1` to `v1.3.2` and run `go mod tidy`. Verified via source diff of `age.go`/`x25519.go`/`parse.go` between the two versions: every symbol `aged` calls (`age.Encrypt`, `age.Decrypt`, `age.ParseIdentities`, `age.GenerateX25519Identity`, `age.X25519Identity`, `age.Recipient`, `age.Identity`) is unchanged — all differences are additive new functions. No breaking change; `v1.3.2`'s own `go.mod` requires `go >= 1.25.0`, compatible with this project's `go` directive.
- Add a `govulncheck` step to `.github/workflows/ci.yml` using the official `golang/govulncheck-action@v1.1.0` (SHA-pinned per this repo's existing convention), so future stdlib/dependency vulnerability gaps are caught automatically in CI rather than requiring a manual review to surface them (F3's secondary recommendation, explicitly requested in scope for this change).
- Run the existing test suite and static checks (`go build ./...`, `go vet ./...`, `go test -race ./...`) to confirm no regressions from the dependency/toolchain bump.

This change does not modify any of `aged`'s own behaviour, API surface, or on-disk formats — it only bumps a pinned dependency version, a toolchain patch pin, and adds a CI check.

## Capabilities

No spec-level behaviour changes. This is a dependency/toolchain/CI-tooling maintenance change with no new, modified, or removed capability in `aged`'s own observable behaviour — `skip_specs: true` is set in `.openspec.yaml`.

### New Capabilities

None.

### Modified Capabilities

None.

## Impact

- **Affected files**: `go.mod`, `go.sum`, `.github/workflows/ci.yml`.
- **Affected dependencies**: `filippo.io/age` (`v1.2.1` → `v1.3.2`); transitively `golang.org/x/crypto`/`golang.org/x/sys` may move to whatever versions `go mod tidy` resolves for the new `age` release.
- **Affected systems**: local developer builds and GitHub Actions CI (both now build with `go1.25.14` instead of `go1.25.0`; CI gains a new `govulncheck` job step).
- **No behavioural change** to the `aged` server or CLI client — this is exclusively a supply-chain/toolchain maintenance change addressing findings F3 and F4 of `SECURITY_REVIEW.md`.
