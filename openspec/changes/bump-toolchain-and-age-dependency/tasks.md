## 1. Dependency and toolchain bump

- [x] 1.1 Add `toolchain go1.25.14` directive to `go.mod` alongside the existing `go 1.25.0` line and verify `go version` (or `go env GOTOOLCHAIN` behaviour) resolves `go1.25.14` for this module
- [x] 1.2 Bump `filippo.io/age` to `v1.3.2` in `go.mod` and run `go mod tidy`; verify `go.sum` is regenerated with no unexpected diff (only `filippo.io/age` and its own transitive deps change)
- [x] 1.3 Run `go build ./...`, `go vet ./...`, and `go test -race ./...` and verify all pass with no regressions from the dependency/toolchain bump

## 2. CI: add govulncheck step

- [x] 2.1 Add a new step to `.github/workflows/ci.yml` running `golang/govulncheck-action@032d45514ae346b1db93c04b0c90b841c370344f # v1.1.0` with `go-version-file: go.mod` and `repo-checkout: false`, placed after the existing `Test (race detector)` step, and verify the workflow YAML is well-formed (e.g. `yamllint` or a dry parse)

## 3. Verification

- [x] 3.1 Confirm `gofmt -l .` reports no unformatted files after the `go.mod`/`go.sum` changes
- [x] 3.2 Confirm the full local test suite (`go build ./...`, `go vet ./...`, `go test -race ./...`) is green before requesting review
