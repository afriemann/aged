## 1. Value resolution logic

- [x] 1.1 Write failing tests in `cmd/aged/client_test.go` for `resolveSetValue` covering: value-supplied-as-argument, value-supplied-via-stdin, value-argument-and-piped-stdin-both-present (error), empty-value-argument-rejected, empty-stdin-value-rejected — and verify they fail (function does not exist yet)
- [x] 1.2 Implement `resolveSetValue(argValue string, hasArg bool, hasPipedStdin bool, stdin io.Reader) (string, error)` in `cmd/aged/client.go` and verify the tests from 1.1 pass
- [x] 1.3 Refactor `set(name string) error` to `set(name, value string) error` (pure HTTP call, no stdin/arg handling) and verify existing behavior (store round-trip) still passes via `TestServer_SetAndGetSecret`

## 2. CLI wiring

- [x] 2.1 Update `main.go`'s `case "set"` to accept 2 or 3 positional args, detect piped stdin via `os.Stdin.Stat()`, call `resolveSetValue` then `set`, and add a test for too-many-arguments rejection; verify it fails with a usage message
- [x] 2.2 Update help text in `main.go` (`set <name> [value] ...`) and verify it renders correctly via manual `aged` (no args) run

## 3. Documentation

- [x] 3.1 Update `README.md` with an example of `aged set <name> <value>` alongside the existing stdin example

## 4. Verification

- [x] 4.1 Run `go test ./...` and `go vet ./...`, confirm all pass with no regressions
- [x] 4.2 Manually verify `aged set foobar 12345` (no pipe) stores the value without blocking, and `echo -n 12345 | aged set foobar` still works
