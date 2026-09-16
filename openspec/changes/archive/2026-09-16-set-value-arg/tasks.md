## 1. Value resolution helper

- [x] 1.1 Add `stdinIsPiped() bool` (uses `os.Stdin.Stat()`'s mode bits to detect a non-terminal stdin) and `resolveSetValue(argValue string, hasArg bool, hasPipedStdin bool, stdin io.Reader) (string, error)` in `cmd/aged/client.go`; verify with unit tests covering all six spec scenarios (argument given, stdin given, both given, empty argument, empty stdin, and — via `parseSetArgs`, task 2.1 — too many arguments).

## 2. CLI wiring

- [x] 2.1 Update `main.go`'s `case "set"`: accept 3 or 4 `os.Args` entries (reject anything else with the existing usage-message style), resolve the value via `resolveSetValue`/`stdinIsPiped`, and call `set(name, value)`; update the command's help text (`set <name> [value]`). Verify with a table test on the argument-count guard covering 2, 3, 4, and 5 total `os.Args` entries.
- [x] 2.2 Change `set`'s signature in `client.go` from `set(name string) error` to `set(name, value string) error`, removing its internal `io.ReadAll(os.Stdin)` step and using the passed-in value directly for the existing envelope/encrypt/upload logic (client-side encryption is otherwise unchanged). Verify the existing `TestClient_Set...` tests (updated to the new signature) still pass, and add a round-trip test that stores via an explicit argument and retrieves via `get`.

## 3. Final verification

- [x] 3.1 Run `go build ./... && go vet ./... && gofmt -l . && go test -race ./...`; fix any failure.
- [x] 3.2 Confirm every scenario in `specs/aged/spec.md` (this change) has a name-matched test, and every `tasks.md` checkbox is ticked before archiving.
