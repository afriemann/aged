## Why

`aged set <name>` currently only accepts a value via stdin. Running `aged set foobar 12345` silently drops `12345` as an ignored extra argument and blocks waiting to read stdin — looking exactly like a hang. Scripted and one-off usage (chezmoi templates, ad-hoc provisioning) benefits from being able to pass the value directly as an argument.

This feature was originally proposed and implemented in PR #5 (`feat/set-value-arg`, opened 2026-09-13) but was never merged. The branch has since fallen behind by 14 commits — most significantly PR #6 (client-side-encryption), which completely rewrote the `set()` function this feature touches (it now loads the caller's identity, wraps the value in the name-binding envelope, and encrypts client-side before upload, instead of forwarding a raw stdin body to the server). The original branch's diff no longer applies. This change reimplements the same feature against the current `set()`.

## What Changes

- `aged set <name> [value]` accepts the secret value either as an explicit third argument or via stdin when the argument is omitted.
- Supplying a value argument while stdin also has piped data is rejected as an ambiguous invocation — the command errors out rather than silently picking one source.
- An empty-string value is rejected as a usage error, whether supplied via the argument or via (trimmed) stdin.
- More than one positional argument after `<name>` is rejected with a usage message.
- No change to the wire format, the HTTP API, or the client-side encryption/envelope logic: value resolution happens before encryption: whichever source (`argument` or `stdin`) is chosen, the resulting plaintext bytes are encrypted and uploaded exactly as `set` already does today.

## Capabilities

### Modified Capabilities
- `aged`: adds a requirement for the `aged set <name> [value]` command's value-resolution behavior (argument vs. stdin, and the rejection cases above). No existing requirement's behavior changes — this is additive CLI surface with no prior requirement covering it.

## Impact

- `cmd/aged/client.go`: `set()`'s signature changes from `set(name string) error` to `set(name, value string) error`; a new `resolveSetValue` helper determines the value source before `set` is called.
- `cmd/aged/main.go`: the `set` case gains argument-count handling (3 or 4 `os.Args` entries) and a stdin-piped detection helper (`stdinIsPiped`); help text updated.
- No changes to `server.go`, the HTTP API, storage, or any other command.
