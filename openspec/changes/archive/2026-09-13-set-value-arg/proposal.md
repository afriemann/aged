## Why

`aged set <name>` only accepts a secret value via stdin. Running `aged set foobar 12345` silently ignores the `12345` argument and blocks on `os.Stdin`, which looks exactly like a hang to a user who expected the value to be taken from the command line. Supporting an explicit value argument, alongside the existing stdin mode, removes this footgun.

## What Changes

- `aged set <name> [value]`: when a third argument is given, it is used as the secret value directly (no stdin read).
- When no third argument is given, behavior is unchanged: the value is read from stdin.
- If a value argument is given **and** stdin is piped (has data available), the command errors out rather than guessing which one to use.
- An empty-string value is rejected as a usage error in both modes (explicit empty argument, or trimmed stdin content that is empty).
- `aged set` with more than one extra argument (i.e. more than `<name> <value>`) errors out.
- Help text and README updated to document both invocation styles.

## Capabilities

### Modified Capabilities
- `aged`: `set` command accepts an optional value argument in addition to stdin, with argument/stdin ambiguity rejected and empty values rejected.

## Impact

- `cmd/aged/client.go`: `set` function signature changes; new `resolveSetValue` helper for value resolution/validation.
- `cmd/aged/main.go`: `set` argument parsing and help text.
- `README.md`: usage example.
- `openspec/specs/aged/spec.md`: `Secret Storage` requirement (client-side `set` command behavior) gains explicit scenarios for argument-based value and validation rules.
- No server, storage format, or API wire-protocol changes.
