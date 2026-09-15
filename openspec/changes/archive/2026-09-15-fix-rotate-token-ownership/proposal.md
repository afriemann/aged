## Why

`aged rotate-token` rewrites the config file via a temp-file-plus-rename atomic write. `os.CreateTemp` creates the temp file owned by whoever *runs* the command, not the original file's owner — so if `rotate-token` is invoked as a different user than the one the service runs as (e.g. root, or an interactive user, rather than the dedicated `aged` service account), the rotated config file silently changes ownership. The service then fails to read its own 0600 config on next start ("permission denied"), refuses to start (no token), and — behind a reverse proxy — surfaces as a 502 with no indication the actual cause is a file-ownership regression from a token rotation. This was hit live in production.

## What Changes

- `rotateToken` SHALL preserve the original config file's owning user and group across the atomic rewrite, regardless of which user invokes the command.
- If ownership cannot be preserved, the command SHALL fail before renaming into place (the existing atomic-write failure path already guarantees the original file is left untouched and no stray temp file remains).

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `aged`: the `Token Rotation` requirement gains an ownership-preservation guarantee and a new scenario covering it; no change to its existing scenarios' behaviour.

## Impact

- **Code**: `cmd/aged/rotate.go` (`rotateToken`) — read the original file's owner before staging the temp file, apply it to the temp file before rename. Uses `syscall.Stat_t` (Linux-only, consistent with this project's existing systemd/journald-only deployment target — no new external dependency).
- **Out of scope**: any change to `rotate-identity`'s already-correct-by-construction file handling (it creates its own files fresh, owned by whoever runs it, which is the intended model there since the operator running migration already needs to be able to read the results); any change to how `set`/`init` create files (both already write as whichever user invokes them, which is correct for client-side, single-user-owned files).
