## Why

A security review of aged's authentication process identified nine findings. This change addresses six actionable ones in Go code: two Medium-severity defects (data-loss risk during token rotation; silent config parse errors), three Low/Info-severity hardening gaps (incomplete IPv6 loopback detection; no HTTP server timeouts; test helper testing the wrong validator), and one Info-level RFC compliance gap (missing `WWW-Authenticate` header on 401).

Two findings were accepted as design behaviour (I-01: token to stdout; I-02: 405 before auth middleware). L-03 (systemd unit hardening) requires a separate path-model decision (home-directory vs `/var/lib/aged`) and README updates; it is deferred to a follow-up change.

## What Changes

- **`rotateToken`** writes the new config atomically: stage to a temp file in the same directory, `defer os.Remove(tmp)` to clean up on failure, set mode 0600, `os.Rename` (POSIX-atomic). Eliminates the truncate-before-write window that corrupts the config on crash or write error.
- **`loadConfig`** logs a warning when `toml.DecodeFile` fails, giving operators a diagnostic instead of a silent zero-value struct. The warning fires on client CLI invocations too (not only `aged serve`), which is acceptable — it goes to stderr, transparent to chezmoi's stdout-only integration.
- **`resolveClientIP`** uses `net.ParseIP(peer).IsLoopback()` instead of an exact string comparison against `"127.0.0.1"` and `"::1"`, correctly handling the IPv4-mapped loopback form `::ffff:127.0.0.1` that Go may produce on dual-stack hosts.
- **`serve()`** constructs an explicit `http.Server` with `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, and `IdleTimeout` to prevent goroutine exhaustion from slow or stalled clients.
- **`bearerMiddleware`** sets `WWW-Authenticate: Bearer realm="aged"` on `w.Header()` before every 401 response, satisfying RFC 7235 §3.1.
- **`testServer` helper** calls `validName(name)` instead of `nameRe.MatchString(name)`, so handler-level tests validate the `"."` and `".."` segment rejection that production code enforces.

## Capabilities

### New Capabilities

_None._

### Modified Capabilities

- `aged`: **Token Rotation** — add atomicity guarantee; **Config File Loading** — add parse-error warning; **HTTP Authentication** — add `WWW-Authenticate` header obligation and update loopback-detection algorithm to `net.IP.IsLoopback()`; **HTTP Server Configuration** — add timeout requirement (new requirement added to the existing `aged` capability).

## Impact

- **`cmd/aged/rotate.go`** — `rotateToken` only; `os` import already present; `path/filepath` for same-directory temp file.
- **`cmd/aged/config.go`** — `loadConfig` only; `log` import added.
- **`cmd/aged/server.go`** — `resolveClientIP`, `serve()`, `bearerMiddleware`; `time` import added; `net` import already present.
- **`cmd/aged/server_test.go`** — `testServer` helper only.
- **No new Go dependencies.**
