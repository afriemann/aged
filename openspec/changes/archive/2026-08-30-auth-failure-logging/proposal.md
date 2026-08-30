## Why

The `aged` HTTP server emits no log events when a client authenticates — successfully or not. An attacker brute-forcing the bearer token leaves no trace, and there is nothing for a tool like fail2ban to match against. Adding per-request auth logging unblocks automated IP blocking and gives operators a post-incident audit trail.

## What Changes

- **`bearerMiddleware`** logs every auth decision — one line per request, including the real client IP resolved from `X-Real-IP` → `X-Forwarded-For` → `r.RemoteAddr` fallback chain:
  - failure: `auth failure: <METHOD> <PATH> from <IP>`
  - success: `auth ok: <METHOD> <PATH> from <IP>`
- **`contrib/fail2ban/`** reference configs are added to the repository: a filter (`aged-auth.conf`) and a jail (`aged.conf`) ready to copy to `/etc/fail2ban/`.
- **`README.md`** documents the required Caddyfile `header_up X-Real-IP {remote_host}` directive and the fail2ban install steps.

## Capabilities

### New Capabilities

_None — no new spec capability is introduced. The fail2ban and README additions are deployment reference artifacts._

### Modified Capabilities

- `aged`: The **HTTP Authentication** requirement gains logging obligations — the server SHALL emit a log line recording the outcome (accepted or rejected) and the resolved client IP on every request.

## Impact

- **`cmd/aged/server.go`** — `bearerMiddleware` only; no API contract, data model, or component boundary changes.
- **`cmd/aged/server_test.go`** — two new tests for log output.
- **`contrib/fail2ban/`** — new directory; two new reference config files.
- **`README.md`** — new deployment section.
- **No new Go dependencies.** `log` and `net/http` are already imported.
- **Caddy config:** operators must add `header_up X-Real-IP {remote_host}` to the `reverse_proxy` block so `aged` sees the real client IP rather than `127.0.0.1`.
