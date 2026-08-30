## 1. Test (red step — write failing tests first)

- [x] 1.1 Add `TestBearerMiddleware_AuthFailureLoggedWithRealClientIP`: pass a `*bytes.Buffer` as log writer; send wrong-token request with `X-Real-IP` header from a loopback peer; assert log line matches `auth failure: GET /secrets from 1.2.3.4` — verify it fails before any implementation change
- [x] 1.2 Add `TestBearerMiddleware_AuthSuccessLoggedWithRealClientIP`: same setup but correct token; assert log line matches `auth ok: GET /secrets from 1.2.3.4` — verify it fails before any implementation change
- [x] 1.3 Add `TestBearerMiddleware_AuthFailureLoggedWithLoopbackWhenXRealIPAbsent`: loopback peer, no `X-Real-IP`; assert log line contains `from 127.0.0.1` — verify it fails
- [x] 1.4 Add `TestBearerMiddleware_AuthFailureLoggedWithDirectPeerIPWhenNotBehindProxy`: non-loopback peer IP, no proxy headers; assert log line contains the peer IP — verify it fails
- [x] 1.5 Add `TestBearerMiddleware_CRLFInPathDoesNotForgeSecondLogLine`: request path containing `\r\n`; assert exactly one log line and control chars replaced with `_` — verify it fails

## 2. Production code

- [x] 2.1 Add `sanitiseLogField(s string) string` helper in `server.go`: replace all runes where `r < 0x20 || r == 0x7f` with `_`; verify by running the CRLF test (1.5) to green
- [x] 2.2 Add `resolveClientIP(r *http.Request) string` helper: implement the three-step loopback-gate algorithm from the spec (split peer IP, loopback check, `X-Real-IP` or fallback, never XFF); verify by running tests 1.1, 1.3, 1.4 to green
- [x] 2.3 Update `bearerMiddleware` signature to `bearerMiddleware(token string, logDst io.Writer)`: create `log.New(logDst, "", 0)` inside the closure; emit `auth failure:` / `auth ok:` lines using the pinned formats with sanitised fields; verify all five new tests pass green
- [x] 2.4 Update `serve()`: call `log.SetFlags(0)` before the listener starts; pass `os.Stderr` to `bearerMiddleware`; verify `go vet ./...` passes and `aged serve` (smoke-tested via `go build`) compiles cleanly
- [x] 2.5 Update `testServer` helper in `server_test.go` to accept an `io.Writer` parameter and pass it to `bearerMiddleware`; update all existing callers to pass `io.Discard`; verify the full test suite passes

## 3. Deployment reference files

- [x] 3.1 Create `contrib/fail2ban/filter.d/aged-auth.conf` with `failregex = auth failure: \S+ \S+ from <HOST>(?::\d+)?$`; verify the regex matches a sample `auth failure:` line via `fail2ban-regex` if available
- [x] 3.2 Create `contrib/fail2ban/jail.d/aged.conf` with `backend = systemd`, `journalmatch = _SYSTEMD_UNIT=aged.service`, `maxretry = 5`, `findtime = 60`, `bantime = 600`

## 4. Documentation

- [x] 4.1 Add a `## fail2ban integration` section to `README.md` covering: (a) required Caddyfile `header_up X-Real-IP {remote_host}` directive, (b) fail2ban install steps, (c) journald rate-limit tuning note (`RateLimitBurst`), (d) success-logging metadata-disclosure trade-off
