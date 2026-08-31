## 1. Tests — red step (write failing tests first)

- [ ] 1.1 Add `TestRotateToken_AtomicWrite_OriginalIntactOnError`: inject an encoder that returns an error; assert the original config file is unchanged and no `.config-*.toml` temp file remains — verify it fails before implementation
- [ ] 1.2 Add `TestLoadConfig_MalformedConfigFileLogsWarning`: write a malformed TOML file to a temp path; set `AGED_CONFIG`; capture `log` output; assert a warning line is emitted — verify it fails
- [ ] 1.3 Add `TestResolveClientIP_IPv4MappedLoopback`: `RemoteAddr = "[::ffff:127.0.0.1]:PORT"` with `X-Real-IP: 1.2.3.4`; assert result is `"1.2.3.4"` — verify it fails
- [ ] 1.4 Add `TestBearerMiddleware_WWWAuthenticateHeaderOnFailure`: wrong token; assert response has `WWW-Authenticate: Bearer realm="aged"` — verify it fails
- [ ] 1.5 Add `TestServe_HasNonZeroTimeouts`: inspect the constructed `http.Server` (extract via a helper or use a short-lived listener); assert all four timeouts are non-zero — verify it fails

## 2. Production code

- [ ] 2.1 **M-01** — Update `rotateToken` in `rotate.go`: `os.CreateTemp(filepath.Dir(path), ".config-*.toml")` → `defer os.Remove(tmp.Name())` → `os.Chmod(0o600)` → encode → `tmp.Close()` → `os.Rename`; add `path/filepath` import; verify tests 1.1 and existing rotation tests pass
- [ ] 2.2 **M-02** — Update `loadConfig` in `config.go`: replace bare `toml.DecodeFile(path, &cfg)` with `if err := ...; err != nil { log.Printf(...) }`; remove `//nolint:errcheck`; add `log` import; verify test 1.2 passes
- [ ] 2.3 **L-01** — Update `resolveClientIP` in `server.go`: replace `peer == "127.0.0.1" || peer == "::1"` with `net.ParseIP(peer)` + `ip.IsLoopback()` guard; verify test 1.3 and existing loopback tests pass
- [ ] 2.4 **I-03** — Update `bearerMiddleware` in `server.go`: add `w.Header().Set("WWW-Authenticate", "Bearer realm=\"aged\"")` before `http.Error`; verify test 1.4 passes
- [ ] 2.5 **L-02** — Replace `http.ListenAndServe` in `serve()` with explicit `http.Server{ReadHeaderTimeout:5s, ReadTimeout:10s, WriteTimeout:30s, IdleTimeout:60s}`; add `time` import; verify test 1.5 passes
- [ ] 2.6 **I-04** — Replace `nameRe.MatchString(name)` with `validName(name)` in the three name-validating handler closures in `testServer` (`GET`, `POST`, `DELETE /secrets/{name...}`); verify full suite passes

## 3. Verification

- [ ] 3.1 Run `go test ./cmd/aged/... -count=1` — all tests pass, no failures
- [ ] 3.2 Run `go vet ./cmd/aged/...` — clean
- [ ] 3.3 Run `go build ./cmd/aged/...` — builds cleanly
