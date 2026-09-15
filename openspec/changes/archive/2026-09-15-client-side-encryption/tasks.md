## 1. Shared atomic-write helper (D3)

- [x] 1.1 Add `writeFileAtomic(path string, data []byte) error` to `server.go` (or a new `atomic.go`), following the `rotate.go:41-61` pattern exactly: `os.CreateTemp` in the destination directory, fd-based `tmp.Chmod(0o600)`, write, `tmp.Close()`, `os.Rename`, `defer os.Remove(tmp.Name())` on every path. Verify with a new `TestWriteFileAtomic` covering a successful write, a write that fails mid-stream (temp file cleaned up, original untouched), and an overwrite of an existing file.

## 2. Envelope pack/unpack (D1)

- [x] 2.1 Implement `packEnvelope(name string, value []byte) []byte` (`aged-v1\nname: <name>\n\n<value>`) and `unpackEnvelope(requestedName string, plaintext []byte) ([]byte, error)` enforcing the strict grammar (exact prefix, name up to `\n`, following byte `\n`, hard failure with no fallback on any deviation or name mismatch — value never returned on failure). Verify with `TestEnvelope` subtests matching the spec scenarios: `Matching name round-trips`, `Swapped ciphertext files are detected`, `Malformed envelope rejected`.

## 3. Server: Store loses all crypto, gains format validation and binary transport (D2, D4)

- [x] 3.1 Move `initIdentity` out of `server.go` into a new `identity.go` (pure file move, no behaviour change). Verify: package still builds, `TestInit` (existing) still passes unmoved.
- [x] 3.2 Reduce `Store` to `secretsDir` only; delete the `identity` field, the identity-loading code in `newStore`, and `publicKey()`. Change `newStore` signature to `newStore(secretsDir string) (*Store, error)`.
- [x] 3.3 Rewrite `setValue(name string, data []byte) error`: validate `bytes.HasPrefix(data, []byte(ageV1Magic))` (`ageV1Magic = "age-encryption.org/v1\n"` as a named constant) returning a sentinel `errInvalidFormat` on failure; otherwise persist via `writeFileAtomic` (task 1.1). Verify with `TestSetValue` subtests: `Valid age-formatted upload accepted`, `Non-age content rejected`.
- [x] 3.4 Rewrite `getValue(name string) ([]byte, error)` to return the file's raw bytes verbatim, no decrypt, no trim. Verify with `TestGetValue` subtests: `Store and retrieve round-trip`, `Retrieve non-existent secret`, `Failed write leaves the previous value intact` (via 3.3's atomic write).
- [x] 3.5 Delete the `GET /pubkey` route and its handler.
- [x] 3.6 Change the `GET`/`POST /secrets/{name}` handlers to `[]byte` in both directions; set `Content-Type: application/octet-stream`; map `errInvalidFormat` to HTTP 400 with the generic body `invalid secret format` (no library error text in the response). Verify with an HTTP-level test asserting the response body on a 400 never contains the string `age.` or any `filippo.io` package path.
- [x] 3.7 Replace `io.LimitReader(r.Body, 64*1024)` with `http.MaxBytesReader(w, r.Body, maxUploadBytes)` where `maxUploadBytes = 96 * 1024`; detect the limit via `errors.As(err, &maxErr)` on `*http.MaxBytesError` and return HTTP 413. Verify with `TestUploadSizeLimit`: `Oversized upload rejected, not truncated` — assert 413 is returned and the store contains no partial file for that name.

## 4. Server: stale identity warning (D6)

- [x] 4.1 Add an unexported `identityExplicit bool` to `Config`, set in `loadConfig` as `cfg.Identity != ""` immediately before the default path is applied (matching design.md D6). Verify unexported field is ignored by `BurntSushi/toml` decoding (existing config tests still pass).
- [x] 4.2 In `serve()`, log a warning naming the configured path if `identityExplicit` is true; do not warn otherwise. Verify with `TestServeStaleIdentityWarning` subtests: `Warning fires when identity is explicitly configured`, `No warning when identity is left at its default` (using a captured log writer, following the existing `bearerMiddleware(token, logDst)` injectable-writer pattern).

## 5. Client: local crypto, envelope, and byte-safe transport (D5)

- [x] 5.1 Add `requestBytes(method, path string, body io.Reader) ([]byte, int, error)` to `client.go` returning the raw response body; make the existing `request()` a thin wrapper applying `strings.TrimRight` on top of it, so `list`/`delete` are unaffected. Set `Content-Type: application/octet-stream` whenever a body is present.
- [x] 5.2 Rewrite `set(name string) error`: read stdin, trim exactly one trailing newline, validate the name locally via the existing `validName` before doing anything else, build the envelope (task 2.1), `age.Encrypt` to the loaded identity's own recipient, upload via `requestBytes`. Verify with `TestClientSet` subtests: `Set encrypts before upload`, `Trailing newline stripped exactly once`, `Client rejects invalid name before encrypting` (assert no request is made — e.g. via a test server that fails the test if hit).
- [x] 5.3 Rewrite `get(name string) error`: fetch ciphertext via `requestBytes`, `age.Decrypt` against every identity parsed from the identity file, unpack and verify the envelope (task 2.1), print the value with no trailing newline. Verify with `TestClientGet` subtests: `Get decrypts locally`, `Multiple identities tried in order`, `No identity matches`, `Missing local identity`.
- [x] 5.4 Rewrite `pubkey() error` to read the local identity file directly (no HTTP call) and print `identity.Recipient().String()` for every identity found, one per line. Verify with `TestClientPubkey` subtests: `Prints local recipient`, `Prints every recipient during rotation overlap`.

## 6. `aged rotate-identity` command (D7, D8, D9)

- [x] 6.1 Create `rotate_identity.go` with the command's argument parsing (`<new-identity-file>`, `--dry-run` flag) and wire it into `main.go`'s command switch and help text.
- [x] 6.2 Implement the running-server guard: `net.Listen("tcp", cfg.Addr)` — success closes and proceeds, failure refuses naming the address, unless `--dry-run` is set. Verify with `TestRotateIdentity` subtest `Refuses to run while the server is listening` (bind a listener on the configured test address first, assert the command refuses; assert `--dry-run` proceeds anyway).
- [x] 6.3 Implement identity loading: old identity from `cfg.Identity` (all parsed identities used for decrypt); new identity from the argument (must parse to exactly one identity, else error before any secret is processed). Verify with `TestRotateIdentity` subtest `New identity file with more than one identity is rejected`.
- [x] 6.4 Implement the per-file pipeline reusing the `listNames`-style `filepath.WalkDir` traversal: decrypt with old identity(ies) → validate the path-derived name via `validName` (abort naming the file on failure) → determine bound/unbound/mismatched via the envelope unpack (task 2.1) and normalise accordingly (abort naming the file on a name mismatch) → encrypt to the new recipient → write to the staging directory via `writeFileAtomic` (task 1.1) → immediately verify by decrypting the staged file with the new identity and comparing to the in-memory plaintext. Verify with `TestRotateIdentity` subtests: `Legacy unbound secret is migrated into the envelope format`, `Misfiled secret aborts the run`.
- [x] 6.5 Implement staging directory creation (`os.MkdirTemp(filepath.Dir(secretsDir), filepath.Base(secretsDir)+".rotating-*")`, mode 0700) and the swap (`os.Rename(secretsDir, secretsDir+".old-"+timestamp)` then `os.Rename(staging, secretsDir)`), only after every file verifies; `defer os.RemoveAll(staging)` for cleanup on any abort. Verify with `TestRotateIdentity` subtests: `Successful rotation replaces the store atomically`, `Verification failure aborts without touching the live store`.
- [x] 6.6 Implement `--dry-run`: run the same decrypt/normalise/encrypt/verify sequence entirely in memory (no staging directory, no real writes), then report success/failure counts. Verify with `TestRotateIdentity` subtest `Dry run reports counts without writing anything` — assert the secrets directory's mtime/contents are unchanged and no `.rotating-*` sibling directory exists afterward.
- [x] 6.7 Ensure no code path in `rotate_identity.go` writes decrypted plaintext or private key material to stdout/stderr, including error paths (paths and error types only). Verify with `TestRotateIdentity` subtest `No plaintext or key material is ever printed` — capture stdout/stderr across a success and a failure run and assert neither known plaintext fixture values nor identity file contents appear.

## 7. Documentation

- [x] 7.1 Rewrite `README.md`'s server setup section: remove `aged init` from the server-setup steps; add client setup instructions including `aged init`; add a migration runbook section following design.md's Migration Plan (stop server → generate new identity → dry-run → real run → restart → confirm/act on the stale-identity warning → destroy the old default-path identity file unconditionally → distribute the new identity file with the strengthened guidance from design.md's step 7 → verify → delete the backup). Verify: a human read-through against design.md's Migration Plan section confirms no step is missing.
- [x] 7.2 Add an explicit note that a client's `identity`/`AGED_IDENTITY` must never be pointed at the server's old identity path, and that `configFilePath()` checks `/etc/aged/config.toml` before `~/.config/aged/config.toml` — relevant on a combined server+client host.

## 8. Final verification

- [x] 8.1 Run the full existing test suite plus all new tests added above; fix any failure.
- [x] 8.2 Run `go vet ./...` and address any finding.
- [x] 8.3 Confirm every scenario in `specs/aged/spec.md` (this change) has a name-matched test per the mapping above, and that every `tasks.md` checkbox is ticked before archiving.
