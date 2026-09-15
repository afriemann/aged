## Context

See `proposal.md` — Why. This document covers only *how*.

Verified facts this design rests on (checked directly against `filippo.io/age@v1.2.1` and the Go 1.22 standard library, not asserted from memory):

| Fact | Source |
|---|---|
| Every age v1 file begins with the literal bytes `age-encryption.org/v1\n` | `internal/format/format.go:108` (`const intro`), written by `Header.MarshalWithoutMAC` (`:137`) and required verbatim by `Parse` (`:245`) |
| `age.Decrypt` parses the header *before* trying any identity, then tries each identity in order, accumulating `ErrIncorrectIdentity` into `*NoIdentityMatchError` | `age.go:208-238` |
| `(*X25519Identity).Recipient() *X25519Recipient`; `(*X25519Recipient).String() string` returns the `age1…` bech32 form | `x25519.go:198-202`, `x25519.go:103-106` |
| `age.ParseIdentities` returns *only* `*X25519Identity` values, errors on any non-X25519 line, and errors if zero are found | `parse.go:23-47` |
| `http.MaxBytesReader` returns `*http.MaxBytesError` from `Read` once the limit is exceeded; the type exists in Go 1.19+ | `net/http/request.go:1148-1173`, `:1221`; module targets `go 1.22` (`go.mod:3`) |
| Secret names are constrained to `^[a-zA-Z0-9._-]+(/[a-zA-Z0-9._-]+)*$` with no `.`/`..` segments | `cmd/aged/server.go:25-39` (`nameRe`, `validName`) |
| STREAM chunk size is `64*1024`, and per-chunk overhead is `chacha20poly1305.Overhead` (16 bytes) — so for any plaintext under one chunk the ciphertext length is the plaintext length plus a *constant* | `internal/stream/stream.go:17,30-31` |

Two consequences of the `ParseIdentities` behaviour worth recording: the `len(ids) == 0` guard and the `*age.X25519Identity` type assertion in today's `newStore` are both unreachable with this library version. They are retained as defensive hygiene where identities are still parsed, not relied upon.

## Goals / Non-Goals

**Goals**

- The server process holds no private key material at any point, in memory or on disk under its control.
- Ciphertext is byte-exact end to end: what the client encrypts is what the client decrypts, with no trimming, re-encoding, or truncation anywhere in between.
- A ciphertext file moved, renamed, or swapped on disk fails a name check on retrieval instead of being returned under the wrong name.
- Migration from the current server-held-identity store is a single repeatable command that either fully succeeds or leaves the existing store untouched.

**Non-Goals (design level, beyond the proposal's scope exclusions)**

- Hiding metadata. Secret names, ciphertext sizes, and access timestamps stay visible to the operator — see *Accepted limitations*.
- Write authenticity. The name binding is an anti-mix-up measure, not a signature — see *Accepted limitations*.
- Any change to `list` or `delete` semantics, or to the `auth ok:`/`auth failure:` log contract.

## Decisions

### D1 — Envelope format: `aged-v1` name binding

The plaintext handed to `age.Encrypt` is an envelope, not the bare value. Exact byte layout:

```
aged-v1\nname: <name>\n\n<value bytes>
```

Concretely: the constant prefix `aged-v1\nname: `, then the secret name, then `\n\n`, then the value verbatim to end of stream.

Parsing rule (strict, no tolerance):

1. The plaintext MUST begin with the exact bytes `aged-v1\nname: `.
2. Read to the next `\n` — those bytes are the bound name.
3. The following byte MUST be `\n`.
4. Everything after it is the value, returned verbatim with no trimming.

**Why this shape.** A fixed magic first line makes the envelope unmistakable and gives a version dispatch point for free. A single well-known `name: ` key avoids needing a general header parser. The blank-line terminator is the universal "headers end here" convention, so a human reading a decrypted envelope needs no explanation. Binary values are unaffected because the value is raw bytes after a fixed offset.

**Name encoding: none.** `validName` already excludes `\n`, `:`, and whitespace, so no escaping is possible or needed. **This makes client-side name validation mandatory** — today only the server validates, so `aged set $'a\nb'` would inject a newline into a header the client itself constructs. The client MUST call the existing `validName` before building the envelope and reject invalid names locally. `validName`/`nameRe` are already in `package main`, so this is a call, not a move.

**Comparison** is plain byte equality. The name is not secret and is supplied by the caller, so constant-time comparison buys nothing.

**Mismatch or malformed header is a hard failure with no fallback.** The value is never returned, printed, or logged under any circumstance; the error names the requested name and the bound name (both non-secret) and nothing else.

*Alternative rejected:* tolerate a missing header and treat the whole plaintext as the value. That reopens exactly the hole the binding closes — an operator could strip the envelope and get the fallback path. There is also no legacy data to tolerate, because `rotate-identity` (D9) is the migration path and adds the envelope as it goes.

### D2 — Server: `Store` loses all crypto

`Store` keeps only `secretsDir`; `newStore(secretsDir string)` no longer reads or parses an identity. `publicKey()` and the `GET /pubkey` route are deleted.

- `setValue(name string, data []byte) error` — validates `bytes.HasPrefix(data, []byte(ageV1Magic))` where `ageV1Magic = "age-encryption.org/v1\n"` is a named constant, then writes `data` verbatim. Rejection returns a sentinel (`errInvalidFormat`) that the handler maps to HTTP 400 with the generic body `invalid secret format`. No library internals reach the response.
- `getValue(name string) ([]byte, error)` — returns the file bytes verbatim. No decrypt, no trim.
- Directory modes are unchanged: `0700` for the secrets tree and namespace directories, `0600` for secret files.

`initIdentity` moves out of `server.go` into a new `identity.go`. It generates a private key, and leaving it in the file whose entire purpose is now "holds no key material" actively misleads a reader. Pure file move, no behaviour change.

### D3 — Server: atomic `setValue` (in scope)

**Decision: yes, upgrade `setValue` to the temp-file-plus-rename pattern.** The brief flagged this as an explicit call; it is in scope, not deferred.

Rationale: today a crash mid-write leaves a truncated file, and post-change that truncated file is *unrecoverable* — the server cannot regenerate ciphertext, and the plaintext exists only on the client that already discarded it. Worse, a truncated age file still passes the magic-prefix check, so it looks healthy until someone tries to decrypt it. The marginal cost is near zero because `rotate-identity` (D9) needs exactly this helper anyway; writing it once as a shared `writeFileAtomic(path string, data []byte) error` and using it in both places is cheaper than writing it for `rotate-identity` alone and leaving `setValue` inconsistent.

The helper follows `rotate.go:41-61` exactly: `os.CreateTemp` in the destination directory (same filesystem, so `os.Rename` is atomic), fd-based `tmp.Chmod(0o600)` to avoid the path-based TOCTOU window, write, `tmp.Close()`, `os.Rename`, with `defer os.Remove(tmp.Name())` cleaning up on every failure path and no-opping after a successful rename.

### D4 — Server: transport is binary

Handlers move from `string` to `[]byte` in both directions.

- `Content-Type` on `GET` and `POST /secrets/{name}` becomes **`application/octet-stream`**. Confirmed as the right value: the payload is opaque binary with no registered media type, and `text/plain` invites charset handling by intermediaries.
- The upload limit switches from `io.LimitReader` to `http.MaxBytesReader(w, r.Body, maxUploadBytes)`. Detection is explicit:

  ```go
  var maxErr *http.MaxBytesError
  if errors.As(err, &maxErr) { /* 413 */ }
  ```

  `errors.As` on the concrete type, not string matching. Verified available in Go 1.22 (`net/http/request.go:1165`). `MaxBytesReader` also signals the server to close the connection, but the handler must still write the 413 itself.
- **`maxUploadBytes = 96 * 1024`.** The current 64 KiB limit applies to *plaintext*; applying the same number to ciphertext would silently lower the effective plaintext ceiling. Measured age v1 overhead for a single X25519 recipient is ~170 bytes of header, 16 bytes of nonce, and 16 bytes per 64 KiB STREAM chunk, plus the `aged-v1` envelope (under 300 bytes for any legal name) — comfortably under 1 KiB total. 96 KiB preserves "roughly 64 KiB of plaintext" with wide headroom and stays trivially small in memory. *Flagged: the brief did not specify a number.*

### D5 — Client: identity handling and the byte-safe helper

`cfg.Identity` becomes client-only in meaning (no config schema change). `get`, `set`, and `pubkey` load it with the `age.ParseIdentities` shape already used by `newStore` (`server.go:48-64`).

Transport: add `requestBytes(method, path string, body io.Reader) ([]byte, int, error)` returning the raw response body. The existing `request()` becomes a thin wrapper over it that applies its `strings.TrimRight(…, "\n")`, so `list` and `delete` keep byte-identical behaviour and there is exactly one transport path. `Content-Type: application/octet-stream` is set whenever a body is present; no caller sends a text body any more, so `text/plain` disappears. Non-2xx error bodies are trimmed *for display only*.

**`set`**: read stdin → trim exactly one trailing newline → build the D1 envelope → `age.Encrypt` to the identity's **own** recipient (`identity.Recipient()`) → `POST` the ciphertext bytes. The trim happens here, once, and nowhere else in the system.

**`get`**: `GET` the ciphertext bytes → `age.Decrypt(bytes.NewReader(ct), identities...)` passing **every** identity from the file (this is what makes a rotation overlap window work — `age.go:224-235` tries them in order) → verify the bound name → strip the envelope → print the value with no trailing newline.

**`pubkey`**: pure local read, no HTTP. Prints `identity.Recipient().String()` for **every** identity in the file, one per line, in file order. With the single identity of the normal case this is byte-identical to today's one-line output; during a rotation overlap it is honest instead of arbitrarily picking the first. *Flagged: the brief said "prints `identity.Recipient().String()`" without resolving the multi-identity case.*

Error messages, both actionable:

- identity file missing → name the path and say to run `aged init`.
- `*age.NoIdentityMatchError` (matched with `errors.As`, per `age.go:192-202`) → say the secret is not encrypted to any identity in *that file*, and that this means the wrong machine or a key rotated without migrating.

### D6 — Stale identity warning fires only on explicit configuration

**Decision: warn when `AGED_IDENTITY` is set non-empty, or the located config file contains an `identity` key. Do NOT warn merely because the default path exists.**

The default is `~/.config/aged/identity.age` — precisely where a *client* identity lives. On any combined server-plus-client host that file exists for entirely correct reasons, so a path-existence trigger would fire on a healthy system every start. An operator who sees a warning that is usually wrong stops reading warnings, which destroys the value of the one case that matters. The warning's actual meaning is "you configured the server to hold a key, and that is now wrong" — an explicit-configuration condition by definition.

Implementation: `loadConfig` already knows both facts at `config.go:62`, immediately before the default is applied. Set an unexported `identityExplicit bool` on `Config` there (`cfg.identityExplicit = cfg.Identity != ""`). Unexported fields are ignored by `BurntSushi/toml`, so decoding is unaffected.

*Alternative rejected:* a standalone helper that re-reads and re-parses the config file to answer the boolean. It duplicates the TOML decode and creates a second source of truth for "was this set".

`serve()` calls nothing on the identity-loading path for its own operation; the warning is a one-line stderr log naming the file and saying the server no longer uses it and it should be secured or removed once migration is verified.

### D7 — `rotate-identity`: running-server guard

The check is `net.Listen("tcp", cfg.Addr)`: success → close immediately and proceed; failure → refuse, naming the address and the error, and telling the operator to stop `aged serve`.

**The reasoning is sound, with bounded caveats.** `rotate-identity` and `aged serve` must run on the same host (both need local `secrets_dir`), and both read `cfg.Addr` from the same config, so the tested address is the served address. The `0.0.0.0` versus `127.0.0.1` question does not weaken it: on Linux a wildcard bind and a specific-address bind conflict on the same port in both directions absent `SO_REUSEADDR`/`SO_REUSEPORT`, so either combination is still detected.

Known limits, accepted and documented rather than engineered around:

- **False positive** — an unrelated process on the port causes a refusal. Wrong direction is safe (refuse, don't corrupt), and it is loud and recoverable.
- **False positive** — `EACCES` on a privileged port refuses wrongly. Accepted for the same reason. **No `--force`/override flag is added**; an override is a footgun that converts the guard's one real job into a prompt to bypass it.
- **False negative** — a server on another host sharing `secrets_dir` over a network filesystem. Outside the single-host model this design assumes.
- **TOCTOU** — `serve` could start milliseconds after the check. Unavoidable and accepted.

This is a guard rail against the common mistake, not a lock. The operator instruction "stop `aged serve` first" remains the real control, and the design states that plainly rather than implying the check is authoritative.

**`--dry-run` skips this check** — it writes nothing, so it is safe and genuinely useful to run against a live server as a pre-flight.

### D8 — `rotate-identity`: identity asymmetry

**Old identity** (`cfg.Identity`): parsed with `age.ParseIdentities`; **all** identities are passed to `age.Decrypt`, exactly as `get` does. This lets a store that is itself mid-overlap be rotated.

**New identity** (the command's path argument): parsed with `age.ParseIdentities` and required to contain **exactly one** identity. `len(ids) != 1` is an error.

*Ambiguity resolved:* this is deliberately stricter than today's `newStore`, which takes `ids[0]` and silently ignores extras. Re-encryption has exactly one target recipient; with several keys present the tool would either pick arbitrarily (silently wrong, and only discovered when a client on the other key fails to decrypt) or encrypt to multiple recipients — an explicit non-goal in the proposal. Failing loudly is the only correct option.

### D9 — `rotate-identity`: the algorithm

Traversal reuses the `filepath.WalkDir` shape from `listNames` (`server.go:155-169`), giving each file's relative path and therefore its authoritative secret name.

**Staging directory.** `os.MkdirTemp(filepath.Dir(secretsDir), filepath.Base(secretsDir)+".rotating-*")` — e.g. `~/.config/aged/secrets.rotating-1847263054`. This is collision-safe by construction (`MkdirTemp` retries, so a stale directory from a crashed run cannot collide — unlike a PID suffix, where PID reuse can), created `0700`, and a **sibling** of `secretsDir` so a whole-directory `os.Rename` is atomic and the staging tree is never seen by a traversal rooted at `secretsDir`. Cleanup is `defer os.RemoveAll(staging)`, which no-ops after a successful swap because the path no longer exists — the same trick `rotate.go:46` uses.

**Per-file transform.** For each `.age` file, in one pass, holding at most one plaintext in memory at a time:

1. Decrypt with the old identities. Failure aborts the whole run.
2. **Normalise to a bound envelope for this file's path-derived name.** This is where migration happens, and the brief did not state it: existing secrets were written by the old server and have *no* envelope.

   **Gate the derived name first.** The name comes from the on-disk relative path via `WalkDir`, not from a validated API request, so unlike every name reaching the `set` path it has never cleared `validName` (`server.go:29`). `rotate-identity` MUST call that same `validName` on the derived name **before** constructing an envelope from it, and MUST abort the run naming the offending file path if it fails — the same posture as the mismatch case below. Without this gate a file placed on disk out-of-band (a stray copy, a hand-made directory, a name legal on the filesystem but outside `nameRe`) gets that name baked into a D1 header, which D1's **name encoding: none** decision explicitly assumes cannot happen: a derived name containing `\n` or `:` would produce a header the client parses into a different name, or cannot parse at all. Validating at the point of derivation makes the assumption D1 relies on true for every path into the envelope, not just the `set` path.

   Then, three cases —
   - already bound and the name matches → leave unchanged;
   - already bound and the name **mismatches** → abort the run naming the file (that secret is misfiled; silently rebinding it would destroy the evidence);
   - not bound → wrap it with the D1 envelope for this (now validated) name.

   Detection is the `aged-v1\n` prefix plus the full D1 grammar. A legacy plaintext value that happens to satisfy the entire grammar would be misread; this is accepted as vanishingly improbable and is noted here rather than defended against.
3. Bytes are taken verbatim — **no trimming**. Legacy plaintexts were already trimmed by the old server on write (`server.go:251`), so re-trimming would be a silent second application.
4. Encrypt the normalised plaintext to the new recipient and write it to the mirrored relative path under the staging directory using the D3 `writeFileAtomic` helper.
5. **Verify immediately, per file**: re-open the just-written staged file, `age.Decrypt` with the **new** identity, read fully, and `bytes.Equal` against the plaintext held in memory from step 2. Any mismatch aborts the run.
6. Best-effort zero the in-memory plaintext before moving on. Go's GC may already have copied it, so this is hygiene, not a guarantee.

**What verification does and does not prove.** It is a self-consistency check on *this run's* data: it proves the encrypt-write-read-decrypt round trip preserved the bytes. It is **not** an independent oracle for whether the plaintext is the semantically correct secret — the old-identity decrypt in step 1 is the only authority for that. Per-file-immediate (rather than a second global pass) also bounds peak memory to one plaintext and fails fast.

**Swap.** Only after every file passes:

1. `os.Rename(secretsDir, backupDir)` where `backupDir = secretsDir + ".old-" + time.Now().UTC().Format("20060102T150405Z")`.
2. `os.Rename(stagingDir, secretsDir)`.

The timestamp format is deliberately not RFC3339: colons are awkward on some filesystems and require shell quoting in the recovery instructions the operator will paste. *Flagged: the brief said "RFC3339-ish"; this pins it.* `backupDir` existence is checked **before** the run starts, not at swap time, because a same-second collision would otherwise fail after all the work is done.

**Crash between the two renames.** The resulting state is unambiguous and self-describing: `secrets/` is absent, `secrets.old-<ts>/` holds the old ciphertext (old identity), `secrets.rotating-<rand>/` holds the new (new identity). Recovery is one rename, and the operator chooses which:

- complete the rotation → `mv secrets.rotating-<rand> secrets`, then use the new identity;
- abandon it → `mv secrets.old-<ts> secrets`, then keep the old identity.

If step 1 fails, nothing has moved and the `defer` cleans up staging. If step 2 fails after step 1 succeeded, the tool **prints this exact recovery guidance on that error path** rather than relying on the operator finding it in documentation. The server is required to be stopped throughout, so no live traffic is exposed during the window.

**`--dry-run` is fully in memory.** Decrypt with old → normalise → encrypt into a `bytes.Buffer` → decrypt that buffer with the new identity → compare. No staging directory, no temp directory, no bytes written anywhere. Then report succeeded/failed counts and exit.

*Deviation from the brief, flagged:* the brief proposed a scratch directory under the OS temp dir with unconditional `defer os.RemoveAll`. In-memory is simpler, faster, writes nothing, and makes "could this be confused with the real staging directory?" unanswerable rather than merely answered. The scratch-directory variant's only extra coverage is disk-space and permission failure — but it would exercise `/tmp`, not `secretsDir`'s parent where real staging lands, so it does not actually cover that either. The real run's stage-verify-then-swap design already fails safely on a disk-full condition without touching `secretsDir`.

**Output discipline.** Decrypted plaintext and private key material are never written to stdout or stderr on any path, including errors. Error messages may name file paths and error types; never content. On success, mirroring `rotate.go:63-66`'s operator-facing tone: counts of secrets rotated, the backup directory path, an explicit instruction to verify a real `aged get` from a real client machine **before** deleting `secrets.old-<ts>/` and the old identity file, and a note that secure deletion of the old identity file is the operator's responsibility — the tool does not attempt to shred it.

## Risks / Trade-offs

**Old client against new server** → the plaintext upload fails the magic-prefix check with a 400. Loud, immediate, no data written.

**New client against old server** → the ciphertext is stored by an old server that will try to decrypt it on read and fail. Loud, no silent leak. Client and server must be upgraded together; this is the declared BREAKING change.

**Truncated ciphertext looks valid to the prefix check** → mitigated by D3's atomic write, which makes a partially-written file unobservable. **A complete but syntactically invalid or outright garbage body passes the same check.** D3 prevents *partial* writes, not *garbage* writes: any body beginning with `age-encryption.org/v1\n` is accepted verbatim, so a client (or anything holding the bearer token) can store bytes that decrypt to nothing on `get`. This is bounded by the same trust model as the write-integrity residual below — a token holder could already overwrite any secret's value before this change — but it is a sharper case of that category and is named here rather than left implied: the failure surfaces only at the next `get`, on a machine that may not be the one that wrote it, and the original plaintext is by then unrecoverable.

**Migration aborts partway** → nothing is ever written into `secretsDir`; staging is removed by the `defer`. The only exposed window is between the two renames, and it is documented with a one-command recovery (D9).

**Guard rail mistaken for a lock** → D7's bind test can be defeated. Mitigated by stating the limits explicitly in this document and in the operator-facing output, and by refusing to add an override flag.

**Value lost if the identity file is lost** → this is the point of the change, not a defect: the server genuinely cannot recover it. The operator-facing consequence is that identity-file backup becomes as important as token backup, and the README must say so.

### Accepted limitation: metadata leakage

This change gives confidentiality of secret *values* and nothing more. The operator retains full filesystem and API access and can therefore still see every secret **name** (they are the filenames), the **exact byte length** of every value, every **access and modification timestamp**, and the existing `auth ok:` / `auth failure:` log lines with method, path, and client IP. The `aged-v1` envelope does not change this: the name is bound *inside* the ciphertext, but the same name is also the filename, in cleartext, by design — `list` and namespace traversal depend on it. Hiding names would require an encrypted or deterministic-hashed index and is explicitly out of scope. This is recorded as an accepted, documented limitation, not an oversight.

**The size leak is exact, not approximate.** For any value fitting in a single age STREAM chunk — 64 KiB, which is the entire supported range given D4's 96 KiB ciphertext cap — every element of the overhead is a constant: a fixed age header for one X25519 recipient, a 16-byte STREAM nonce, one 16-byte Poly1305 tag per chunk, and the D1 envelope's fixed 16 bytes (`aged-v1\n` + `name: ` + `\n\n`) plus the name itself. The name is already public — it *is* the filename — so the whole overhead is a constant the observer can compute. Subtracting it from the file size yields the plaintext length **to the byte**, with no key and no decryption. "Approximate" would understate this: a 12-character password and a 13-character password are distinguishable by `ls -l` alone. Padding values to a block size would close it and is deliberately not done; it is listed here as a known, accepted property of the format rather than a gap to be fixed later without a decision.

### Accepted limitation: write-integrity residual

The name-binding envelope defends against *accidental or misdirected* substitution — a file copied to the wrong path, a restore from the wrong backup, a namespace refactor gone wrong, an operator swapping two files. In all of those the bound name no longer matches the requested name and `get` fails loudly instead of returning the wrong secret. It does **not** defend against a deliberate forgery. An operator who knows the recipient public key — which is not secret, is derivable from any existing ciphertext's stanza only with the private key but is trivially available to anyone who has ever run `aged pubkey` on a client — can construct a well-formed envelope binding *any* value to *any* existing name, encrypt it to that recipient, and write it into `secretsDir`. It will pass the magic-prefix check on ingest, decrypt correctly on the client, and pass the name check.

**The actor set is wider than "an operator", and filesystem access is not a prerequisite.** Any holder of the bearer token achieves the identical outcome through the ordinary, sanctioned `POST /secrets/{name}` API — build the envelope, encrypt to the recipient, upload — with no access to `secretsDir` at all. The server's only ingest check is the `age-encryption.org/v1\n` magic prefix (D2), which a genuine, well-formed forgery passes by construction. Per the proposal's multi-machine model the identity file is copied to *every* client machine, and the recipient public key is derivable from it locally via `aged pubkey`, so the set of principals able to do this is every token-holding client — plausibly a much larger set than "the operator". None of this is new risk: a token holder could already overwrite any secret's value before this change, and the trust model has always treated the token as write authority. It is stated explicitly because the framing above implies filesystem access is the entry point, when the sanctioned API is the easier one.

Closing this requires client-side authentication of writes (a signature or MAC over name-plus-value under a key the server never sees), which the proposal explicitly defers. The residual is accepted and documented.

## Migration Plan

1. Deploy the new binary to the server host and to every client machine (breaking wire change — do not stagger).
2. Stop `aged serve`.
3. On the server host, generate the new client identity (`aged init` against a new path, or copy an existing client identity).
4. `aged rotate-identity <new-identity-file> --dry-run` — confirm the counts match the expected secret count and nothing failed.
5. `aged rotate-identity <new-identity-file>` — stages, verifies every file, then swaps.
6. Start `aged serve`. Confirm the stale-identity warning fires if and only if `identity`/`AGED_IDENTITY` is still configured for the server; remove that setting. **Absence of the warning does not mean no key is left on disk** — by D6's design it is silent for a deployment that always used the default path. Step 10 is unconditional.
7. Distribute the new identity file to every client machine that runs `get`/`set`. **Post-change this file is strictly more sensitive than the bearer token**: token compromise alone no longer yields plaintext, whereas identity compromise is total and irreversible short of a full `rotate-identity` of every secret. "Send it however the token is already sent" is therefore not a sufficient bar. Specifically:
   - transfer over a channel that is *already authenticated* and gives both confidentiality and integrity — an existing SSH/`scp` session to a known-host-verified machine, or an equivalent — not one authenticated by the very credential being replaced;
   - verify mode `0600` and correct ownership **on arrival at the destination**, not only at the source;
   - never use a channel that leaves a durable unencrypted copy: chat tools, issue trackers and tickets, email, shared drives, CI logs, or pasted terminal scrollback;
   - treat any backup of the identity file with at least the rigour the existing `rotate-token` runbook applies to the token — with the added constraint that losing this file loses the secrets outright (see *Value lost if the identity file is lost*).
8. Verify a real `aged get` from a real client machine.
9. Only then delete `secrets.old-<ts>/`.
10. **Destroy the old server identity file — unconditionally.** This step applies **even if `identity`/`AGED_IDENTITY` was never explicitly configured**: in that case the old server's live private key is sitting at the *default* identity path, unflagged, and it still decrypts every file in `secrets.old-<ts>/` and any backup of it. Move it, rename it, or delete it, and confirm it is gone. Do **not** wait for the D6 warning to prompt this — by design D6 fires only on explicit configuration, so the most common upgrade (a deployment that always used the default path) is never warned. Secure destruction is the operator's responsibility; neither `serve` nor `rotate-identity` shreds it.

**Rollback** (before steps 9 and 10 — both the backup directory *and* the old identity file are required): stop the service, `mv secrets.old-<ts> secrets`, restore the previous binary and the old `identity` config setting, restart.

## Component Breakdown

| Component | Work kind | Done when |
|---|---|---|
| Envelope pack/unpack (D1) | Go, new file | Round-trips arbitrary bytes; rejects malformed and mismatched names without exposing the value; client-side `validName` gate enforced |
| `Store` de-cryption (D2) | Go, edit `server.go`; move `initIdentity` to `identity.go` | `Store` has one field; no `age` import path reaches the serving code; `/pubkey` route gone |
| `writeFileAtomic` (D3) | Go, new shared helper | Used by both `setValue` and `rotate-identity`; a failed write leaves the previous file intact and no temp file behind |
| Binary handlers + size limit (D4) | Go, edit `server.go` | `[]byte` both directions; `application/octet-stream`; oversize body yields 413 via `errors.As` on `*http.MaxBytesError` |
| Client crypto + `requestBytes` (D5) | Go, edit `client.go` | `get`/`set` round-trip through a real server; `list`/`delete` byte-identical to before; `pubkey` makes no network call |
| Stale-identity warning (D6) | Go, edit `config.go` + `server.go` | Fires on explicit config only; silent when only the default path happens to exist |
| `rotate-identity` (D7–D9) | Go, new `rotate_identity.go` | Dry-run reports correct counts with zero bytes written; real run rejects any path-derived name failing `validName` (naming the file), migrates unbound legacy secrets, verifies every file, swaps atomically, prints recovery guidance on the swap error path |
| README + runbook | Documentation | Server setup no longer generates an identity; client setup includes `aged init`; migration runbook present, including the unconditional old-identity-destruction step and the identity-distribution handling rules; explicit warning not to point a client's `identity` at the server's old path |

## Spec Mapping

Requirements the engineer will author in `openspec/changes/client-side-encryption/specs/aged/spec.md`:

| Decision | Spec requirement | Change |
|---|---|---|
| D2 (`setValue` stores opaque bytes), D3 (atomicity) | **Secret Storage** | MODIFIED — server persists validated ciphertext verbatim, no encryption; atomic stage-and-rename; `0700`/`0600` modes retained |
| D2 (`getValue` returns raw bytes) | **Secret Retrieval** | MODIFIED — server returns stored bytes verbatim, no decryption, no trimming |
| D5 (`aged init` is a client operation) | **Identity Initialisation** | MODIFIED — behaviour unchanged, scope clarified as client-side |
| D5, D6 (`identity` is client-only) | **Environment Variable Configuration** | MODIFIED — `AGED_IDENTITY`/`identity` documented as client-only; `aged serve` no longer requires it |
| D1 (client must reject invalid names before building the envelope) | **Secret Name Validation** | MODIFIED — the same rule is now enforced client-side as well as server-side. *Flagged: not in the brief's list; required by D1's no-escaping decision* |
| D2 (`/pubkey` route deleted) | **Public Key Endpoint** | REMOVED |
| D5 (`set` path) | **Client-Side Secret Encryption** | ADDED — trim exactly once before encryption; encrypt to the identity's own recipient; upload ciphertext bytes |
| D5 (`get` path) | **Client-Side Secret Decryption** | ADDED — decrypt locally trying every identity in the file; print with no trailing newline; actionable `NoIdentityMatchError` message |
| D1 | **Name-Binding Integrity Check** | ADDED — exact envelope format; hard failure on mismatch or malformed header; value never returned on failure |
| D2 (magic-prefix check) | **Ciphertext Format Validation** | ADDED — `age-encryption.org/v1\n` prefix required; HTTP 400 with a generic body |
| D4 (`MaxBytesReader`) | **Upload Size Limit** | ADDED — oversize body rejected with HTTP 413, never truncated. *Flagged: not in the brief's list; the 413-versus-truncation difference is externally observable and needs its own contract* |
| D5 (`pubkey` is local) | **Local Public Key Command** | ADDED — reads the identity file, prints one recipient per line, makes no network call |
| D6 | **Stale Server Identity Warning** | ADDED — warns only when `identity`/`AGED_IDENTITY` is explicitly configured |
| D7, D8, D9 | **Identity Rotation** | ADDED — running-server guard, exactly-one new identity, path-derived names revalidated with `validName` before binding, stage-verify-swap, legacy envelope migration, `--dry-run`, no plaintext or key material in output, backup directory and recovery guidance |

No spec requirement:

- **Moving `initIdentity` into `identity.go`** — file organisation only, no observable behaviour change.
- **The `requestBytes` helper and `request()` becoming a wrapper over it** — internal refactor; `list` and `delete` behaviour is byte-identical by construction.
- **`newStore` signature change** — internal API, not reachable from any external contract.
- **The `writeFileAtomic` helper itself** — its observable effect is covered by the atomicity clause on **Secret Storage** and by **Identity Rotation**.
