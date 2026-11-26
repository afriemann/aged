## Decisions

**Version/ETag.** The server never decrypts. The manifest version is the SHA-256 hex of the stored blob, returned as `ETag`. The signed counter inside the plaintext is separate and is checked only by clients.

**Server surface (minimal).** New per-tenant `GET /trust` and `PUT /trust` (If-None-Match: * to create, If-Match: etag to swap; 412 on mismatch). The blob is stored at `<user>/.aged/trust` and must carry the age magic. `listNames` already hides it, since the file has no `.age` suffix. Per-store mutex serialises PUT /trust and POST /secrets.

**Set precondition.** `POST /secrets/{name}` requires header `X-Aged-Trust: <etag>` (`none` when no manifest exists). A mismatch gives 412 and a missing header gives 428 once a manifest exists. Optional `If-Match: <secret etag>` is used by trust re-encryption to avoid overwriting concurrent `set`.

**Reserved name.** Every `/secrets` route rejects names whose first segment equals `.aged` case-insensitively (400). The client rejects them too. The manifest envelope binds the name `.aged/trust`.

**Manifest plaintext.** Envelope-wrapped JSON `{body, sig}`. `body` = version counter, default recipients, overrides `{name:{add,remove}}`, signing public key, and the signing private key. `sig` = Ed25519 over `"aged-trust-v1\n"` + the exact stored `body` bytes; the counter is inside `body`.

**Pins.** `<config dir>/trust-pins.json`, keyed by server URL + truncated SHA-256 of the token. Each entry holds the signing pubkey and last-seen counter. First use needs one confirmation (`--yes` / `AGED_TRUST_YES=1` for non-interactive). A lower counter is refused. A different signing key is refused unless re-pinned explicitly.

**Bootstrap.** The first `trust add` creates the manifest (default = local key, new signing key, counter 1) using create-only PUT.

**Delta semantics.** Effective set = (default ∪ add) \ remove, so `remove` wins over default. `trust remove K` deletes K from default and drops all `add K` deltas. The local key is always included at encrypt time. Removing the local key or the last default key needs `--force`. `sync` drops deltas for secrets that no longer exist.

**Trust run.** Re-encrypt affected secrets first, then CAS the manifest last (retry on 412 after re-reading and re-validating). `trust sync` derives the target from the manifest and re-encrypts every decryptable secret, so it is idempotent. Undecryptable secrets are skipped and reported. The manifest does not advance while any were skipped unless `--allow-skipped` is given.

**Errors.** A "not a trusted device" error (no identity matches the manifest) is distinct from corrupt, bad-signature, or name-mismatch errors.

**Layout.** `trust.go` (manifest, signing, pins, effective-set logic), `trust_cmd.go` (list/add/remove/sync), `trust_server.go` (handlers, mutex, reserved-name check). `set`/`get` in `client.go` call the trust helpers. `main.go` is updated. `rotate_identity.go`, its tests, and the `warnIfIdentityConfigured` text referencing it are removed or updated.

**UX/utility impact.** `set` gains one manifest GET. The first use per server needs a confirmation. A device outside the default set cannot `set` until trusted. No other must-keep capability is restricted.
