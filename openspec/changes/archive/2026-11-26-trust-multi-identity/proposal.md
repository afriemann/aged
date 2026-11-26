## Why

A user's secrets are encrypted only to the one identity on the machine that ran `aged set`. A second device sharing the same bearer token but holding a different identity cannot read them, and `rotate-identity` is a server-local, server-stopped, single-identity tool that cannot grant access to additional devices.

## Product intent

Actors: one user with several devices, each with its own age identity and the shared bearer token. Job: read and write secrets from any trusted device. Must keep: client-side encryption, server unable to decrypt, name binding. Trust model: server and token holders are untrusted for confidentiality and for recipient-set integrity; the trusted key set is the authority.

## What Changes

- New `aged trust` commands (`list`, `add`, `remove`, `sync`) manage a per-user recipient set: a default set plus per-secret deltas (`+key`/`-key`) that keep following the default.
- The manifest is an age blob under reserved name `.aged/trust`, encrypted to the default set. It carries a signing key, a monotonic counter and a signature. Clients pin the signing public key per server and user on first use (one confirmation) and refuse a lower counter. The reserved name is rejected for direct access on client and server.
- `aged set` encrypts to the secret's effective recipients (local key always included); an existing secret keeps its effective set. The upload carries the manifest version it used; the server answers 412 if the manifest moved, and the client retries.
- Trust changes use the API (server stays up), re-encrypt only affected secrets (`remove` then rotates the signing key and runs a full `sync`), write the manifest last with compare-and-swap, are idempotent (`sync` repairs partial runs), support `--dry-run`, skip and report undecryptable secrets, and refuse removing the last or local key without `--force`. `remove` warns that the key keeps ciphertext it already copied and the secret values should be rotated.
- **BREAKING**: `aged rotate-identity` and its migration runbook are removed; use `trust add <new>` then `trust remove <old>`.

## Out of scope

Pinned per-secret sets, per-device tokens, per-secret rollback protection.

## Impact

`cmd/aged` (client, server, main, new trust code), `rotate_identity.go` removal, README, `openspec/specs/aged/spec.md`.
