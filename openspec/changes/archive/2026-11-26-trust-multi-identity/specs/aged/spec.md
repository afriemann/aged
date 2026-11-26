## MODIFIED Requirements

### Requirement: Identity Initialisation

The system SHALL generate a new X25519 age identity when `aged init` is run, writing the private key to the configured identity file with mode 0600, and print the public key to stdout. This identity is used exclusively by client-side operations (`get`, `set`, `pubkey`, `trust`) to encrypt and decrypt secret values; the server (`aged serve`) neither generates, reads, nor requires an identity to operate.

#### Scenario: Generate new identity
GIVEN no identity file exists at the configured path
WHEN `aged init` is run
THEN a new 0600 identity file is written
AND the public key is printed to stdout

#### Scenario: Refuse to overwrite existing identity
GIVEN an identity file already exists at the configured path
WHEN `aged init` is run
THEN the command exits with a non-zero code
AND the existing identity file is unchanged

### Requirement: Environment Variable Configuration

The server SHALL read its runtime configuration from environment variables. When a config file is also present, environment variables take precedence over config file values. The following defaults apply when a value is absent from both sources. `identity`/`AGED_IDENTITY` is a client-only setting: it configures which identity file `get`, `set`, `pubkey`, and `trust` use, and `aged serve` SHALL NOT read or require it to start.

`token`/`AGED_TOKEN` is the CLI client's own credential and is read by every client command (`get`/`set`/`list`/`delete`) exactly as before. `aged serve` SHALL NOT treat a bare `token` value as an implicit tenant: server-side users come exclusively from the `[[users]]` config array and/or the `AGED_USERNAME`/`AGED_TOKEN` environment pair (see Multi-User Configuration). If `AGED_USERNAME` is set without `AGED_TOKEN`, or `AGED_TOKEN` is set without `AGED_USERNAME`, `aged serve` SHALL refuse to start with an error naming which of the two is missing.

| Variable | Config key | Default |
|---|---|---|
| `AGED_TOKEN` | `token` | — (client credential; combines with `AGED_USERNAME` to define one server user) |
| `AGED_USERNAME` | — | — (server-only; combines with `AGED_TOKEN` to define one server user) |
| `AGED_IDENTITY` | `identity` | `~/.config/aged/identity.age` (client-only) |
| `AGED_SECRETS_DIR` | `secrets_dir` | `~/.config/aged/secrets/` |
| `AGED_ADDR` | `addr` | `127.0.0.1:8743` |
| `AGED_SERVER_URL` | `server_url` | `http://localhost:8743` |

#### Scenario: Missing token on startup
GIVEN no `[[users]]` entries are configured, and neither `AGED_TOKEN` nor `AGED_USERNAME` is set
WHEN `aged serve` is run
THEN the server exits with a non-zero code and an informative error message

#### Scenario: Server starts without any identity configured
GIVEN neither `AGED_IDENTITY` nor a config file `identity` key is set
AND `AGED_TOKEN` and `AGED_USERNAME` are both set, defining one user
WHEN `aged serve` is run
THEN the server starts successfully

#### Scenario: AGED_USERNAME without AGED_TOKEN refused
GIVEN `AGED_USERNAME` is set and `AGED_TOKEN` is not set
WHEN `aged serve` is run
THEN the server exits with a non-zero code naming `AGED_TOKEN` as the missing value

#### Scenario: AGED_TOKEN without AGED_USERNAME refused
GIVEN `AGED_TOKEN` is set and `AGED_USERNAME` is not set
WHEN `aged serve` is run
THEN the server exits with a non-zero code naming `AGED_USERNAME` as the missing value

### Requirement: Secret Name Validation

The server SHALL reject any secret name that contains characters outside `[a-zA-Z0-9._-]` or `/` (per the namespace rules), returning HTTP 400. This prevents path traversal and shell injection via the `.age` filename. The server SHALL also reject, with HTTP 400, any name whose first segment equals `.aged` compared case-insensitively, on every `/secrets` route; that namespace is reserved for the trust manifest. The CLI client SHALL apply the identical validation rules locally before constructing the client-side encryption envelope for a `set` operation, so that an invalid or reserved name is rejected before any network request is made and before it can be embedded in the envelope's name-binding header.

#### Scenario: Valid name accepted
GIVEN a secret name matching `[a-zA-Z0-9._-]+`
WHEN the name is used in any secrets endpoint
THEN the request is processed normally

#### Scenario: Invalid name rejected
GIVEN a secret name containing characters outside `[a-zA-Z0-9._-]` (e.g. `../evil`)
WHEN the name is used in any secrets endpoint
THEN the server returns HTTP 400

#### Scenario: Client rejects invalid name before encrypting
GIVEN a secret name containing characters outside the allowed set
WHEN `aged set` is run with that name
THEN the client exits with a non-zero code and an error before making any network request
AND no envelope is constructed and no request is sent to the server

#### Scenario: Reserved name rejected on every secrets route
GIVEN a name whose first segment is `.aged` in any letter case (e.g. `.AGED/trust`)
WHEN it is used in a get, set, or delete request, or by the client for `aged get`, `aged set`, or `aged delete`
THEN the server returns HTTP 400 and the client exits with a non-zero code before any network request

### Requirement: Client-Side Secret Encryption

The CLI client SHALL encrypt a secret value locally before any network transmission to the server. The server SHALL at no point receive, construct, or observe the plaintext value.

The client SHALL: read the plaintext from stdin; strip exactly one trailing newline; validate the secret name (see Secret Name Validation); construct a name-binding envelope (see Name-Binding Integrity Check) from the trimmed plaintext and the validated name; encrypt the envelope using the age v1 format to the secret's effective recipients (see Trust Manifest) together with the local identity's own recipient, or to the local identity's own recipient alone when no manifest exists; and upload the resulting ciphertext bytes verbatim.

#### Scenario: Set encrypts before upload
GIVEN a plaintext value on stdin and a valid secret name
WHEN `aged set <name>` is run
THEN the value is encrypted locally before any request is sent
AND the server receives only ciphertext bytes

#### Scenario: Trailing newline stripped exactly once
GIVEN a plaintext value on stdin ending in a newline
WHEN `aged set <name>` is run
THEN exactly one trailing newline is stripped before encryption
AND no further trimming is applied anywhere else in the system

#### Scenario: Set encrypts to every effective recipient
GIVEN a manifest whose default set is keys U and V
WHEN `aged set <name>` is run on the device holding U
THEN the stored ciphertext is decryptable by both U and V

#### Scenario: Set without a manifest encrypts to the local key only
GIVEN no trust manifest exists
WHEN `aged set <name>` is run
THEN the stored ciphertext is decryptable only by the local identity

## REMOVED Requirements

### Requirement: Identity Rotation

**Reason**: Replaced by `aged trust add <new>` followed by `aged trust remove <old>`, which works through the API without stopping the server.
**Migration**: Run `aged trust add <new-pubkey>` on the old device, then `aged trust remove <old-pubkey>`. Secrets stored without the name-binding envelope by a pre-client-side-encryption server are no longer migrated; re-set them with `aged set`.

## ADDED Requirements

### Requirement: Trust Manifest

The client SHALL maintain a per-user trust manifest stored on the server as an age-encrypted blob, encrypted to the manifest's default recipient set, holding a version counter, the default recipient set, per-secret overrides (`add` and `remove` key lists per secret name), an Ed25519 signing public key, the matching signing private key, and a signature over the exact serialised body.

A secret's effective recipient set SHALL be its overrides' `add` keys unioned with the default set, minus its overrides' `remove` keys; the local identity's recipient SHALL always be included when encrypting. A change to the default set SHALL therefore apply to every secret whose overrides do not name the changed key.

#### Scenario: Per-secret addition follows later default changes
GIVEN secret `foo` is set by key U, `aged trust add X --secret foo` is run, then `aged trust add Y` is run
WHEN the effective recipient sets are evaluated
THEN `foo` is encrypted to U, X and Y
AND every other secret is encrypted to U and Y

#### Scenario: Per-secret removal wins over the default
GIVEN the default set contains U and V and `aged trust remove V --secret foo` was run
WHEN `foo` is next encrypted
THEN `foo` is encrypted to U only
AND other secrets remain encrypted to U and V

#### Scenario: Existing secret keeps its effective set on re-set
GIVEN secret `foo` has an override adding key X
WHEN `aged set foo` is run again
THEN the new ciphertext is decryptable by X

### Requirement: Trust Commands

The CLI SHALL provide `aged trust list [--secret <name>]`, `aged trust add <age1-key> [--secret <name>]`, `aged trust remove <age1-key> [--secret <name>]` and `aged trust sync`. Mutating commands SHALL accept `--dry-run`, which reports what would change without writing anything.

A mutating trust command SHALL re-encrypt only secrets whose effective set changed, verify each re-encrypted secret by decrypting it before upload, upload secrets before the manifest, and write the manifest last with a compare-and-swap, re-reading and retrying when the manifest changed concurrently. `aged trust sync` SHALL re-encrypt every decryptable secret to its effective set from the manifest, so rerunning any trust command after a partial failure converges. A secret that cannot be decrypted SHALL be skipped and reported, and the manifest SHALL NOT advance while any were skipped unless `--allow-skipped` is given. `aged trust add` of an already-trusted key SHALL succeed without change.

`aged trust remove` SHALL refuse to remove the local identity's key or the last default key unless `--force` is given, and SHALL warn that the removed key keeps access to ciphertext it already copied and that secret values should be rotated. After removing a default-set key, `aged trust remove` SHALL generate a new signing key pair for the manifest and then run a full `sync`, unless the removed key is the local identity's own key, in which case it SHALL say the sync was skipped.

#### Scenario: Add bootstraps the manifest
GIVEN no manifest exists
WHEN `aged trust add X` is run
THEN a manifest with default set {local key, X} is created, using a create-only write
AND every existing secret is re-encrypted to include X

#### Scenario: Dry run changes nothing
GIVEN a manifest exists
WHEN `aged trust add X --dry-run` is run
THEN the affected secrets are listed
AND no secret and no manifest is written

#### Scenario: Remove revokes access and syncs every secret
GIVEN a secret with a per-secret override adding X and another without
WHEN `aged trust remove X` is run
THEN X can no longer decrypt either secret
AND a secret written to the old set during the run is re-encrypted by the follow-up sync
AND the warning about previously copied ciphertext is printed

#### Scenario: Remove rotates the signing key
GIVEN devices A, B and X trust each other
WHEN A runs `aged trust remove X`
THEN the manifest carries a new signing key
AND B must confirm the new key's fingerprint before using the manifest

#### Scenario: Remove refuses the last or local key
GIVEN the default set contains only the local key
WHEN `aged trust remove <local-key>` is run without `--force`
THEN the command exits with a non-zero code and changes nothing

#### Scenario: Sync repairs a partial run
GIVEN a previous trust command uploaded some secrets and then failed before writing the manifest
WHEN `aged trust sync` is run
THEN every secret is stored encrypted to its effective set from the manifest

#### Scenario: Undecryptable secret blocks manifest advance
GIVEN one secret cannot be decrypted by the local identity
WHEN `aged trust remove K` is run without `--allow-skipped`
THEN that secret is reported as skipped
AND the manifest is not advanced

#### Scenario: Concurrent manifest change is retried
GIVEN another device changed the manifest after this command read it
WHEN this command writes the manifest
THEN the write is rejected as stale, the manifest is re-read and validated, and the command retries

### Requirement: Trust Manifest Authenticity

The client SHALL verify the manifest's Ed25519 signature and refuse a manifest whose signature is invalid or whose counter is lower than the last-seen counter for that pin. On first use for a server and user, the client SHALL display the default recipient set and the signing key fingerprint and require one confirmation, which MAY be given non-interactively via `--yes` or `AGED_TRUST_YES=1`; the pin and last-seen counter SHALL be stored in the client's config directory. A manifest signed by a different key than the pin SHALL be refused unless the user confirms the new key's fingerprint interactively or sets `AGED_TRUST_REPIN=1`; `AGED_TRUST_YES=1` SHALL NOT confirm it.

A client holding no identity that matches the manifest's recipients SHALL report that this device is not trusted, distinct from corrupt-manifest, bad-signature and name-mismatch errors.

#### Scenario: First use requires confirmation
GIVEN a manifest exists and no pin is stored for this server and user
WHEN a trust command or `aged set` is run
THEN the default recipients and signing key fingerprint are shown and confirmation is required before the pin is stored

#### Scenario: Forged manifest rejected
GIVEN a manifest whose signature does not verify under the pinned signing key
WHEN any command reads it
THEN the command fails with an error and uses no recipients from it

#### Scenario: Changed signing key needs confirmation
GIVEN a manifest signed by a key other than the pinned one with a counter not lower than the last seen
WHEN any command reads it
THEN the old and new fingerprints are shown and the command fails unless the user confirms

#### Scenario: Rolled-back manifest rejected
GIVEN a manifest with a counter lower than the stored last-seen counter
WHEN any command reads it
THEN the command fails with a rollback error

#### Scenario: Untrusted device is told so
GIVEN the local identity matches none of the manifest's default recipients
WHEN `aged set` or a trust command is run
THEN the error states this device is not trusted

### Requirement: Trust Server Endpoints

The server SHALL expose `GET /trust` and `PUT /trust` per authenticated user to store and return the manifest blob, which it SHALL validate only by the age v1 magic and treat as opaque. The manifest's version SHALL be the SHA-256 hex of the stored blob, returned as `ETag`. `PUT /trust` SHALL require `If-None-Match: *` to create or `If-Match: <etag>` to replace, answering 412 on mismatch.

`POST /secrets/{name}` SHALL require header `X-Aged-Trust: <etag>` (`none` when no manifest exists) and answer 412 when it does not equal the current manifest version, and 428 when it is missing while a manifest exists. An optional `If-Match: <secret etag>` on `POST /secrets/{name}` SHALL answer 412 when the stored secret changed. The server SHALL serialise manifest writes and secret writes per user. The manifest SHALL NOT appear in secret listings.

#### Scenario: Create-only manifest write
GIVEN no manifest exists
WHEN `PUT /trust` is sent with `If-None-Match: *`
THEN the blob is stored and its ETag returned

#### Scenario: Stale manifest write rejected
GIVEN a manifest exists
WHEN `PUT /trust` is sent with an `If-Match` that is not the current ETag
THEN the server returns HTTP 412 and the manifest is unchanged

#### Scenario: Set against a moved manifest rejected
GIVEN the manifest changed after the client read it
WHEN `POST /secrets/{name}` is sent with the old `X-Aged-Trust` value
THEN the server returns HTTP 412 and stores nothing

#### Scenario: Missing trust header rejected once a manifest exists
GIVEN a manifest exists
WHEN `POST /secrets/{name}` is sent without `X-Aged-Trust`
THEN the server returns HTTP 428

#### Scenario: Manifest hidden from listing
GIVEN a manifest and several secrets exist
WHEN secrets are listed
THEN the manifest is not among the returned names
