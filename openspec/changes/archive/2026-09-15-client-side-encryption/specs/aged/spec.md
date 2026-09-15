## MODIFIED Requirements

### Requirement: Secret Storage

The system SHALL validate that uploaded secret content begins with the age v1 file format magic (`age-encryption.org/v1\n`) and persist it verbatim as a `.age` file in the configured secrets directory, creating the directory with mode 0700 if absent. The server SHALL NOT encrypt, decrypt, or otherwise transform the content in any way — encryption and decryption happen exclusively on the client. The write SHALL be atomic: content is staged to a temporary file in the same directory, set to mode 0600, then renamed into place; a failure at any point before the rename SHALL leave the previously stored value (if any) unchanged and SHALL leave no temporary file behind.

#### Scenario: Store and retrieve round-trip
GIVEN a valid secret name and age-v1-formatted ciphertext bytes
WHEN the ciphertext is stored then retrieved
THEN the retrieved bytes equal the originally stored ciphertext exactly, with no trimming or transformation

#### Scenario: Overwrite existing secret
GIVEN a secret name already has stored ciphertext
WHEN new ciphertext is stored under the same name
THEN only the new ciphertext is returned on subsequent retrieval

#### Scenario: Failed write leaves the previous value intact
GIVEN a secret name already has stored ciphertext
AND an error occurs while writing the staged temporary file for a new value
WHEN the store attempts to persist the new value
THEN the previously stored ciphertext is unchanged
AND no stray temporary file remains in the secrets directory

### Requirement: Secret Retrieval

The system SHALL return the stored ciphertext bytes of a named secret verbatim, with no decryption, transformation, or trimming performed by the server.

#### Scenario: Retrieve existing secret
GIVEN a secret that has been stored
WHEN the secret is retrieved by name
THEN the stored ciphertext bytes are returned exactly as stored

#### Scenario: Retrieve non-existent secret
GIVEN a name that has no stored secret
WHEN retrieval is attempted
THEN an error is returned indicating the secret was not found

### Requirement: Identity Initialisation

The system SHALL generate a new X25519 age identity when `aged init` is run, writing the private key to the configured identity file with mode 0600, and print the public key to stdout. This identity is used exclusively by client-side operations (`get`, `set`, `pubkey`, `rotate-identity`) to encrypt and decrypt secret values; the server (`aged serve`) neither generates, reads, nor requires an identity to operate.

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

The server SHALL read its runtime configuration from environment variables. When a config file is also present, environment variables take precedence over config file values. The following defaults apply when a value is absent from both sources. `identity`/`AGED_IDENTITY` is a client-only setting: it configures which identity file `get`, `set`, `pubkey`, and `rotate-identity` use, and `aged serve` SHALL NOT read or require it to start.

| Variable | Config key | Default |
|---|---|---|
| `AGED_TOKEN` | `token` | — (required; server refuses to start if absent) |
| `AGED_IDENTITY` | `identity` | `~/.config/aged/identity.age` (client-only) |
| `AGED_SECRETS_DIR` | `secrets_dir` | `~/.config/aged/secrets/` |
| `AGED_ADDR` | `addr` | `127.0.0.1:8743` |
| `AGED_SERVER_URL` | `server_url` | `http://localhost:8743` |

#### Scenario: Missing token on startup
GIVEN `AGED_TOKEN` is not set and no config file provides `token`
WHEN `aged serve` is run
THEN the server exits with a non-zero code and an informative error message

#### Scenario: Server starts without any identity configured
GIVEN neither `AGED_IDENTITY` nor a config file `identity` key is set
AND `AGED_TOKEN` is set
WHEN `aged serve` is run
THEN the server starts successfully

### Requirement: Secret Name Validation

The server SHALL reject any secret name that contains characters outside `[a-zA-Z0-9._-]` or `/` (per the namespace rules), returning HTTP 400. This prevents path traversal and shell injection via the `.age` filename. The CLI client SHALL apply the identical validation rule locally before constructing the client-side encryption envelope for a `set` operation, so that an invalid name is rejected before any network request is made and before it can be embedded in the envelope's name-binding header.

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

## REMOVED Requirements

### Requirement: Public Key Endpoint

**Reason**: The server no longer holds any age identity or key material, so it has no public key to report. Moving all encryption/decryption to the client (see Client-Side Secret Encryption and Client-Side Secret Decryption) makes this endpoint meaningless.

**Migration**: Use the `aged pubkey` CLI command instead (see Local Public Key Command), which reads the caller's own local identity file and prints its recipient without any network call.

## ADDED Requirements

### Requirement: Client-Side Secret Encryption

The CLI client SHALL encrypt a secret value locally, using the identity configured for the invoking machine, before any network transmission to the server. The server SHALL at no point receive, construct, or observe the plaintext value.

The client SHALL: read the plaintext from stdin; strip exactly one trailing newline; validate the secret name (see Secret Name Validation); construct a name-binding envelope (see Name-Binding Integrity Check) from the trimmed plaintext and the validated name; encrypt the envelope to the local identity's own recipient using the age v1 format; and upload the resulting ciphertext bytes verbatim.

#### Scenario: Set encrypts before upload
GIVEN a plaintext value on stdin and a valid secret name
WHEN `aged set <name>` is run
THEN the value is encrypted locally to the caller's own identity before any request is sent
AND the server receives only ciphertext bytes

#### Scenario: Trailing newline stripped exactly once
GIVEN a plaintext value on stdin ending in a newline
WHEN `aged set <name>` is run
THEN exactly one trailing newline is stripped before encryption
AND no further trimming is applied anywhere else in the system

### Requirement: Client-Side Secret Decryption

The CLI client SHALL download the stored ciphertext for a named secret and decrypt it locally, trying every identity present in the configured identity file in order, before printing the plaintext value. The server SHALL at no point perform or assist with decryption.

#### Scenario: Get decrypts locally
GIVEN a secret previously stored via `aged set`
WHEN `aged get <name>` is run from a machine holding the matching identity
THEN the ciphertext is downloaded and decrypted locally
AND the plaintext value is printed to stdout with no trailing newline

#### Scenario: Multiple identities tried in order
GIVEN an identity file containing more than one identity
WHEN `aged get <name>` is run and the secret was encrypted to any one of them
THEN decryption succeeds using whichever identity matches
AND the client does not require the matching identity to be first in the file

#### Scenario: No identity matches
GIVEN a secret encrypted to a recipient not present in the caller's identity file
WHEN `aged get <name>` is run
THEN the client returns an error indicating the secret was not encrypted to any of the caller's identities
AND the error suggests this means the wrong machine or a rotated key
AND no partial or garbage value is printed

#### Scenario: Missing local identity
GIVEN no identity file exists at the configured path
WHEN `aged get <name>` or `aged set <name>` is run
THEN the client returns an error naming the expected path and instructing the caller to run `aged init`

### Requirement: Name-Binding Integrity Check

The plaintext handed to client-side encryption SHALL be wrapped in an envelope binding it to its secret name, so that a ciphertext file moved, renamed, or swapped with another on disk is detected and rejected on retrieval rather than silently returned under the wrong name.

The envelope format SHALL be exactly: the literal bytes `aged-v1\nname: `, followed by the secret name, followed by the literal bytes `\n\n`, followed by the value bytes verbatim to the end of the plaintext. No escaping of the name is performed or required, because valid secret names cannot contain `\n` (see Secret Name Validation).

On decryption, the client SHALL: verify the plaintext begins with the exact literal `aged-v1\nname: `; read up to the next `\n` as the bound name; verify the following byte is `\n`; and verify the bound name equals the name that was requested. A missing, malformed, or mismatched envelope SHALL be a hard failure — the value SHALL NOT be returned, printed, or logged under any circumstance, regardless of whether decryption itself otherwise succeeded.

#### Scenario: Matching name round-trips
GIVEN a secret stored under name `ha/token`
WHEN it is retrieved by the same name
THEN the envelope's bound name matches the requested name
AND the value is returned

#### Scenario: Swapped ciphertext files are detected
GIVEN two secrets `a` and `b` whose stored ciphertext files are swapped on disk (e.g. via direct filesystem manipulation)
WHEN either `a` or `b` is retrieved
THEN the decrypted envelope's bound name does not match the requested name
AND the client returns an error instead of returning the wrong value

#### Scenario: Malformed envelope rejected
GIVEN a ciphertext that decrypts to plaintext not matching the envelope grammar
WHEN it is retrieved
THEN the client returns an error
AND no value is printed

### Requirement: Ciphertext Format Validation

The server SHALL validate that uploaded content begins with the literal age v1 file format magic bytes `age-encryption.org/v1\n` before storing it, without attempting to decrypt or otherwise parse the content further. Content that does not begin with this magic SHALL be rejected with HTTP 400 and a generic error body that does not disclose library implementation details.

#### Scenario: Valid age-formatted upload accepted
GIVEN content beginning with the age v1 magic bytes
WHEN it is uploaded via `POST /secrets/{name}`
THEN the server accepts and stores it

#### Scenario: Non-age content rejected
GIVEN content that does not begin with the age v1 magic bytes (e.g. plaintext from a pre-change client)
WHEN it is uploaded via `POST /secrets/{name}`
THEN the server returns HTTP 400
AND the response body does not include any age library error text

### Requirement: Upload Size Limit

The server SHALL enforce a maximum upload size of 96 KiB on `POST /secrets/{name}` by rejecting any request body exceeding the limit with HTTP 413, rather than silently truncating it.

#### Scenario: Oversized upload rejected, not truncated
GIVEN a request body larger than 96 KiB
WHEN it is uploaded via `POST /secrets/{name}`
THEN the server returns HTTP 413
AND no truncated or partial content is stored

### Requirement: Local Public Key Command

The `aged pubkey` command SHALL read the identity file configured for the invoking machine and print the recipient (public key) of every identity found in it, one per line, without making any network request to the server.

#### Scenario: Prints local recipient
GIVEN a local identity file containing one identity
WHEN `aged pubkey` is run
THEN the identity's `age1…` recipient is printed to stdout
AND no request is made to the server

#### Scenario: Prints every recipient during rotation overlap
GIVEN a local identity file containing more than one identity
WHEN `aged pubkey` is run
THEN one recipient is printed per line, in file order

### Requirement: Stale Server Identity Warning

`aged serve` SHALL log a clear warning at startup if `identity`/`AGED_IDENTITY` is explicitly set in the environment or in the located config file, naming the configured path and explaining that the server no longer uses it and that it should be secured or removed once migration to client-side encryption has been verified. The warning SHALL NOT fire merely because a file happens to exist at the default identity path, since that path is the correct default location for a client-only identity on a combined server-and-client host.

#### Scenario: Warning fires when identity is explicitly configured
GIVEN `AGED_IDENTITY` is set in the environment, or the located config file sets `identity`
WHEN `aged serve` starts
THEN a warning is logged naming the configured path

#### Scenario: No warning when identity is left at its default
GIVEN neither `AGED_IDENTITY` nor a config file `identity` key is set
AND a file happens to exist at the default identity path
WHEN `aged serve` starts
THEN no stale-identity warning is logged

### Requirement: Identity Rotation

The system SHALL provide an `aged rotate-identity <new-identity-file>` command that re-encrypts every secret in the configured secrets directory from the currently configured identity to a new identity, as a single operation that either succeeds completely or leaves the existing secrets directory completely untouched.

The command SHALL refuse to run if the server's configured address appears to already be in use (a proxy for detecting that `aged serve` is currently running), unless invoked with `--dry-run`. The new identity file SHALL be required to contain exactly one identity; the currently configured identity file MAY contain more than one, all of which SHALL be tried when decrypting existing secrets.

For every secret, the command SHALL: decrypt it using the currently configured identity; determine its secret name from its on-disk path and validate that name using the same rule enforced elsewhere (see Secret Name Validation) — a name that fails validation SHALL abort the entire run, naming the offending file, before any secret is re-encrypted; normalise the plaintext into the name-binding envelope for that (validated) name if it is not already bound, leave it unchanged if it is already correctly bound, or abort the entire run naming the offending file if it is bound to a different name; re-encrypt the normalised plaintext to the new identity's recipient; write the result into a staging area; and immediately verify the staged result by decrypting it with the new identity and comparing it byte-for-byte to the plaintext produced for that same secret in this run.

The command SHALL only replace the live secrets directory after every secret has been individually verified. The previous secrets directory SHALL be retained as a timestamped backup rather than deleted. At no point SHALL the command print decrypted plaintext or any private key material to stdout or stderr, including on any error path.

`--dry-run` SHALL perform the same decrypt/normalise/re-encrypt/verify sequence without writing to the real secrets directory or the staging area, and SHALL report the number of secrets that would be migrated successfully and the number that would fail.

#### Scenario: Dry run reports counts without writing anything
GIVEN a secrets directory containing several secrets encrypted to the old identity
WHEN `aged rotate-identity <new-identity-file> --dry-run` is run
THEN the command reports how many secrets would migrate successfully
AND the secrets directory is unchanged
AND no staging directory is created

#### Scenario: Successful rotation replaces the store atomically
GIVEN a secrets directory containing several secrets encrypted to the old identity
WHEN `aged rotate-identity <new-identity-file>` is run and every secret verifies successfully
THEN the secrets directory is replaced with the re-encrypted secrets
AND the previous secrets directory is retained as a timestamped backup
AND every migrated secret is retrievable using the new identity

#### Scenario: Verification failure aborts without touching the live store
GIVEN a secrets directory containing several secrets encrypted to the old identity
AND re-encrypting one of them produces a value that fails verification
WHEN `aged rotate-identity <new-identity-file>` is run
THEN the command aborts before replacing the secrets directory
AND the original secrets directory is unchanged

#### Scenario: Refuses to run while the server is listening
GIVEN `aged serve` is currently running and bound to the configured address
WHEN `aged rotate-identity <new-identity-file>` is run without `--dry-run`
THEN the command refuses to run and instructs the operator to stop the server first

#### Scenario: Legacy unbound secret is migrated into the envelope format
GIVEN a secret stored by a pre-change server with no name-binding envelope
WHEN `aged rotate-identity <new-identity-file>` is run
THEN the secret is wrapped in the name-binding envelope for its name as part of re-encryption
AND it is retrievable via `aged get` afterward

#### Scenario: Misfiled secret aborts the run
GIVEN a secret whose existing name-binding envelope names a different secret than the one implied by its file path
WHEN `aged rotate-identity <new-identity-file>` is run
THEN the command aborts the entire run naming the offending file
AND no secret is re-encrypted

#### Scenario: New identity file with more than one identity is rejected
GIVEN a new identity file containing more than one identity
WHEN `aged rotate-identity <new-identity-file>` is run
THEN the command exits with a non-zero code and an error before any secret is processed

#### Scenario: No plaintext or key material is ever printed
GIVEN any successful or failed run of `aged rotate-identity`
WHEN its output is inspected
THEN no decrypted secret value and no private key material appears in stdout or stderr
