# aged — Secret Server

## Purpose

aged is a small HTTP server that stores secrets as age-encrypted files on disk and exposes them to authenticated clients. A companion CLI provides `get`, `set`, `list`, `delete`, and `pubkey` commands that call the server. The primary integration target is chezmoi's `[secret]` backend: `aged get <name>` prints the plaintext value to stdout with no trailing newline.

## Requirements

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

### Requirement: Secret Deletion

The system SHALL remove the `.age` file for a named secret.

#### Scenario: Delete existing secret
GIVEN a secret that has been stored
WHEN the secret is deleted by name
THEN subsequent retrieval returns a not-found error

#### Scenario: Delete non-existent secret
GIVEN a name that has no stored secret
WHEN deletion is attempted
THEN an error is returned indicating the secret was not found

### Requirement: Secret Listing

The system SHALL return the names of all stored secrets, excluding the `.age` file extension, scoped to the secrets store of the authenticated user (see Per-User Storage Isolation) — a request SHALL never see another user's secret names.

#### Scenario: List populated store
GIVEN one or more secrets have been stored
WHEN secrets are listed
THEN all stored secret names are returned

#### Scenario: List empty store
GIVEN no secrets have been stored
WHEN secrets are listed
THEN an empty list is returned

### Requirement: HTTP Authentication

The server SHALL reject any request whose `Authorization` header does not match any configured user's token. The token SHALL be compared against every configured user's token using constant-time comparison, with no early exit — every configured user is compared on every request, regardless of where (or whether) a match occurs, so that timing cannot reveal which user matched or whether any user matched. (The number of configured users is not treated as a secret and is not concealed by this guarantee.) Rejected requests receive HTTP 401. Any request where the `Authorization` header is absent, uses a wrong scheme, or carries a token that matches no configured user is a failure — all such cases are treated identically. A request whose token matches exactly one configured user SHALL be routed to that user's own secrets store (see Per-User Storage Isolation).

Every rejected request SHALL include a `WWW-Authenticate: Bearer realm="aged"` response header in accordance with RFC 7235 §3.1.

On every request the server SHALL emit exactly one log line recording the auth outcome and the resolved client IP, using the following pinned formats (these are a machine interface consumed by fail2ban and must not change):

- Failure: `auth failure: <METHOD> <PATH> from <IP>`
- Success: `auth ok: <METHOD> <PATH> from <IP> as <USER>`

`<USER>` is the name of the user whose token matched. The failure line's format is unchanged — no username is available on a failed authentication, and none SHALL be guessed or logged.

`<METHOD>` and `<PATH>` SHALL have CR, LF, and ASCII control characters replaced with `_` before logging to prevent CRLF log-injection. `<IP>` and `<USER>` SHALL be sanitised in the same way. `<IP>` SHALL be resolved as follows:

1. Strip the port from `r.RemoteAddr` to obtain the peer IP.
2. If the peer IP is a loopback address as determined by `net.IP.IsLoopback()` (this covers `127.0.0.1`, `::1`, `::ffff:127.0.0.1`, and the full `127.0.0.0/8` range), read the `X-Real-IP` request header as the client IP; if that header is absent, use the peer IP itself.
3. If the peer IP is NOT a loopback address, use the peer IP directly and ignore all proxy headers.

`X-Forwarded-For` SHALL NOT be used at any step.

The log destination SHALL be injectable (an `io.Writer` parameter on `bearerMiddleware`) so tests can capture output without mutating global logger state. In production the destination is `os.Stderr`.

#### Scenario: Authorised request accepted

GIVEN a request with the correct bearer token
WHEN the request reaches any endpoint
THEN the server processes the request normally

#### Scenario: Wrong token rejected

GIVEN a request with an incorrect bearer token
WHEN the request reaches any endpoint
THEN the server returns HTTP 401

#### Scenario: Missing Authorization header rejected

GIVEN a request with no Authorization header
WHEN the request reaches any endpoint
THEN the server returns HTTP 401

#### Scenario: WWW-Authenticate header present on 401

GIVEN a request with a wrong or missing bearer token
WHEN the request reaches any endpoint
THEN the server returns HTTP 401
AND the response includes `WWW-Authenticate: Bearer realm="aged"`

#### Scenario: Auth failure logged with real client IP

GIVEN aged is behind a reverse proxy that sets `X-Real-IP` to the real client address
AND the peer IP on the connection is a loopback address
WHEN a request arrives with a wrong or missing bearer token
THEN the log contains exactly one line matching `auth failure: <METHOD> <PATH> from <REAL-CLIENT-IP>`

#### Scenario: Auth success logged with real client IP

GIVEN aged is behind a reverse proxy that sets `X-Real-IP` to the real client address
AND the peer IP on the connection is a loopback address
WHEN a request arrives with the correct bearer token
THEN the log contains exactly one line matching `auth ok: <METHOD> <PATH> from <REAL-CLIENT-IP> as <USER>`

#### Scenario: Auth failure logged with loopback IP when X-Real-IP absent

GIVEN aged receives a request from a loopback peer
AND the `X-Real-IP` header is absent
WHEN the bearer token is wrong
THEN the log contains exactly one line matching `auth failure: <METHOD> <PATH> from 127.0.0.1`
AND fail2ban does not ban `127.0.0.1` (covered by default `ignoreip`)

#### Scenario: Auth failure logged with IPv4-mapped loopback peer

GIVEN aged receives a request and the OS presents the loopback connection as `::ffff:127.0.0.1`
AND the `X-Real-IP` header is set to a real client address
WHEN the bearer token is wrong
THEN `X-Real-IP` is trusted and the log contains the real client address (not `::ffff:127.0.0.1`)

#### Scenario: Auth failure logged with direct peer IP when not behind proxy

GIVEN aged receives a direct connection from a non-loopback peer IP (e.g. `10.0.0.5`)
WHEN the bearer token is wrong
THEN the log contains exactly one line matching `auth failure: <METHOD> <PATH> from 10.0.0.5`
AND no proxy headers are read

#### Scenario: CRLF in path does not forge a second log line

GIVEN a request path containing CR or LF characters
WHEN the bearer token is wrong or correct
THEN the control characters are replaced with `_` in the log output
AND the log contains exactly one line for this request

#### Scenario: Second configured user's token authenticates

GIVEN two or more users are configured
WHEN a request carries the last configured user's correct token
THEN the server accepts the request and routes it to that user's own secrets store

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

### Requirement: Environment Variable Configuration

The server SHALL read its runtime configuration from environment variables. When a config file is also present, environment variables take precedence over config file values. The following defaults apply when a value is absent from both sources. `identity`/`AGED_IDENTITY` is a client-only setting: it configures which identity file `get`, `set`, `pubkey`, and `rotate-identity` use, and `aged serve` SHALL NOT read or require it to start.

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

### Requirement: Config File Loading

The server SHALL load configuration from a TOML file before applying environment variable overrides. The file is optional — its absence is not an error. The lookup order is: (1) path in `$AGED_CONFIG`; (2) `/etc/aged/config.toml`; (3) `~/.config/aged/config.toml`. The first file found is used; remaining paths are not checked.

If the located config file cannot be parsed, the server SHALL log a warning to stderr before continuing; environment variables may supply any missing values.

#### Scenario: Config file sets identity path

GIVEN a config file at the resolved path containing `identity = "/custom/path.age"`
AND `AGED_IDENTITY` is not set in the environment
WHEN the server starts
THEN the identity file is read from `/custom/path.age`

#### Scenario: Env var overrides config file

GIVEN a config file containing `addr = "0.0.0.0:9000"`
AND `AGED_ADDR` is set to `"127.0.0.1:8743"` in the environment
WHEN the server starts
THEN the server listens on `127.0.0.1:8743`

#### Scenario: Absent config file is not an error

GIVEN no config file exists at any of the lookup paths
AND all required values are provided via environment variables
WHEN the server starts
THEN the server starts successfully

#### Scenario: AGED_CONFIG points to a custom path

GIVEN `$AGED_CONFIG` is set to `/tmp/my-aged.toml` containing a valid config
WHEN the server starts
THEN configuration is read from `/tmp/my-aged.toml` and the standard paths are not checked

#### Scenario: Malformed config file logs a warning and continues

GIVEN a config file exists at a standard lookup path
AND the file contains invalid TOML
WHEN aged starts or a client command runs
THEN a warning is logged to stderr naming the file and the parse error
AND execution continues (environment variables may supply missing values)

### Requirement: Client Server URL Config

The CLI client SHALL read the server URL from the `server_url` config file field when `AGED_SERVER_URL` is not set in the environment. Environment variables take precedence over the config file value. When neither source provides a value, the default `http://localhost:8743` is used.

#### Scenario: Config file provides server URL
GIVEN a config file containing `server_url = "https://aged.example.com"`
AND `AGED_SERVER_URL` is not set in the environment
WHEN a client command is run
THEN requests are sent to `https://aged.example.com`

#### Scenario: Env var overrides config file server URL
GIVEN a config file containing `server_url = "https://aged.example.com"`
AND `AGED_SERVER_URL` is set to `"http://localhost:8743"`
WHEN a client command is run
THEN requests are sent to `http://localhost:8743`

### Requirement: Token Rotation

The system SHALL generate a new cryptographically random 32-byte hex token, write it to the `token` field of the target user's entry, and print the new token to stdout along with the name of the user whose token was rotated. All other config file values SHALL be preserved unchanged; comments and the original key ordering SHALL NOT be preserved (this is pre-existing behaviour, made more noticeable by `[[users]]` since per-user identifying comments are now the natural way to annotate which machine a token belongs to — operators SHOULD instead encode that information in the username itself, which survives rotation and appears in the `auth ok:` log line). If no config file is found at any of the standard lookup paths and `AGED_CONFIG` is not set, the command SHALL exit with a non-zero code.

The command SHALL accept an optional username argument. If more than one user is configured, the argument SHALL be required — the command SHALL exit with a non-zero code listing the configured names if it is omitted or does not match any configured user. If exactly one user is configured, the argument, if omitted, SHALL default to that user; its name SHALL be printed regardless of whether it was given explicitly.

The command SHALL decode the config file's `users` value defensively: an absent `users` key, a value that is not an array of tables, or an entry missing a `name` or `token` field of the expected type SHALL each produce a clear error, never a panic.

Before writing, the command SHALL validate the complete resulting set of users against the same rules `aged serve` enforces at startup (see Multi-User Configuration). A structural problem (invalid name, duplicate name, duplicate token) on any user SHALL abort the rotation, leaving the original config file unchanged. A malformed-token-format problem on a user other than the one being rotated SHALL NOT abort the rotation — it SHALL be reported as a warning naming the affected user and remedy, since `rotate-token` is itself the tool that repairs such a problem and must not be blocked by an unrelated user's pre-existing malformed token.

The update SHALL be written atomically: the new content SHALL be staged to a temporary file in the same directory as the config file, the temporary file SHALL be set to mode 0600, and then it SHALL be renamed to replace the original. If any step between staging and rename fails, the temporary file SHALL be removed and the original config file SHALL remain unchanged.

The rewritten config file SHALL retain the same owning user and group as the original file, regardless of which user invokes `aged rotate-token`. If the original owner cannot be applied to the staged file, the command SHALL fail before renaming into place, leaving the original config file unchanged.

#### Scenario: Rotates token in config file

GIVEN a config file exists at a standard path, containing exactly one `[[users]]` entry with a token
WHEN `aged rotate-token` is run
THEN that user's token field is replaced with a new value
AND the old and new tokens differ
AND the new token is printed to stdout, along with the user's name
AND all other config file fields are unchanged

#### Scenario: No config file returns an error

GIVEN no config file exists at any lookup path
AND `AGED_CONFIG` is not set
WHEN `aged rotate-token` is run
THEN the command exits with a non-zero code

#### Scenario: New token is cryptographically random

GIVEN a config file exists
WHEN `aged rotate-token` is run twice in succession
THEN the two generated tokens differ

#### Scenario: Failed write leaves original config intact

GIVEN a config file exists
AND an error occurs while writing the staged temporary file
WHEN `aged rotate-token` is run
THEN the original config file is unchanged
AND no stray temporary file remains in the config file's directory

#### Scenario: Preserves file ownership across rotation

GIVEN a config file exists, owned by a specific user and group
WHEN `aged rotate-token` is run
THEN the rewritten config file retains the same owning user and group as the original
AND this holds regardless of which user account invoked the command

#### Scenario: Username required with multiple users
GIVEN a config file with more than one `[[users]]` entry
WHEN `aged rotate-token` is run with no username argument
THEN the command exits with a non-zero code listing the configured user names

#### Scenario: Unknown username lists configured names
GIVEN a config file with one or more `[[users]]` entries
WHEN `aged rotate-token` is run with a username that matches none of them
THEN the command exits with a non-zero code listing the configured user names

#### Scenario: Malformed users value produces a clean error
GIVEN a config file whose `users` key is not an array of tables (e.g. a single inline table, or a scalar)
WHEN `aged rotate-token` is run
THEN the command exits with a non-zero code describing the problem
AND the command does not panic

#### Scenario: Rotation is blocked by a structural problem on another user
GIVEN a config file with two users, one of which has an invalid name
WHEN `aged rotate-token` is run targeting the other, valid user
THEN the command exits with a non-zero code
AND the original config file is unchanged

#### Scenario: Rotation proceeds despite another user's malformed token
GIVEN a config file with two users, one of which has a token that is not 64 hexadecimal characters
WHEN `aged rotate-token` is run targeting the other user
THEN the rotation succeeds
AND a warning naming the malformed user is printed

### Requirement: Namespaced Secret Names

Secret names SHALL support `/` as a namespace separator. Each segment between `/` characters SHALL match `[a-zA-Z0-9._-]+`. Names with empty segments, leading or trailing slashes, or any segment equal to `..` SHALL be rejected with HTTP 400. The store SHALL persist namespaced secrets as a subdirectory tree (e.g. `ha/token` → `ha/token.age` under the secrets directory).

The resolved file path SHALL be verified to lie within the secrets directory before any file operation, using the precise form of the containment check (`rel == ".."`, or `rel` begins with `".."` followed by the path separator) so that a legitimate name containing literal dots (e.g. `..foo`, a valid segment under the character class above) is never rejected. This verification SHALL additionally resolve symlinks: for an operation on an existing file, the resolved (symlink-free) path SHALL be re-verified to lie within the store's own symlink-resolved root; for a new file being created, the resolved (symlink-free) parent directory SHALL be re-verified instead. A symlink whose resolved target lies outside the store's root SHALL be rejected on every operation (get, set, delete).

The store's root directory itself SHALL never be removed by namespace cleanup, regardless of whether the configured secrets directory path carries a trailing path separator.

#### Scenario: Namespaced secret round-trip
GIVEN a name containing a `/` separator such as `ha/token`
WHEN the value is stored then retrieved
THEN the retrieved value equals the stored value

#### Scenario: Deeply nested namespace
GIVEN a name with multiple `/` separators such as `infra/db/password`
WHEN the value is stored then retrieved
THEN the retrieved value equals the stored value

#### Scenario: List returns namespaced names
GIVEN secrets `ha/token` and `ha/client-id` and `grafana/key` have been stored
WHEN secrets are listed
THEN all three namespaced names are returned

#### Scenario: Invalid name with double slash rejected
GIVEN a name containing `//` (empty segment)
WHEN the name is used in a request
THEN the server returns HTTP 400

#### Scenario: Invalid name with `..` segment rejected
GIVEN a name containing a `..` segment such as `foo/../bar`
WHEN the name is used in a request
THEN the server returns HTTP 400

#### Scenario: Delete removes empty namespace directories
GIVEN only one secret exists under a namespace (e.g. `ns/only`)
WHEN the secret is deleted
THEN the namespace directory is also removed

#### Scenario: Name containing literal dots is accepted
GIVEN a secret name such as `..foo` whose segment matches the allowed character class but is not exactly `..`
WHEN the name is used in any secrets endpoint
THEN the request is processed normally and is not rejected as a traversal attempt

#### Scenario: Symlink escaping the store root is rejected
GIVEN a symlink inside the secrets directory whose target resolves outside the store's own root
WHEN the symlinked path is used in a get, set, or delete operation
THEN the server rejects the operation

#### Scenario: Store root survives cleanup regardless of trailing separator
GIVEN the configured secrets directory path ends with a trailing path separator
AND the last secret under a namespace is deleted
WHEN the empty namespace directory is cleaned up
THEN the store's own root directory is never removed

### Requirement: HTTP Server Configuration

The server SHALL be configured with explicit per-connection timeouts to prevent goroutine exhaustion from slow or stalled clients. The following minimum timeouts SHALL be set:

| Timeout | Minimum value |
|---|---|
| `ReadHeaderTimeout` | 5 seconds |
| `ReadTimeout` | 10 seconds |
| `WriteTimeout` | 30 seconds |
| `IdleTimeout` | 60 seconds |

#### Scenario: Server is configured with non-zero timeouts

GIVEN the server is started
WHEN the HTTP server is initialised
THEN `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, and `IdleTimeout` are all set to non-zero values meeting or exceeding the minimums above

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

When more than one user is configured (see Multi-User Configuration), the command SHALL require a `--user <name>` flag naming exactly one configured user, and SHALL refuse to run without it — re-encrypting the shared, multi-tenant secrets base as if it were a single store would silently attempt to re-encrypt every user's secrets under one identity. When exactly one user is configured, `--user` MAY be omitted and SHALL default to that user; the selected user's name SHALL be printed regardless of whether it was given explicitly. The command SHALL operate only on the selected user's own secrets subtree (`secrets_dir/<name>/`) — every subsequent reference to "the secrets directory" in this requirement means that subtree, not the shared base.

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

#### Scenario: Refuses to run without --user when multiple users are configured
GIVEN more than one user is configured
WHEN `aged rotate-identity <new-identity-file>` is run without `--user`
THEN the command exits with a non-zero code naming the required flag and listing configured users

#### Scenario: Defaults to the sole user when exactly one is configured
GIVEN exactly one user is configured
WHEN `aged rotate-identity <new-identity-file>` is run without `--user`
THEN the command operates on that user's secrets and prints the selected user's name

#### Scenario: Operates only on the selected user's subtree
GIVEN more than one user is configured, each with their own secrets
WHEN `aged rotate-identity <new-identity-file> --user <name>` is run for one of them
THEN only that user's secrets are re-encrypted
AND the other users' secrets are unaffected

### Requirement: Multi-User Configuration

The server SHALL support multiple independent users, each identified by a distinct bearer token and isolated to its own storage subtree. Users SHALL be configured via a `[[users]]` array in the config file (each entry a `name` and `token` pair), an environment-variable pair (`AGED_TOKEN` + `AGED_USERNAME`, defining one additional user), or both combined — the environment-defined user (when both variables are set) SHALL be appended after every config-file-defined user, in that order, before validation.

The server SHALL fail to start, exiting with a non-zero code naming the specific problem, if any of the following hold after merging all configured users:
- No users are configured.
- Any user's name is empty, exceeds 63 bytes, starts with `-`, is exactly `.` or `..`, or contains any character outside `[a-zA-Z0-9._-]` (usernames do not support `/` namespacing, unlike secret names).
- Any user's token is empty or is not exactly 64 lowercase hexadecimal characters.
- Any two users have the same token.
- Any two users have the same name after ASCII lowercasing (checked as defense-in-depth even though the deployment target is a case-sensitive filesystem).

#### Scenario: Single user via config file
GIVEN a config file with one `[[users]]` entry
WHEN `aged serve` is run
THEN the server starts successfully and authenticates that user's token

#### Scenario: Multiple users via config file
GIVEN a config file with two or more `[[users]]` entries, each with a distinct name and token
WHEN `aged serve` is run
THEN the server starts successfully and authenticates each user's own token

#### Scenario: Single user via environment pair
GIVEN no config file `[[users]]` entries
AND `AGED_TOKEN` and `AGED_USERNAME` are both set
WHEN `aged serve` is run
THEN the server starts successfully with exactly one user, defined by the environment pair

#### Scenario: Environment pair combined with config-file users
GIVEN a config file with one `[[users]]` entry
AND `AGED_TOKEN` and `AGED_USERNAME` are both set to values naming a different user
WHEN `aged serve` is run
THEN the server starts successfully with both the config-file user and the environment-defined user

#### Scenario: No users configured refuses to start
GIVEN no `[[users]]` entries and neither `AGED_TOKEN` nor `AGED_USERNAME` set
WHEN `aged serve` is run
THEN the server exits with a non-zero code

#### Scenario: Duplicate token rejected
GIVEN two configured users share the same token
WHEN `aged serve` is run
THEN the server exits with a non-zero code naming both users

#### Scenario: Duplicate name rejected
GIVEN two configured users share the same name
WHEN `aged serve` is run
THEN the server exits with a non-zero code naming the duplicated name

#### Scenario: Case-insensitive duplicate name rejected
GIVEN two configured users are named `alice` and `Alice`
WHEN `aged serve` is run
THEN the server exits with a non-zero code, since the names differ only by case

#### Scenario: Invalid name rejected
GIVEN a configured user's name contains a character outside `[a-zA-Z0-9._-]`, or starts with `-`, or is `.` or `..`, or exceeds 63 bytes
WHEN `aged serve` is run
THEN the server exits with a non-zero code naming the invalid entry

#### Scenario: Malformed token rejected
GIVEN a configured user's token is empty or is not exactly 64 lowercase hexadecimal characters
WHEN `aged serve` is run
THEN the server exits with a non-zero code naming the invalid entry

### Requirement: Per-User Storage Isolation

Each configured user SHALL have its own secrets subtree at `secrets_dir/<name>/`, constructed eagerly at server startup — a name colliding with an existing regular file, or any other filesystem error constructing a user's store, SHALL be a startup error naming the user, never a runtime failure on that user's first request.

Before constructing any user's store, the server SHALL scan `secrets_dir` one level deep and refuse to start if any entry directly under it is not a directory (following symlinks) — such an entry indicates secrets that predate multi-user support and have not yet been moved into a user's subdirectory. The server SHALL name every such offending entry in a single aggregated error (capped at 20 entries plus a count of any remainder), distinguishing an unmigrated `.age` file from any other unexpected non-directory entry. A directory that does not match any configured user's name SHALL NOT block startup, but SHALL produce a warning naming it (this covers, without failing on, an orphaned former user's directory or a leftover single-tenant namespace directory).

A request authenticated as one user SHALL only ever be able to read, write, delete, or list secrets under that user's own subtree.

#### Scenario: Loose secret file blocks startup
GIVEN a `.age` file exists directly under `secrets_dir`, not inside any subdirectory
WHEN `aged serve` is run
THEN the server exits with a non-zero code naming the offending file and the configured user names

#### Scenario: Unexpected non-directory entry blocks startup
GIVEN a non-directory entry that is not a `.age` file exists directly under `secrets_dir`
WHEN `aged serve` is run
THEN the server exits with a non-zero code naming the offending entry

#### Scenario: Unknown subdirectory warns but does not block startup
GIVEN a directory exists directly under `secrets_dir` whose name does not match any configured user
WHEN `aged serve` is run
THEN the server starts successfully
AND a warning naming the unknown directory is logged

#### Scenario: Store construction failure is a startup error
GIVEN a configured user's name collides with an existing regular file directly under `secrets_dir`
WHEN `aged serve` is run
THEN the server exits with a non-zero code naming the user and the conflicting path

#### Scenario: One user cannot list another user's secrets
GIVEN two users each have stored secrets under their own names
WHEN one user's token is used to list secrets
THEN only that user's own secret names are returned

### Requirement: Client Secret Set Command

The `aged set <name> [value]` CLI command SHALL accept a secret value either as an explicit third argument or via stdin when the argument is omitted. The command SHALL reject the invocation when a value argument is given while stdin also has piped data available. The command SHALL reject an empty-string value, whether supplied as an explicit argument or as trimmed stdin content. The command SHALL reject an invocation with more than one positional argument after `<name>` with a usage message.

#### Scenario: Value supplied as argument
- **WHEN** `aged set foobar 12345` is run with stdin attached to a terminal (not piped)
- **THEN** the value `12345` is stored for `foobar` without reading stdin

#### Scenario: Value supplied via stdin when argument omitted
- **WHEN** `aged set foobar` is run with `12345` piped to stdin
- **THEN** the value `12345` is stored for `foobar`

#### Scenario: Value argument and piped stdin both present
- **WHEN** `aged set foobar 12345` is run while `67890` is also piped to stdin
- **THEN** the command errors out and stores nothing

#### Scenario: Empty value argument rejected
- **WHEN** `aged set foobar ""` is run
- **THEN** the command errors out and stores nothing

#### Scenario: Empty stdin value rejected
- **WHEN** `aged set foobar` is run with only a newline piped to stdin
- **THEN** the command errors out and stores nothing

#### Scenario: Too many arguments rejected
- **WHEN** `aged set foobar 12345 extra` is run
- **THEN** the command errors out with a usage message and stores nothing
