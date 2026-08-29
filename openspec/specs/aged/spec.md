# aged — Secret Server

## Purpose

aged is a small HTTP server that stores secrets as age-encrypted files on disk and exposes them to authenticated clients. A companion CLI provides `get`, `set`, `list`, `delete`, and `pubkey` commands that call the server. The primary integration target is chezmoi's `[secret]` backend: `aged get <name>` prints the plaintext value to stdout with no trailing newline.
## Requirements
### Requirement: Identity Initialisation

The system SHALL generate a new X25519 age identity when `aged init` is run, writing the private key to the configured identity file with mode 0600, and print the public key to stdout.

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

The system SHALL encrypt a plaintext value with the server's age X25519 public key and persist it as a `.age` file in the configured secrets directory, creating the directory with mode 0700 if absent.

#### Scenario: Store and retrieve round-trip
GIVEN a valid secret name and a plaintext value
WHEN the value is stored then retrieved
THEN the retrieved value equals the original plaintext

#### Scenario: Overwrite existing secret
GIVEN a secret name already has a stored value
WHEN a new value is stored under the same name
THEN only the new value is returned on subsequent retrieval

### Requirement: Secret Retrieval

The system SHALL decrypt and return the plaintext value of a named secret, with any trailing newline stripped.

#### Scenario: Retrieve existing secret
GIVEN a secret that has been stored
WHEN the secret is retrieved by name
THEN the plaintext value is returned

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

The system SHALL return the names of all stored secrets, excluding the `.age` file extension.

#### Scenario: List populated store
GIVEN one or more secrets have been stored
WHEN secrets are listed
THEN all stored secret names are returned

#### Scenario: List empty store
GIVEN no secrets have been stored
WHEN secrets are listed
THEN an empty list is returned

### Requirement: HTTP Authentication

The server SHALL reject any request whose `Authorization` header does not contain the correct bearer token, using constant-time comparison to prevent timing side-channels. Rejected requests receive HTTP 401.

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

### Requirement: Secret Name Validation

The server SHALL reject any secret name that contains characters outside `[a-zA-Z0-9._-]`, returning HTTP 400. This prevents path traversal and shell injection via the `.age` filename.

#### Scenario: Valid name accepted
GIVEN a secret name matching `[a-zA-Z0-9._-]+`
WHEN the name is used in any secrets endpoint
THEN the request is processed normally

#### Scenario: Invalid name rejected
GIVEN a secret name containing characters outside `[a-zA-Z0-9._-]` (e.g. `../evil`)
WHEN the name is used in any secrets endpoint
THEN the server returns HTTP 400

### Requirement: Public Key Endpoint

The server SHALL return its age X25519 public key as plain text at `GET /pubkey`.

#### Scenario: Retrieve public key
GIVEN the server is running with an initialised identity
WHEN `GET /pubkey` is called with a valid token
THEN the age1… public key string is returned

### Requirement: Environment Variable Configuration

The server SHALL read its runtime configuration from environment variables. When a config file is also present, environment variables take precedence over config file values. The following defaults apply when a value is absent from both sources.

| Variable | Config key | Default |
|---|---|---|
| `AGED_TOKEN` | `token` | — (required; server refuses to start if absent) |
| `AGED_IDENTITY` | `identity` | `~/.config/aged/identity.age` |
| `AGED_SECRETS_DIR` | `secrets_dir` | `~/.config/aged/secrets/` |
| `AGED_ADDR` | `addr` | `127.0.0.1:8743` |

#### Scenario: Missing token on startup
GIVEN `AGED_TOKEN` is not set and no config file provides `token`
WHEN `aged serve` is run
THEN the server exits with a non-zero code and an informative error message

### Requirement: Config File Loading

The server SHALL load configuration from a TOML file before applying environment variable overrides. The file is optional — its absence is not an error. The lookup order is: (1) path in `$AGED_CONFIG`; (2) `/etc/aged/config.toml`; (3) `~/.config/aged/config.toml`. The first file found is used; remaining paths are not checked.

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

