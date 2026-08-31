## MODIFIED Requirements

### Requirement: HTTP Authentication

The server SHALL reject any request whose `Authorization` header does not contain the correct bearer token, using constant-time comparison to prevent timing side-channels. Rejected requests receive HTTP 401. Any request where the `Authorization` header is absent, uses a wrong scheme, or carries an incorrect token is a failure — all three cases are treated identically.

Every rejected request SHALL include a `WWW-Authenticate: Bearer realm="aged"` response header in accordance with RFC 7235 §3.1.

On every request the server SHALL emit exactly one log line recording the auth outcome and the resolved client IP, using the following pinned formats (these are a machine interface consumed by fail2ban and must not change):

- Failure: `auth failure: <METHOD> <PATH> from <IP>`
- Success: `auth ok: <METHOD> <PATH> from <IP>`

`<METHOD>` and `<PATH>` SHALL have CR, LF, and ASCII control characters replaced with `_` before logging to prevent CRLF log-injection. `<IP>` SHALL be sanitised in the same way and SHALL be resolved as follows:

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
THEN the log contains exactly one line matching `auth ok: <METHOD> <PATH> from <REAL-CLIENT-IP>`

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

### Requirement: Token Rotation

The system SHALL generate a new cryptographically random 32-byte hex token, write it to the `token` field of the located config file, and print the new token to stdout. All other config file keys SHALL be preserved unchanged. If no config file is found at any of the standard lookup paths and `AGED_CONFIG` is not set, the command SHALL exit with a non-zero code.

The update SHALL be written atomically: the new content SHALL be staged to a temporary file in the same directory as the config file, the temporary file SHALL be set to mode 0600, and then it SHALL be renamed to replace the original. If any step between staging and rename fails, the temporary file SHALL be removed and the original config file SHALL remain unchanged.

#### Scenario: Rotates token in config file

GIVEN a config file exists at a standard path containing a token
WHEN `aged rotate-token` is run
THEN the config file's token field is replaced with a new value
AND the old and new tokens differ
AND the new token is printed to stdout
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

## ADDED Requirements

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
