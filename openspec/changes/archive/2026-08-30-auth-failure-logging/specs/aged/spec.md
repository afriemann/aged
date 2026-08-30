## MODIFIED Requirements

### Requirement: HTTP Authentication

The server SHALL reject any request whose `Authorization` header does not contain the correct bearer token, using constant-time comparison to prevent timing side-channels. Rejected requests receive HTTP 401. Any request where the `Authorization` header is absent, uses a wrong scheme, or carries an incorrect token is a failure — all three cases are treated identically.

On every request the server SHALL emit exactly one log line recording the auth outcome and the resolved client IP, using the following pinned formats (these are a machine interface consumed by fail2ban and must not change):

- Failure: `auth failure: <METHOD> <PATH> from <IP>`
- Success: `auth ok: <METHOD> <PATH> from <IP>`

`<METHOD>` and `<PATH>` SHALL have CR, LF, and ASCII control characters replaced with `_` before logging to prevent CRLF log-injection. `<IP>` SHALL be resolved as follows:

1. Strip the port from `r.RemoteAddr` to obtain the peer IP.
2. If the peer IP is a loopback address (`127.0.0.1` or `::1`), read the `X-Real-IP` request header as the client IP; if that header is absent, use the peer IP itself.
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
