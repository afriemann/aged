## ADDED Requirements

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

## MODIFIED Requirements

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
