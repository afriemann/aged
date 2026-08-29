## ADDED Requirements

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

## MODIFIED Requirements

### Requirement: Environment Variable Configuration

The server SHALL read its runtime configuration from environment variables. When a config file is also present, environment variables take precedence over config file values. The following defaults apply when a value is absent from both sources.

| Variable | Config key | Default |
|---|---|---|
| `AGED_TOKEN` | `token` | — (required; server refuses to start if absent) |
| `AGED_IDENTITY` | `identity` | `~/.config/aged/identity.age` |
| `AGED_SECRETS_DIR` | `secrets_dir` | `~/.config/aged/secrets/` |
| `AGED_ADDR` | `addr` | `127.0.0.1:8743` |
| `AGED_SERVER_URL` | `server_url` | `http://localhost:8743` |

#### Scenario: Missing token on startup
GIVEN `AGED_TOKEN` is not set and no config file provides `token`
WHEN `aged serve` is run
THEN the server exits with a non-zero code and an informative error message
