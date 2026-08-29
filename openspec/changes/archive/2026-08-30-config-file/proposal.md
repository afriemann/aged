# Proposal: Config File Support

## Problem

aged server configuration is currently read exclusively from environment variables. While functional, this requires either exporting variables in the shell or using a systemd `EnvironmentFile`. There is no human-friendly config file that a user can create once and forget, and no precedent for per-directory development overrides.

## Proposed Solution

Add a TOML config file that the server reads on startup, with environment variables overriding individual fields. The file is optional — aged continues to work with env vars alone.

**Lookup order (first found wins):**
1. Path in `$AGED_CONFIG` env var
2. `/etc/aged/config.toml` (system-wide)
3. `~/.config/aged/config.toml` (user)

**Config file format:**
```toml
token      = "your-bearer-token"
identity   = "/var/lib/aged/identity.age"
secrets_dir = "/var/lib/aged/secrets"
addr       = "127.0.0.1:8743"
```

**Env var override priority:** any `AGED_*` variable set in the environment overrides the corresponding config file field, identical to current behaviour.

## Scope

In scope:
- TOML config file parsing on `aged serve` and `aged init`
- `AGED_CONFIG` env var to specify a custom config path
- Env vars continue to override config file values
- Config file is optional — absence is not an error

Out of scope:
- Config file for client commands (client already has two env vars only)
- Config validation beyond what's already done (e.g. token length)
- A `aged config` subcommand for editing the file

## Dependencies

Adds one dependency: `github.com/BurntSushi/toml` for TOML parsing.
