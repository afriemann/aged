# Proposal: Client Config File Support

## Problem

The aged CLI client currently reads its two configuration values — server URL and bearer token — exclusively from environment variables (`AGED_SERVER_URL`, `AGED_TOKEN`). This means the token must be stored in a shell profile or exported manually on every machine that uses aged. There is no way to store the token at rest in a protected file that the CLI reads automatically.

## Proposed Solution

Extend the existing `Config` struct and `loadConfig()` function to include a `server_url` field. The client commands (`get`, `set`, `list`, `delete`, `pubkey`) will read both `token` and `server_url` from the config file, with environment variables continuing to override. This means a client-only machine just needs:

```toml
# ~/.config/aged/config.toml (mode 0600)
token      = "your-bearer-token"
server_url = "https://aged.automate.wtf"
```

No environment variables required. The file is owned by the user with mode 0600 — same protection as an SSH private key.

## Scope

In scope:
- Add `server_url` config key and `ServerURL` field to `Config`
- `loadConfig()` reads `AGED_SERVER_URL` env var and maps it to `Config.ServerURL`
- `serverURL()` and `request()` use `loadConfig()` instead of reading env vars directly
- Config file lookup order unchanged (AGED_CONFIG → /etc/aged/config.toml → ~/.config/aged/config.toml)

Out of scope:
- Separate client vs server config files
- Encrypted config file
- `aged config set` subcommand
