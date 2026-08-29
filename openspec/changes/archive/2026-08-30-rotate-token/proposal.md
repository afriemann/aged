# Proposal: rotate-token command

## Problem

Rotating the bearer token requires manual file editing on the server, and the token must then be manually distributed to all client configs. There is no first-class CLI operation for this.

## Proposed Solution

Add `aged rotate-token` that generates a new cryptographically random 32-byte hex token, updates the `token` field in the located config file in place, prints the new token to stdout, and reminds the user to restart the service.

Works on both server (`/etc/aged/config.toml`) and client (`~/.config/aged/config.toml`) configs.

## Scope

In scope:
- `aged rotate-token` subcommand
- Locate config via `configFilePath()` (AGED_CONFIG → /etc/aged → ~/.config/aged)
- Generate token with `crypto/rand`
- Update only the `token` key in the config file; preserve all other keys
- Print new token to stdout
- Error if no config file is found

Out of scope:
- Automatic service restart
- Propagating the new token to remote client configs
