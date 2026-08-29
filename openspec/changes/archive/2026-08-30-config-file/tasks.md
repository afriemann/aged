# Tasks: config-file

## Implementation

- [x] Add `github.com/BurntSushi/toml` dependency (`go get`)
- [x] Add `Config` struct with `Token`, `Identity`, `SecretsDir`, `Addr` fields
- [x] Implement `loadConfig()`: find config file (AGED_CONFIG → /etc/aged/config.toml → ~/.config/aged/config.toml), parse TOML if found, apply env var overrides
- [x] Update `serve()` to use `loadConfig()` instead of reading env vars directly
- [x] Update `initIdentity()` to read identity path from `loadConfig()`

## Tests

- [x] Write `TestStore_*` unit tests (set/get round-trip, overwrite, not-found, delete, list empty, list populated, public key)
- [x] Write `TestServer_*` HTTP handler tests (auth middleware, CRUD endpoints, invalid name rejection)
- [x] Write `TestLoadConfig_*` tests (file sets value, env overrides file, absent file is not error, AGED_CONFIG custom path)
