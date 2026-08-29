# Tasks: client-config

- [x] Add `ServerURL string \`toml:"server_url"\`` field to `Config`
- [x] Update `loadConfig()` to apply `AGED_SERVER_URL` env var override to `Config.ServerURL`
- [x] Update `serverURL()` in client.go to call `loadConfig().ServerURL` with default fallback
- [x] Update `request()` to use `loadConfig().Token` instead of reading `AGED_TOKEN` directly
- [x] Write `TestLoadConfig_ConfigFileProvidesServerURL` and `TestLoadConfig_EnvVarOverridesConfigFileServerURL`
- [x] Update README with client config file example
