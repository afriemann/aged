# aged

A small age-encrypted secret server. Secrets are stored as age-encrypted files on disk; a lightweight HTTP API exposes them to any machine on your network. Designed to be used as a [chezmoi](https://chezmoi.io) secret backend.

## Install

```sh
make install          # installs to /usr/local/bin/aged
# or
make install PREFIX=~/.local
```

## Server setup (on homebox)

**1. Generate an identity key:**

```sh
aged init
# public key:  age1xxxx...
# identity:    ~/.config/aged/identity.age
```

**2. Create `/etc/aged/env`** (mode 0600):

```sh
AGED_TOKEN=<generate with: openssl rand -hex 32>
AGED_IDENTITY=/home/<user>/.config/aged/identity.age
AGED_SECRETS_DIR=/home/<user>/.config/aged/secrets/
AGED_ADDR=127.0.0.1:8743
```

**3. Install and start the systemd service:**

```sh
sudo cp aged.service /etc/systemd/system/aged.service
sudo systemctl daemon-reload
sudo systemctl enable --now aged
```

**4. Put it behind your reverse proxy** (Caddy example):

```
secrets.home.example.com {
    reverse_proxy 127.0.0.1:8743
}
```

## Configuration

aged can be configured via a TOML config file, environment variables, or both. Environment variables always take precedence over the config file.

**Config file lookup order** (first found wins):
1. `$AGED_CONFIG` — custom path
2. `/etc/aged/config.toml` — system-wide
3. `~/.config/aged/config.toml` — user

**Example `/etc/aged/config.toml`:**

```toml
token       = "your-bearer-token"
identity    = "/var/lib/aged/identity.age"
secrets_dir = "/var/lib/aged/secrets"
addr        = "127.0.0.1:8743"
```

**Environment variable overrides:**

| Variable | Config key | Default |
|---|---|---|
| `AGED_TOKEN` | `token` | — (**required**) |
| `AGED_IDENTITY` | `identity` | `~/.config/aged/identity.age` |
| `AGED_SECRETS_DIR` | `secrets_dir` | `~/.config/aged/secrets/` |
| `AGED_ADDR` | `addr` | `127.0.0.1:8743` |

## Client usage


Create `~/.config/aged/config.toml` (mode 0600) — no environment variables needed:

```toml
token      = "your-bearer-token"
server_url = "https://aged.automate.wtf"
```

```sh
chmod 600 ~/.config/aged/config.toml
```

Environment variables (`AGED_TOKEN`, `AGED_SERVER_URL`) still override the config file when set.

```sh
# Store a secret
echo -n "my-token-value" | aged set ha-token

# Retrieve it
aged get ha-token

# List all secrets
aged list

# Delete
aged delete ha-token

# Show server's public key
aged pubkey
```

## chezmoi integration

In `~/.config/chezmoi/ai-dotfiles.toml` (machine-local, never committed):

```toml
[secret]
command = "aged"
args = ["get"]

[data]
secret_ha_token = "ha-token"
```

Then in any chezmoi template:

```
{{ secret "ha-token" }}
```

chezmoi calls `aged get ha-token` and uses the stdout as the secret value.
