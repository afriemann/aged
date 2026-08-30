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

# Rotate the bearer token (run on server, then restart + update client configs)
aged rotate-token
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

## fail2ban integration

aged logs one line to stderr (→ journald) for every authentication attempt:

```
auth failure: GET /secrets/ha-token from 198.51.100.42
auth ok: GET /secrets/ha-token from 198.51.100.42
```

The log format is a stable contract — the `contrib/fail2ban/` configs depend on it.

> **Note on success logging:** `auth ok:` lines record which secret was fetched and from which IP. Anyone with journal read access (`journalctl`) can see this access pattern. If secret *names* are sensitive in your environment, be aware of this trade-off; journal access is already a privileged operation.

### 1. Configure Caddy to forward the real client IP

Without this, aged sees every request coming from `127.0.0.1` (Caddy's loopback connection) and fail2ban cannot identify the attacker. Add `header_up` inside your `reverse_proxy` block:

```
secrets.home.example.com {
    reverse_proxy 127.0.0.1:8743 {
        header_up X-Real-IP {remote_host}
    }
}
```

Reload Caddy after making this change.

### 2. Install the fail2ban filter and jail

```sh
sudo cp contrib/fail2ban/filter.d/aged-auth.conf /etc/fail2ban/filter.d/
sudo cp contrib/fail2ban/jail.d/aged.conf        /etc/fail2ban/jail.d/
sudo systemctl reload fail2ban
```

The jail uses `backend = systemd` — it reads directly from the journal, so no log file path is needed. Default settings: ban after 5 failures in 60 seconds for 10 minutes. Adjust `maxretry`, `findtime`, and `bantime` in `/etc/fail2ban/jail.d/aged.conf` to suit your environment.

Test that the filter matches correctly before a real attack:

```sh
fail2ban-regex --usedns=no \
  "auth failure: GET /secrets/ha-token from 198.51.100.42" \
  /etc/fail2ban/filter.d/aged-auth.conf
```

### 3. (Optional) Tune journald rate-limiting

Under a heavy brute-force attack journald may rate-limit aged's log output, causing fail2ban to under-count failures and delay banning. To raise the limit, add to `/etc/systemd/journald.conf`:

```ini
[Journal]
RateLimitBurst=1000
RateLimitIntervalSec=10s
```

Then restart journald: `sudo systemctl restart systemd-journald`.
