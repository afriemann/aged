# aged

[![CI](https://github.com/afriemann/aged/actions/workflows/ci.yml/badge.svg)](https://github.com/afriemann/aged/actions/workflows/ci.yml)

A small age-encrypted secret server. Secrets are stored as age-encrypted files on disk; a lightweight HTTP API exposes them to any machine on your network. Designed to be used as a [chezmoi](https://chezmoi.io) secret backend.

## Install

```sh
make install          # installs to /usr/local/bin/aged
# or
make install PREFIX=~/.local
```

## Server setup (on homebox)

The service unit uses `StateDirectory=aged` — systemd creates and owns `/var/lib/aged` automatically on first start. Do **not** use home-directory paths for secrets; the hardened unit sets `ProtectHome=yes` which makes `/home`, `/root`, and `/run/user` inaccessible to the process.

**The server never holds an age identity.** All encryption and decryption happen on the client — the server stores and returns opaque ciphertext only, and cannot decrypt any secret even with full filesystem access. There is no `aged init` step on the server.

**1. Install the unit and let systemd create the directories:**

```sh
sudo cp aged.service /etc/systemd/system/aged.service
sudo systemctl daemon-reload
sudo systemctl start aged   # creates /var/lib/aged and /etc/aged; will fail (no users configured yet — expected)
sudo systemctl stop aged
```

**2. Create `/etc/aged/config.toml`** (mode 0600):

```sh
sudo tee /etc/aged/config.toml <<'EOF'
secrets_dir = "/var/lib/aged/secrets"
addr        = "127.0.0.1:8743"

[[users]]
name  = "laptop"
token = "<generate with: openssl rand -hex 32>"
EOF
sudo chmod 600 /etc/aged/config.toml
sudo chown aged:aged /etc/aged/config.toml
```

See [Multi-user server configuration](#multi-user-server-configuration) to add more than one user.

**3. Start and enable the service:**

```sh
sudo systemctl enable --now aged
```

**4. Verify confinement (optional but recommended):**

```sh
systemd-analyze security aged.service
```

**5. Put it behind your reverse proxy** (Caddy example):

```
secrets.home.example.com {
    reverse_proxy 127.0.0.1:8743 {
        header_up X-Real-IP {remote_host}
    }
}
```

## Configuration

aged can be configured via a TOML config file, environment variables, or both. Environment variables always take precedence over the config file.

**Config file lookup order** (first found wins):
1. `$AGED_CONFIG` — custom path
2. `/etc/aged/config.toml` — system-wide
3. `~/.config/aged/config.toml` — user

> **Note for a combined server+client host:** `configFilePath()` checks `/etc/aged/config.toml` *before* `~/.config/aged/config.toml`. If you run client commands (`get`/`set`/`pubkey`) on the same machine that runs `aged serve`, make sure your shell user doesn't pick up the server's config file — a client's `identity` must never point at the server's old (pre-migration) identity path. Run client commands with `$AGED_CONFIG` pointed explicitly at your own `~/.config/aged/config.toml` if there's any ambiguity.

### Multi-user server configuration

**`aged serve` supports multiple independent users**, each identified by its own bearer token and isolated to its own storage subtree (`secrets_dir/<name>/`) — one user's token can never read, write, delete, or list another user's secrets. Define server users via a `[[users]]` array in the config file, the `AGED_USERNAME`/`AGED_TOKEN` environment pair, or both combined (the environment-defined user, when present, is appended after every config-file user).

> **`token`/`AGED_TOKEN` alone is no longer a server credential.** This is a breaking change from earlier versions: `aged serve` used to treat a bare `token` value as the one implicit tenant. It now requires at least one entry in `[[users]]`, or the `AGED_USERNAME`+`AGED_TOKEN` pair. `token`/`AGED_TOKEN` continues to mean exactly what it always has for **client** commands (`get`/`set`/`list`/`delete`) — your own credential, read from the same config key/env var as before.

**Example `/etc/aged/config.toml`** (server — no `identity` key; the server never holds one):

```toml
secrets_dir = "/var/lib/aged/secrets"
addr        = "127.0.0.1:8743"

[[users]]
name  = "laptop"
token = "<generate with: openssl rand -hex 32>"

[[users]]
name  = "ci-runner"
token = "<generate with: openssl rand -hex 32>"
```

Each user's `name` is also how you address them in `aged rotate-token <name>` — **recommend encoding the machine or purpose in the name itself** (`laptop`, `ci-runner`), since `rotate-token` does not preserve config-file comments across a rotation, but the name always survives and appears in the `auth ok: … as <user>` log line.

A single-user deployment with no config file at all can instead set both `AGED_USERNAME` and `AGED_TOKEN` — this is the simplest way to run one tenant without a config file:

```sh
AGED_USERNAME=laptop AGED_TOKEN="$(openssl rand -hex 32)" aged serve
```

Setting only one of the two is refused at startup (naming which one is missing) — this is deliberate: `AGED_TOKEN` alone is the exact shape of a pre-upgrade single-user deployment, and starting anyway would leave the operator's credential silently inert.

**Startup validation.** The server refuses to start, naming the specific problem, if: no users are configured; any user's name is empty, exceeds 63 bytes, starts with `-`, is `.`/`..`, or contains a character outside `[a-zA-Z0-9._-]` (usernames are a single path segment — unlike secret names, they do not support `/`); any user's token is not exactly 64 lowercase hexadecimal characters (the exact shape `rotate-token` produces); or any two users share a token, or share a name after case-folding.

**Recommend a distinct age identity per tenant.** The name-binding envelope binds a secret to its *name*, not to its owner — a secret misfiled into the wrong tenant's directory under the same name is only caught if that tenant holds a *different* identity than the correct owner (decryption then simply fails). Two tenants sharing one identity lose this incidental safety net entirely.

**Migrating an existing single-tenant deployment to `[[users]]`:**

1. **Stop the service:** `sudo systemctl stop aged`.
2. **Choose a username** for the existing store, e.g. `laptop`.
3. **Move the existing store into a named subdirectory.** `secrets_dir` may already contain legitimate namespace subdirectories (`ha/`, `infra/`) alongside top-level `.age` files, so use a sibling staging directory rather than a single `mv`:
   ```sh
   sudo mkdir -m 700 /var/lib/aged/laptop.staging
   sudo mv /var/lib/aged/secrets/* /var/lib/aged/laptop.staging/
   sudo mv /var/lib/aged/laptop.staging /var/lib/aged/secrets/laptop
   sudo chown -R aged:aged /var/lib/aged/secrets/laptop
   ```
4. **Rewrite the config** to a `[[users]]` block (or the `AGED_USERNAME`/`AGED_TOKEN` pair), keeping the existing token value so you don't have to re-provision clients.
5. **Start the service:** `sudo systemctl start aged`. If step 3 was incomplete, startup fails loudly and names every file still to be moved — no traffic is served in a broken state.
6. **Verify** with `aged list` from a client: it must return exactly that user's secret names.
7. **Add further users** by appending `[[users]]` entries and restarting — adding or removing a user requires a full service restart today (a brief all-tenant blip; hot-reload is not supported).

**Environment variable overrides:**

| Variable | Config key | Default | Used by |
|---|---|---|---|
| `AGED_TOKEN` | `token` | — | client credential; combines with `AGED_USERNAME` to define one server user |
| `AGED_USERNAME` | — | — | server-only; combines with `AGED_TOKEN` to define one server user |
| `AGED_SECRETS_DIR` | `secrets_dir` | `~/.config/aged/secrets/` | server |
| `AGED_ADDR` | `addr` | `127.0.0.1:8743` | server |
| `AGED_IDENTITY` | `identity` | `~/.config/aged/identity.age` | **client only** — `get`/`set`/`pubkey`/`trust` |
| `AGED_SERVER_URL` | `server_url` | `http://localhost:8743` | client |

If `identity`/`AGED_IDENTITY` is still set for `aged serve`, the server logs a startup warning naming the file — it's unused and should be secured or removed once you have verified client-side encryption works.

## Client usage

Create `~/.config/aged/config.toml` (mode 0600):

```toml
token      = "your-bearer-token"
server_url = "https://aged.automate.wtf"
```

```sh
chmod 600 ~/.config/aged/config.toml
```

Environment variables (`AGED_TOKEN`, `AGED_SERVER_URL`, `AGED_IDENTITY`) still override the config file when set.

**Generate your own identity — once, on each machine you'll run `get`/`set` from:**

```sh
aged init
# public key:  age1xxxx...
# identity:    ~/.config/aged/identity.age
```

This identity never leaves your machine. All encryption and decryption happen locally — the server only ever stores and returns ciphertext.

```sh
# Store a secret (encrypted locally before upload)
echo -n "my-token-value" | aged set ha-token

# Retrieve it (downloaded ciphertext is decrypted locally)
aged get ha-token

# List all secrets
aged list

# Delete
aged delete ha-token

# Show your own public key (reads your local identity file — no network call)
aged pubkey

# Rotate the bearer token (run on server, then restart + update client configs)
# specify <username> if more than one [[users]] entry is configured
aged rotate-token [<username>]
```

## Multiple devices (`aged trust`)

Each device has its own identity (`aged init`) and shares the user's bearer token. Secrets are encrypted to a set of trusted keys, kept in a **trust manifest** stored on the server as an age-encrypted blob (reserved name `.aged/trust`, encrypted to the default set, so the server cannot read it).

```sh
# on device A: grant device B's key access to everything
aged trust add age1…B

# grant a key access to one secret only
aged trust add age1…C --secret ha-token

# revoke
aged trust remove age1…B
aged trust remove age1…C --secret ha-token

aged trust list [--secret ha-token]   # show the default set and per-secret changes
aged trust sync                       # re-encrypt every secret to the manifest (repairs a partial run)
```

- The recipients of a secret are the default set, plus its per-secret `add` keys, minus its per-secret `remove` keys. A per-secret change keeps following later changes to the default set. `aged set` uses this set (and always includes your own key).
- Trust commands run against the live server. They re-encrypt only affected secrets, write the manifest last, and are safe to rerun; `--dry-run` previews. Secrets your device cannot decrypt are skipped and reported, and the manifest is not advanced unless you pass `--allow-skipped`.
- `trust remove` stops future access but **cannot take back ciphertext the removed key already copied**; rotate the secret values if that matters. It rotates the manifest's signing key (the removed device may have seen the old one) and then runs a full `sync`, so every secret ends up on the new set even if another device wrote one meanwhile. Removing your own or the last key needs `--force`, and then the sync is left to another trusted device. Every other device confirms the new signing key once (interactively, or `AGED_TRUST_REPIN=1`; `AGED_TRUST_YES=1` deliberately does not cover it; do not export `AGED_TRUST_REPIN` permanently, it disables this check).
- **Trusting a new device:** run `aged init` there, `aged trust add <its pubkey>` from a trusted device, then use it. A device not in the default set can read secrets re-encrypted to it but cannot run `trust` or `set` until it is added.
- **First use per server:** each device shows the default recipients and the manifest's signing-key fingerprint and asks once for confirmation (`--yes` or `AGED_TRUST_YES=1` to skip). The signing key is then pinned in `trust-pins.json` beside the identity file, and a manifest with a different key or a lower counter is rejected, so the server or a token holder cannot silently add a recipient. Verify the fingerprint against one you trust (e.g. shown on an existing device).
- Limitations: a malicious server can still replace a secret with an older blob stored under the same name; every default-set holder can see the per-secret changes; there is no per-device token.
- To replace a key: `aged trust add <new>` then `aged trust remove <old>`. Back up every identity file with at least the care you give the bearer token; losing all trusted identities means losing every secret.

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
auth ok: GET /secrets/ha-token from 198.51.100.42 as laptop
```

The **failure** line's format is a stable contract — the `contrib/fail2ban/` configs match only this line and are unaffected by the change below.

> **Breaking change (multi-user support):** the **success** line now ends with `as <user>`, naming which configured user's token matched. This is a machine-readable format change for anyone parsing `auth ok:` lines directly (not the shipped fail2ban filter, which only matches `auth failure:`).

> **Note on success logging:** `auth ok:` lines record which secret was fetched, from which IP, and as which user. Anyone with journal read access (`journalctl`) can see this access pattern. If secret *names* or *usernames* are sensitive in your environment, be aware of this trade-off; journal access is already a privileged operation.

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
