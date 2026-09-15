# aged

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
sudo systemctl start aged   # creates /var/lib/aged and /etc/aged; will fail (no token yet — expected)
sudo systemctl stop aged
```

**2. Create `/etc/aged/config.toml`** (mode 0600):

```sh
sudo tee /etc/aged/config.toml <<'EOF'
token       = "<generate with: openssl rand -hex 32>"
secrets_dir = "/var/lib/aged/secrets"
addr        = "127.0.0.1:8743"
EOF
sudo chmod 600 /etc/aged/config.toml
sudo chown aged:aged /etc/aged/config.toml
```

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

**Migrating an existing (pre-client-side-encryption) deployment:** if you're upgrading a server that previously held its own identity, see [Migrating to client-side encryption](#migrating-to-client-side-encryption) before installing the new binary — you need to re-encrypt your existing secrets onto a new, client-held identity first.

## Configuration

aged can be configured via a TOML config file, environment variables, or both. Environment variables always take precedence over the config file.

**Config file lookup order** (first found wins):
1. `$AGED_CONFIG` — custom path
2. `/etc/aged/config.toml` — system-wide
3. `~/.config/aged/config.toml` — user

> **Note for a combined server+client host:** `configFilePath()` checks `/etc/aged/config.toml` *before* `~/.config/aged/config.toml`. If you run client commands (`get`/`set`/`pubkey`) on the same machine that runs `aged serve`, make sure your shell user doesn't pick up the server's config file — a client's `identity` must never point at the server's old (pre-migration) identity path. Run client commands with `$AGED_CONFIG` pointed explicitly at your own `~/.config/aged/config.toml` if there's any ambiguity.

**Example `/etc/aged/config.toml`** (server — no `identity` key; the server never holds one):

```toml
token       = "your-bearer-token"
secrets_dir = "/var/lib/aged/secrets"
addr        = "127.0.0.1:8743"
```

**Environment variable overrides:**

| Variable | Config key | Default | Used by |
|---|---|---|---|
| `AGED_TOKEN` | `token` | — (**required**) | server + client |
| `AGED_SECRETS_DIR` | `secrets_dir` | `~/.config/aged/secrets/` | server |
| `AGED_ADDR` | `addr` | `127.0.0.1:8743` | server |
| `AGED_IDENTITY` | `identity` | `~/.config/aged/identity.age` | **client only** — `get`/`set`/`pubkey`/`rotate-identity` |
| `AGED_SERVER_URL` | `server_url` | `http://localhost:8743` | client |

If `identity`/`AGED_IDENTITY` is still set for `aged serve`, the server logs a startup warning naming the file — it's unused and should be secured or removed once you've verified migration (see below).

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
aged rotate-token
```

**Using aged from more than one machine:** copy your `identity.age` file to every machine you run `get`/`set` from, protected with at least the rigour you'd apply to the bearer token — see [Migrating to client-side encryption](#migrating-to-client-side-encryption) for concrete guidance, since the identity file is now more sensitive than the token.

## Migrating to client-side encryption

If you're upgrading an existing aged deployment whose server previously held its own identity, follow this runbook **before** switching to the new binary in production.

**The new identity must be generated on, and never leave, an actual client machine** — not the server. `aged rotate-identity` needs the new identity's *private* key present wherever it runs (it decrypts its own freshly re-encrypted output to verify before swapping anything), so **run the migration itself on that same client machine**, not on the server — otherwise the server ends up holding the very private key this change exists to keep it from ever seeing, even if only transiently.

1. **Deploy the new binary** to the server host and to every client machine — this is a breaking wire-format change; do not run mismatched versions against each other.
2. **Stop `aged serve`.**
3. **On the client machine you intend to use going forward, generate its identity:** `aged init`. This key is born here and stays here — it is never copied to or generated on the server, including during the steps below.
4. **Temporarily copy the server's current ciphertext store and its old identity file to that same client machine**, over an already-authenticated channel (e.g. `scp` over an existing SSH session to a known-host-verified server), into a scratch location distinct from the client's own `secrets_dir`/`identity` — e.g. `~/aged-migration-scratch/{secrets,old-identity.age}`. The server's originals are left in place untouched at this point.
5. **Dry run, on the client, against the scratch copy:**
   ```sh
   AGED_IDENTITY=~/aged-migration-scratch/old-identity.age \
   AGED_SECRETS_DIR=~/aged-migration-scratch/secrets \
     aged rotate-identity ~/.config/aged/identity.age --dry-run
   ```
   Confirm the reported count matches the number of secrets you expect, with zero failures. (`~/.config/aged/identity.age` here is the identity you just generated in step 3 — the target of the migration, not something copied from the server.)
6. **Run it for real** (same command, without `--dry-run`). This stages every secret, verifies each one individually against the client's own new identity, then swaps the *scratch copy* atomically — the client's new private key never leaves this machine at any point in this process.
7. **On the server, make room for the migrated store**: rename the live `secrets_dir` aside as your own backup (e.g. `mv /path/to/secrets /path/to/secrets.old-<timestamp>`) — this is the server-side equivalent of the atomic-swap backup `rotate-identity` would have made if it had run in place, and gives you the same rollback safety net.
8. **Copy the migrated scratch secrets directory back to the server**, into the now-empty `secrets_dir` path, preserving ownership/permissions (`0700` dirs, `0600` files, owned by whatever user runs `aged serve`).
9. **Securely delete the transient scratch copy from the client** — the copied-down old identity and pre-migration ciphertext have served their purpose and should not linger.
10. **Start `aged serve`.** Confirm the stale-identity warning fires only if you still have `identity`/`AGED_IDENTITY` configured for the server — remove that setting either way, since it's unused now.
11. **Destroy the old server-held identity file — unconditionally, even if you never explicitly configured `identity`.** If you always relied on the default path (`~/.config/aged/identity.age` on the server host), that file is the old private key and the stale-identity warning will *not* fire for it (by design — see Configuration above). Move it, rename it, or delete it, and confirm it's gone.
12. **Distribute the client's new identity file to every *other* client machine** that runs `get`/`set` (it already lives on the one that generated it in step 3). This file is now strictly more sensitive than the bearer token — its compromise is total and irreversible short of running `rotate-identity` again:
    - transfer over an already-authenticated, confidentiality-and-integrity-protected channel (e.g. an existing SSH session to a known-host-verified machine) — not a channel whose only property is "the same one used for the token";
    - verify file mode `0600` and correct ownership *on arrival* at each destination;
    - never use a channel that leaves a durable unencrypted copy — chat tools, tickets, email, shared drives, or pasted terminal scrollback are all unsuitable;
    - back up the identity file with at least the rigour you apply to the `rotate-token` runbook — losing it means losing every secret.
13. **Verify** a real `aged get` works from a real client machine using the new identity, against the live server.
14. **Only then** delete the server-side `secrets.old-<timestamp>/` backup from step 7 and securely destroy the old identity file if you haven't already.

**Rollback** (only possible before step 14, and only if you kept the step-7 backup): stop the service, move `secrets.old-<timestamp>` back into place as `secrets_dir`, restore the previous binary and the old `identity` config setting, restart.

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
