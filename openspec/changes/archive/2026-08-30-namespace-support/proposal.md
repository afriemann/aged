# Proposal: Namespace support

## Problem

Secret names are currently restricted to `[a-zA-Z0-9._-]+` — no slashes. This means all secrets live in a flat store. There is no way to group related secrets (e.g. `ha/token`, `ha/client-id`, `grafana/api-key`).

## Proposed Solution

Allow `/` as a namespace separator in secret names. Each segment must still match `[a-zA-Z0-9._-]+`; segments may not be empty or be `..`. Names like `ha/token`, `infra/db/password` become valid. Secrets are stored as subdirectory trees under `AGED_SECRETS_DIR` (e.g. `ha/token.age`). `aged list` returns names with their full namespace path.

No changes to the wire format, auth, or config file.

## Scope

In scope:
- nameRe updated to `^[a-zA-Z0-9._-]+(/[a-zA-Z0-9._-]+)*$`
- Explicit rejection of `..` segments (defence in depth)
- HTTP routes changed from `{name}` to `{name...}`
- Store creates subdirectories on set, walks recursively on list
- Store.removeValue cleans up empty parent directories after delete
- Path-safety check in store: resolved path must be within secretsDir

Out of scope:
- Namespace-scoped listing (`aged list ha/`)
- Access control per namespace
