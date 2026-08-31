## Why

L-03 from the 2026-08-30 security audit: the `aged.service` systemd unit runs with no process sandboxing beyond `User=aged`. A post-compromise exploit has full `aged`-user filesystem and network access. This change adds the standard single-purpose-HTTP-server hardening directives and adopts `/var/lib/aged` as the canonical system deployment path, eliminating the conflict between `ProtectHome=yes` and the current home-directory defaults.

## What Changes

- **`aged.service`** gains the full sandboxing directive set: `NoNewPrivileges`, `PrivateTmp`, `PrivateDevices`, `ProtectSystem=strict`, `ProtectHome=yes`, `StateDirectory=aged` (creates and owns `/var/lib/aged`), `ConfigurationDirectory=aged` (manages `/etc/aged`), `ReadWritePaths=/etc/aged` (permits atomic config rotation under `ProtectSystem=strict`), `CapabilityBoundingSet=` (drop all), `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `SystemCallFilter=@system-service`, `LockPersonality=yes`, `MemoryDenyWriteExecute=yes`, `ProtectKernelTunables=yes`, `ProtectControlGroups=yes`.
- **`README.md`** — server setup section updated to use `/var/lib/aged` for identity and secrets paths. `StateDirectory=aged` creates and owns this directory automatically; operators no longer need to create it manually. A note is added explaining that `ProtectHome=yes` means home-directory paths are blocked under the systemd unit.

## Capabilities

### New Capabilities

_None._

### Modified Capabilities

- `service-hardening`: **Service Process Sandboxing** — adds the `/var/lib/aged` path model and `StateDirectory=aged` as the mechanism; `ReadWritePaths=/etc/aged` for config rotation under `ProtectSystem=strict`.

## Impact

- **`aged.service`** — deployment artifact; operators must re-install it and migrate identity/secrets from any previous home-directory path to `/var/lib/aged/` before restarting the service.
- **`README.md`** — server setup section rewritten for the new paths.
- **`openspec/specs/service-hardening/spec.md`** — committed for the first time (existed as untracked from a prior session).
- **No Go code changes. No new dependencies.**
