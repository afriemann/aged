## 1. Deployment reference file

- [ ] 1.1 Update `aged.service` with the full sandboxing directive set from the spec table: `NoNewPrivileges=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `StateDirectory=aged`, `ConfigurationDirectory=aged`, `ReadWritePaths=/etc/aged`, `CapabilityBoundingSet=`, `SystemCallFilter=@system-service`, `SystemCallErrorNumber=EPERM`, `LockPersonality=yes`, `MemoryDenyWriteExecute=yes`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `ProtectKernelTunables=yes`, `ProtectControlGroups=yes`; verify it is valid systemd unit syntax with `systemd-analyze verify aged.service` if available
- [ ] 1.2 Fix `openspec/specs/service-hardening/spec.md` Purpose line (replace `TBD - created by archiving change security. Update Purpose after archive.` with a real one-sentence purpose)

## 2. Documentation

- [ ] 2.1 Rewrite `README.md` server setup section: replace home-path examples with `/var/lib/aged/identity.age` and `/var/lib/aged/secrets/`; add note that `StateDirectory=aged` creates `/var/lib/aged` automatically; remove the `EnvironmentFile=/etc/aged/env` step (the unit never loaded it); add a migration runbook (stop → move files → `chown -R aged:aged /var/lib/aged` → update config → restart) and a `ProtectHome=yes` warning about home paths

## 3. Verification (manual — no automated tests for systemd unit syntax)

- [ ] 3.1 `systemd-analyze verify aged.service` on homebox after deployment — no errors
- [ ] 3.2 `systemd-analyze security aged.service` on homebox — exposure score below 9.6 baseline
- [ ] 3.3 `aged get <any-secret>` returns the expected value under the sandbox
- [ ] 3.4 `aged rotate-token` succeeds (proves `ReadWritePaths=/etc/aged` works)
