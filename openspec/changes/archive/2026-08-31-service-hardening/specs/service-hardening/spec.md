## MODIFIED Requirements

### Requirement: Service Process Sandboxing

The `aged.service` systemd unit SHALL apply standard process sandboxing directives to limit the access of the `aged` process to only what it requires. The following directives SHALL be present and set to the specified values:

| Directive | Value |
|---|---|
| `NoNewPrivileges` | `yes` |
| `PrivateTmp` | `yes` |
| `PrivateDevices` | `yes` |
| `ProtectSystem` | `strict` |
| `ProtectHome` | `yes` |
| `StateDirectory` | `aged` |
| `ConfigurationDirectory` | `aged` |
| `CapabilityBoundingSet` | *(empty — drop all capabilities)* |
| `SystemCallFilter` | `@system-service` |
| `SystemCallErrorNumber` | `EPERM` |
| `LockPersonality` | `yes` |
| `MemoryDenyWriteExecute` | `yes` |
| `RestrictAddressFamilies` | `AF_INET AF_INET6 AF_UNIX` |
| `ProtectKernelTunables` | `yes` |
| `ProtectControlGroups` | `yes` |

`StateDirectory=aged` directs systemd to create and own `/var/lib/aged` (`0700`, `aged:aged`) on service start, and adds it to the unit's read-write set automatically. This is the canonical path for the identity key and secrets store under the hardened unit. The `/var/lib/aged` path SHALL be used in `/etc/aged/config.toml` for `identity` and `secrets_dir`; home-directory paths SHALL NOT be used (they are inaccessible under `ProtectHome=yes`).

`ConfigurationDirectory=aged` directs systemd to create and own `/etc/aged` on service start. No `ReadWritePaths` entry is needed for `/etc/aged`: the `aged serve` process only reads `/etc/aged/config.toml` at startup and never writes to it. The `aged rotate-token` command that writes the config runs as an operator CLI process entirely outside this sandbox and relies on standard DAC permissions (`0600 aged:aged`) on the file.

`AF_UNIX` is required because journald logging and NSS/resolver lookups by the Go runtime use Unix-domain sockets at runtime. Omitting it would break log output under the sandbox.

#### Scenario: Hardened unit exposes fewer kernel interfaces than baseline

GIVEN the updated `aged.service` is installed
WHEN `systemd-analyze security aged.service` is run
THEN the reported exposure score is lower than the un-hardened baseline of 9.6

#### Scenario: Service starts and serves requests after hardening

GIVEN the hardened `aged.service` is installed
AND `/etc/aged/config.toml` references `/var/lib/aged/identity.age` and `/var/lib/aged/secrets/`
WHEN the service is started with valid files at those paths
THEN authenticated requests to `/secrets` are handled normally

#### Scenario: Token rotation succeeds as operator CLI outside sandbox

GIVEN the hardened unit is running
WHEN an operator runs `aged rotate-token` in a shell session
THEN the config file token is updated atomically via DAC permissions
AND the running service is unaffected until restarted
