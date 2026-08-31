# service-hardening Specification

## Purpose

Defines the systemd process-sandboxing requirements for `aged.service`, limiting the blast radius of a post-compromise exploit to the minimum filesystem and network surface needed to run the server.
## Requirements
### Requirement: Service Process Sandboxing

The `aged.service` systemd unit SHALL apply standard process sandboxing directives to limit the
access of the `aged` process to only what it requires. The following directives SHALL be present
and set to the specified values:

| Directive | Value |
|---|---|
| `NoNewPrivileges` | `yes` |
| `PrivateTmp` | `yes` |
| `PrivateDevices` | `yes` |
| `ProtectSystem` | `strict` |
| `ProtectHome` | `yes` |
| `CapabilityBoundingSet` | *(empty — drop all capabilities)* |
| `SystemCallFilter` | `@system-service` |
| `LockPersonality` | `yes` |
| `MemoryDenyWriteExecute` | `yes` |
| `RestrictAddressFamilies` | `AF_INET AF_INET6 AF_UNIX` |

The `ReadWritePaths` directive SHALL be set to allow write access to the identity file path and
the secrets directory path so that `ProtectSystem=strict` does not block legitimate writes.

#### Scenario: Hardened unit exposes fewer kernel interfaces than baseline
GIVEN the updated `aged.service` is installed
WHEN `systemd-analyze security aged.service` is run
THEN the reported exposure score is lower than the un-hardened baseline of 9.6

#### Scenario: Service starts and serves requests after hardening
GIVEN the hardened `aged.service` is installed with correct ReadWritePaths
WHEN the service is started with a valid identity and config
THEN authenticated requests to `/secrets` are handled normally

