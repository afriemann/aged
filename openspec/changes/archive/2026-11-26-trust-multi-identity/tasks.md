## 1. Server

- [x] 1.1 Reserved `.aged` name rejection on all `/secrets` routes (Reserved name rejected on every secrets route)
- [x] 1.2 `GET/PUT /trust` with ETag, create-only and If-Match, per-store mutex (Trust Server Endpoints scenarios)
- [x] 1.3 `X-Aged-Trust` precondition and optional secret `If-Match` on `POST /secrets/{name}`

## 2. Client trust core

- [x] 2.1 `trust.go`: manifest body, Ed25519 signing, envelope-wrapped encryption, effective-set logic (Trust Manifest scenarios)
- [x] 2.2 Pin store, first-use confirmation, counter rollback and not-trusted-device errors (Trust Manifest Authenticity scenarios)
- [x] 2.3 `set` encrypts to effective recipients and sends `X-Aged-Trust` with retry on 412 (Set encrypts to every effective recipient)
- [x] 2.4 Client-side reserved-name rejection for get/set/delete

## 3. Trust commands

- [x] 3.1 `trust list`
- [x] 3.2 `trust add` and bootstrap with create-only write, `--dry-run`
- [x] 3.3 `trust remove` with last/local-key guard, `--force`, warning
- [x] 3.4 `trust sync`, skipped-secret handling, `--allow-skipped`, CAS retry (Concurrent manifest change is retried)
- [x] 3.5 Wire `trust` in `main.go` and usage text

## 4. Removal and docs

- [x] 4.1 Delete `rotate_identity.go`, its tests, `main.go` case and usage, stale references
- [x] 4.2 README: multi-device and trust commands; remove rotate-identity and migration runbook sections
