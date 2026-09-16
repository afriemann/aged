## 1. Config schema and env-pair capture (D1)

- [x] 1.1 Add `UserConfig{Name, Token string}` and `Users []UserConfig` to `Config`; add unexported `envToken`/`envUsername` fields captured verbatim from `AGED_TOKEN`/`AGED_USERNAME` in `loadConfig` (no merge logic in `loadConfig` itself — client commands must be completely unaffected). Verify existing config tests still pass unmodified and a new test confirms `cfg.Users` decodes from a `[[users]]` TOML block.

## 2. User validation and merge (D2.1)

- [x] 2.1 Add `validUserName(name string) bool`: matches `^[a-zA-Z0-9._-]+$`, not `.`/`..`, not starting with `-`, length 1–63 bytes. Verify with a table test covering every rule.
- [x] 2.2 Add `validTokenFormat(token string) bool`: exactly 64 characters, all in `[0-9a-f]`. Verify with a table test (empty, too short, too long, uppercase hex, non-hex chars, exactly-right).
- [x] 2.3 Implement `resolveUsers(cfg Config) ([]UserConfig, []problem, error)` (or equivalent): merges `cfg.Users` (file order) with the env-constructed user (appended last, only when both `envToken` and `envUsername` are non-empty), then validates the full set — at least one user, no duplicate token, no duplicate name (case-insensitive), every name/token valid per 2.1/2.2. Each problem is tagged `structural` or `tokenFormat`. Verify with `TestResolveUsers` covering every scenario in the `Multi-User Configuration` requirement: single user via config, multiple users via config, single user via env pair, env pair combined with config users, no users configured, duplicate token, duplicate name, case-insensitive duplicate name, invalid name, malformed token.
- [x] 2.4 Implement the partial-env-pair check as a server-only startup guard (not inside `resolveUsers`/`loadConfig`): `AGED_USERNAME` set without `AGED_TOKEN`, or vice versa, is a startup error naming the missing variable. Verify with `TestCheckServeConfig` (or equivalent) subtests: `AGED_USERNAME without AGED_TOKEN refused`, `AGED_TOKEN without AGED_USERNAME refused`.

## 3. Unmigrated-store scan (D2.2)

- [x] 3.1 Implement a one-level `secrets_dir` scan run before any per-user store is constructed: any non-directory entry (following symlinks via `os.Stat`) is an offender — classify `.age` files with a migration-specific message, anything else with a generic "unexpected entry" message; aggregate all offenders into one error (capped at 20 + "and N more"). A directory not matching any configured user's name is a warning, not a failure. Verify with `TestScanSecretsDir` (or equivalent) subtests: `Loose secret file blocks startup`, `Unexpected non-directory entry blocks startup`, `Unknown subdirectory warns but does not block startup`.

## 4. Startup wiring: eager stores, ordering, checkServeConfig (D2.3, D2.4)

- [x] 4.1 Replace `checkServeConfig`'s `cfg.Token == ""` check with a call into `resolveUsers` (and the partial-env-pair guard from 2.4), returning the first fatal problem. Verify the "Missing token on startup" scenario now reflects "no users configured" and passes with the new check.
- [x] 4.2 In `serve()`, after `checkServeConfig` succeeds: construct one `*Store` per validated user at `filepath.Join(cfg.SecretsDir, user.Name)`, in the order: (a) run the unmigrated-store scan (task 3.1) against `cfg.SecretsDir`, (b) construct each user's `Store` (a name colliding with a regular file, or any `newStore` error, is a startup error naming the user). Verify with `TestServe...`/direct unit tests: `Store construction failure is a startup error`, and that `warnIfIdentityConfigured` still runs (ordering per D2.4 — validation and scan before any directory creation).

## 5. Auth resolution and tenant routing (D3.1, D3.2, D3.3)

- [x] 5.1 Rewrite `bearerMiddleware` to accept `[]tenant{name, store}` instead of a single token: compare the presented token against every tenant using `subtle.ConstantTimeCompare` with no `break`/early `return`, accumulate the match flag and the matched index via `subtle.ConstantTimeSelect` (only a single branch after the loop decides 401 vs. success). Verify with a structural test asserting every configured tenant's token is compared exactly once per request regardless of which one matches (an instrumented comparison counter, not a wall-clock measurement).
- [x] 5.2 Change the middleware's wrapped-handler shape to `func(http.ResponseWriter, *http.Request, *tenant)` (explicit parameter, not `context.Value`) and update all four endpoint closures (`GET /secrets`, `GET/POST/DELETE /secrets/{name...}`) to operate on the resolved tenant's store. Verify `GET /secrets` returns only the authenticated tenant's names ("One user cannot list another user's secrets"), and add the "Second configured user's token authenticates" scenario as a test.
- [x] 5.3 Change the success log line to `auth ok: %s %s from %s as %s` (appending the sanitised matched username); leave the failure line's format untouched. Verify with updated/new tests: `Auth success logged with real client IP` (now asserts the ` as <USER>` suffix) and a fail2ban-filter regression check that the shipped `contrib/fail2ban/filter.d/aged-auth.conf` (matching only `auth failure:`) is unaffected.

## 6. Path containment hardening (D4)

- [x] 6.1 Fix the containment check to the precise form (`rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))`). Verify with `Name containing literal dots is accepted` (e.g. `..foo`).
- [x] 6.2 Add symlink-aware containment: `newStore` resolves and stores a `canonicalDir` via `filepath.EvalSymlinks` at construction; `getValue`/`removeValue` re-verify the symlink-resolved target path is inside `canonicalDir`; `setValue` re-verifies the symlink-resolved *parent* directory instead (the target file may not exist yet). Any resolution error other than `fs.ErrNotExist` is a hard error; `fs.ErrNotExist` on get/delete maps to the existing 404 path. Verify with `Symlink escaping the store root is rejected` (get, set, and delete each tested against a symlink pointing outside the store root).
- [x] 6.3 Normalise `secretsDir` with `filepath.Clean` in `newStore` before storing it, fixing `removeValue`'s cleanup-loop termination for a trailing-slash `secrets_dir`. Verify with `Store root survives cleanup regardless of trailing separator`.

## 7. `rotate-token` redesign (D5)

- [x] 7.1 Implement defensive decoding of the config's `users` value: type-switch over `[]map[string]any` (genuine `[[users]]`) and `[]any` (inline array — convert element-wise), erroring (never panicking) on an unexpected type, a missing/wrong-typed `name`, or a missing/wrong-typed `token`, each naming the offending index. Verify with `Malformed users value produces a clean error` (inline table, scalar, missing key, wrong type — each as a subtest, asserting no panic).
- [x] 7.2 Implement username-based target selection: optional argument, auto-selected and always printed when exactly one user is configured, required (with configured names listed on error) when more than one. Verify with `Username required with multiple users` and `Unknown username lists configured names`.
- [x] 7.3 After generating the new token and setting it on the target entry, validate the complete resulting user set using the same rules as `resolveUsers`/task 2.3, with this exception: a `structural` problem anywhere aborts the write; a `tokenFormat` problem on any entry *other than* the one just rotated is a warning (not an abort); a `tokenFormat` problem on the rotated entry itself (which cannot occur by construction) would be fatal. Verify with `Rotation is blocked by a structural problem on another user` and `Rotation proceeds despite another user's malformed token`.
- [x] 7.4 Confirm the existing atomic-write and ownership-preservation logic (`chownFunc`/`fileOwnerFunc`, temp-file-plus-rename) is reused unchanged for the `[[users]]`-shaped write. Verify `Preserves file ownership across rotation`, `Failed write leaves original config intact`, and `Rotates token in config file` all still pass against a `[[users]]`-shaped config.

## 8. `rotate-identity` scoping (D6)

- [x] 8.1 Add a `--user <name>` flag to `parseRotateIdentityArgs` (alongside the existing `--dry-run`, any order; handle `--user` as the final argument with no value as an error). Verify with a table test extending `TestParseRotateIdentityArgs`.
- [x] 8.2 In `rotateIdentity`: resolve the configured users; if more than one is configured and `--user` is omitted or matches none, refuse and list configured names; if exactly one is configured, default to it (and always print the selected name). Compute `effectiveRoot := filepath.Join(cfg.SecretsDir, username)` and pass it through to `newStore`/`performRotate`/`dryRunRotate` in place of `cfg.SecretsDir` directly. Verify with `Refuses to run without --user when multiple users are configured`, `Defaults to the sole user when exactly one is configured`, and `Operates only on the selected user's subtree` (two users, each with distinct secrets; rotating one leaves the other's secrets and identity requirements untouched).

## 9. CLI wiring and help text

- [x] 9.1 Update `main.go`'s command dispatch: `rotate-token` becomes `rotate-token [<username>]`; `rotate-identity` argument parsing already extended in 8.1. Update the help text to document `[[users]]`, `AGED_USERNAME`, and the new command signatures.

## 10. Documentation

- [x] 10.1 Update `README.md`: `[[users]]` config example (replacing the single flat `token` example for the server), the `AGED_USERNAME` env var, the new `auth ok: … as <user>` log format (and a note that the shipped fail2ban filter is unaffected since it matches only the failure line), the per-tenant-identity recommendation (distinct identity per user, since the name-binding envelope does not bind tenant identity), and the migration sequence from `design.md`'s Migration Plan (stop service → choose a username → move the existing store into a named subdirectory via a staging directory, not a direct `mv` → rewrite config → start → verify with `aged list`).

## 11. Final verification

- [x] 11.1 Run the full test suite (`go test ./...`) and `go vet ./...`; fix any failure.
- [x] 11.2 Confirm every scenario in `specs/aged/spec.md` (this change) has a name-matched test, and that every `tasks.md` checkbox is ticked before archiving.
