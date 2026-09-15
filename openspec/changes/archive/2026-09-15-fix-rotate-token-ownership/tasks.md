## 1. Preserve ownership on rotation

- [x] 1.1 Add a `fileOwner(info os.FileInfo) (uid, gid int, ok bool)` helper that extracts the owning UID/GID from a `os.FileInfo` via `syscall.Stat_t`. Verify with a unit test asserting it returns the current process's UID/GID for a freshly created file.
- [x] 1.2 Add a package-level `chownFunc = os.Chown` seam (mirroring the existing `rotateIdentityCorruptStagedFileHook` test-injection pattern) so ownership preservation is directly testable without requiring root privileges.
- [x] 1.3 In `rotateToken`, before renaming the staged temp file into place: stat the original config file, extract its owner via `fileOwner`, and apply it to the temp file via `chownFunc`. On failure, return an error before the rename (the existing atomic-write cleanup already removes the temp file and leaves the original untouched). Verify with `TestRotateToken` subtest `Preserves file ownership across rotation`: inject a `chownFunc` spy, assert it is called with the original file's UID/GID before any rename occurs.
- [x] 1.4 Confirm the four pre-existing `Token Rotation` scenarios still pass unmodified (`Rotates token in config file`, `No config file returns an error`, `New token is cryptographically random`, `Failed write leaves original config intact`).

## 2. Final verification

- [x] 2.1 Run the full test suite (`go test ./...`) and `go vet ./...`; fix any failure.
- [x] 2.2 Confirm every scenario in `specs/aged/spec.md` (this change) has a name-matched test.
