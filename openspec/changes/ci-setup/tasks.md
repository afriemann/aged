## 1. CI workflow

- [x] 1.1 Create `.github/workflows/ci.yml`: triggers on `push` to `main` and on `pull_request`; a single `test` job with `permissions: contents: read` (no broader scope needed — nothing is written), a `concurrency` group keyed on `${{ github.workflow }}-${{ github.ref }}` with `cancel-in-progress: true`, `actions/checkout` and `actions/setup-go` pinned to their exact commit SHAs (verified via the GitHub API, not guessed) with `go-version-file: go.mod` so the toolchain always matches what `go.mod` declares. Verify by running `actionlint` (or, absent that tool, careful manual review) against the file for YAML/schema errors.
- [x] 1.2 Add build/vet/format/test steps to the job: `go build ./...`, `go vet ./...`, a `gofmt -l .` step that fails the job if it prints any file, and `go test -race ./...`. Verify by pushing the branch and confirming the workflow run succeeds on GitHub Actions (all four steps green).

## 2. Documentation

- [x] 2.1 Add a status badge for the new workflow to `README.md`'s top. Verify the badge URL resolves to the correct workflow file path.
