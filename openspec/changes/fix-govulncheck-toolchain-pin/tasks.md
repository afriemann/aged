## 1. Fix govulncheck Go-version resolution

- [x] 1.1 Add `go-version-input: ''` to the `govulncheck` step's `with:` block in `.github/workflows/ci.yml` and verify the YAML is well-formed (dry parse)
- [ ] 1.2 Verify locally (or via the next CI run) that the step no longer emits the "Both go-version and go-version-file inputs are specified" warning and resolves the version from `go.mod` (`go1.25.14`) instead of `stable`
