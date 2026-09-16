## 1. Revert incorrect toolchain-pin attempt and restore working config

- [x] 1.1 Remove `go-version-input: ''` and `go-version-file: go.mod` from the `govulncheck` step in `.github/workflows/ci.yml`, restoring the action's default Go-version resolution, and add an explanatory comment; verify the YAML is well-formed (dry parse)
- [x] 1.2 Verify via this PR's own CI run that the `govulncheck` step passes (matches the behaviour already proven in the merged `bump-toolchain-and-age-dependency` CI run) — confirmed: run 35150192085 resolved `go1.27.1` cleanly (no version-conflict warning) and reported "No vulnerabilities found."
