# Tasks: namespace-support

- [x] Write failing tests (red step) for namespace scenarios
- [x] Update nameRe to allow `/`-separated segments
- [x] Add `..` segment check to name validation helper
- [x] Change HTTP routes from `{name}` to `{name...}`
- [x] Add `secretPath()` helper with path-safety check
- [x] Update `setValue` to MkdirAll parent directory
- [x] Update `listNames` to WalkDir recursively
- [x] Update `removeValue` to clean up empty parent dirs
