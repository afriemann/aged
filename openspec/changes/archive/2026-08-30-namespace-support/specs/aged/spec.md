## ADDED Requirements

### Requirement: Namespaced Secret Names

Secret names SHALL support `/` as a namespace separator. Each segment between `/` characters SHALL match `[a-zA-Z0-9._-]+`. Names with empty segments, leading or trailing slashes, or any segment equal to `..` SHALL be rejected with HTTP 400. The store SHALL persist namespaced secrets as a subdirectory tree (e.g. `ha/token` → `ha/token.age` under the secrets directory). The resolved file path SHALL be verified to lie within the secrets directory before any file operation.

#### Scenario: Namespaced secret round-trip
GIVEN a name containing a `/` separator such as `ha/token`
WHEN the value is stored then retrieved
THEN the retrieved value equals the stored value

#### Scenario: Deeply nested namespace
GIVEN a name with multiple `/` separators such as `infra/db/password`
WHEN the value is stored then retrieved
THEN the retrieved value equals the stored value

#### Scenario: List returns namespaced names
GIVEN secrets `ha/token` and `ha/client-id` and `grafana/key` have been stored
WHEN secrets are listed
THEN all three namespaced names are returned

#### Scenario: Invalid name with double slash rejected
GIVEN a name containing `//` (empty segment)
WHEN the name is used in a request
THEN the server returns HTTP 400

#### Scenario: Invalid name with `..` segment rejected
GIVEN a name containing a `..` segment such as `foo/../bar`
WHEN the name is used in a request
THEN the server returns HTTP 400

#### Scenario: Delete removes empty namespace directories
GIVEN only one secret exists under a namespace (e.g. `ns/only`)
WHEN the secret is deleted
THEN the namespace directory is also removed
