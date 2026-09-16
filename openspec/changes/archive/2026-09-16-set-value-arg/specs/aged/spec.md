## ADDED Requirements

### Requirement: Client Secret Set Command

The `aged set <name> [value]` CLI command SHALL accept a secret value either as an explicit third argument or via stdin when the argument is omitted. The command SHALL reject the invocation when a value argument is given while stdin also has piped data available. The command SHALL reject an empty-string value, whether supplied as an explicit argument or as trimmed stdin content. The command SHALL reject an invocation with more than one positional argument after `<name>` with a usage message.

#### Scenario: Value supplied as argument
- **WHEN** `aged set foobar 12345` is run with stdin attached to a terminal (not piped)
- **THEN** the value `12345` is stored for `foobar` without reading stdin

#### Scenario: Value supplied via stdin when argument omitted
- **WHEN** `aged set foobar` is run with `12345` piped to stdin
- **THEN** the value `12345` is stored for `foobar`

#### Scenario: Value argument and piped stdin both present
- **WHEN** `aged set foobar 12345` is run while `67890` is also piped to stdin
- **THEN** the command errors out and stores nothing

#### Scenario: Empty value argument rejected
- **WHEN** `aged set foobar ""` is run
- **THEN** the command errors out and stores nothing

#### Scenario: Empty stdin value rejected
- **WHEN** `aged set foobar` is run with only a newline piped to stdin
- **THEN** the command errors out and stores nothing

#### Scenario: Too many arguments rejected
- **WHEN** `aged set foobar 12345 extra` is run
- **THEN** the command errors out with a usage message and stores nothing
