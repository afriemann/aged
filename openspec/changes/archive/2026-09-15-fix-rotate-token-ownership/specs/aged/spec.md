## MODIFIED Requirements

### Requirement: Token Rotation

The system SHALL generate a new cryptographically random 32-byte hex token, write it to the `token` field of the located config file, and print the new token to stdout. All other config file keys SHALL be preserved unchanged. If no config file is found at any of the standard lookup paths and `AGED_CONFIG` is not set, the command SHALL exit with a non-zero code.

The update SHALL be written atomically: the new content SHALL be staged to a temporary file in the same directory as the config file, the temporary file SHALL be set to mode 0600, and then it SHALL be renamed to replace the original. If any step between staging and rename fails, the temporary file SHALL be removed and the original config file SHALL remain unchanged.

The rewritten config file SHALL retain the same owning user and group as the original file, regardless of which user invokes `aged rotate-token`. If the original owner cannot be applied to the staged file, the command SHALL fail before renaming into place, leaving the original config file unchanged.

#### Scenario: Rotates token in config file

GIVEN a config file exists at a standard path containing a token
WHEN `aged rotate-token` is run
THEN the config file's token field is replaced with a new value
AND the old and new tokens differ
AND the new token is printed to stdout
AND all other config file fields are unchanged

#### Scenario: No config file returns an error

GIVEN no config file exists at any lookup path
AND `AGED_CONFIG` is not set
WHEN `aged rotate-token` is run
THEN the command exits with a non-zero code

#### Scenario: New token is cryptographically random

GIVEN a config file exists
WHEN `aged rotate-token` is run twice in succession
THEN the two generated tokens differ

#### Scenario: Failed write leaves original config intact

GIVEN a config file exists
AND an error occurs while writing the staged temporary file
WHEN `aged rotate-token` is run
THEN the original config file is unchanged
AND no stray temporary file remains in the config file's directory

#### Scenario: Preserves file ownership across rotation

GIVEN a config file exists, owned by a specific user and group
WHEN `aged rotate-token` is run
THEN the rewritten config file retains the same owning user and group as the original
AND this holds regardless of which user account invoked the command
