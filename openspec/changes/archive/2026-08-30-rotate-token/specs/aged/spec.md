## ADDED Requirements

### Requirement: Token Rotation

The system SHALL generate a new cryptographically random 32-byte hex token, write it to the `token` field of the located config file, and print the new token to stdout. All other config file keys SHALL be preserved unchanged. If no config file is found at any of the standard lookup paths and `AGED_CONFIG` is not set, the command SHALL exit with a non-zero code.

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
