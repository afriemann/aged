package main

// spec: openspec/changes/multi-user-support/specs/aged/spec.md

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// userNameRe matches a single valid username segment. Usernames are single
// path segments — unlike secret names (validName), they do NOT support "/"
// namespacing: allowing it would let a username create a nested tenant root
// overlapping another tenant's directory tree.
var userNameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// validUserName reports whether name is a valid tenant/username: 1-63 bytes,
// matching [a-zA-Z0-9._-], not "." or "..", and not starting with "-" (a
// leading dash is a footgun once the name is passed to a shell or to
// `aged rotate-identity --user <name>`).
func validUserName(name string) bool {
	if len(name) == 0 || len(name) > 63 {
		return false
	}
	if name == "." || name == ".." {
		return false
	}
	if strings.HasPrefix(name, "-") {
		return false
	}
	return userNameRe.MatchString(name)
}

// hexTokenRe matches exactly 64 lowercase hexadecimal characters — the exact
// shape produced by rotate.go's hex.EncodeToString(32 random bytes). A fixed
// length closes both an empty-token auth bypass and a length-based timing
// signal in the constant-time comparison (see bearerMiddleware).
var hexTokenRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// validTokenFormat reports whether token is exactly 64 lowercase hex chars.
func validTokenFormat(token string) bool {
	return hexTokenRe.MatchString(token)
}

// userProblemCategory distinguishes structural problems (always fatal to
// every consumer) from token-format problems (fatal to serve, but treated as
// a warning by rotate-token when the problem belongs to a user other than
// the one being rotated — see rotate.go).
type userProblemCategory int

const (
	problemStructural userProblemCategory = iota
	problemTokenFormat
)

// userProblem describes one validation failure found by validateUserSet.
// index identifies the offending user's position in the validated slice for
// a single-user problem (rule 6, tokenFormat); it is -1 for problems that are
// not tied to a single user (no users configured) or that name two users
// directly in the message (duplicate name/token — both are always fatal
// regardless of index, so no consumer needs to recover the indices).
type userProblem struct {
	index    int
	category userProblemCategory
	message  string
}

// validateUserSet applies the full multi-user validation ruleset (see
// Multi-User Configuration in specs/aged/spec.md) to an already-merged user
// slice. It is the single authoritative ruleset shared by two callers with
// different policies: checkServeConfig treats every problem as fatal;
// rotateToken treats a tokenFormat problem on any user other than the one
// just rotated as a warning (see D5.3 in design.md).
func validateUserSet(users []UserConfig) []userProblem {
	var problems []userProblem

	if len(users) == 0 {
		problems = append(problems, userProblem{
			index:    -1,
			category: problemStructural,
			message:  "no users are configured: define at least one [[users]] entry, or set AGED_USERNAME and AGED_TOKEN",
		})
		return problems
	}

	for i, u := range users {
		if !validUserName(u.Name) {
			problems = append(problems, userProblem{
				index:    i,
				category: problemStructural,
				message: fmt.Sprintf(
					"user %q has an invalid name: must match [a-zA-Z0-9._-], must not start with \"-\", must not be \".\" or \"..\", and must be 1-63 bytes",
					u.Name,
				),
			})
		}
		if !validTokenFormat(u.Token) {
			problems = append(problems, userProblem{
				index:    i,
				category: problemTokenFormat,
				message: fmt.Sprintf(
					"user %q has an invalid token: expected 64 hexadecimal characters, got %d — run: aged rotate-token %s",
					u.Name, len(u.Token), u.Name,
				),
			})
		}
	}

	// Rule 7: no two names equal after ASCII lowercasing. Names are already
	// constrained to ASCII by validUserName above, so strings.ToLower is
	// exact and locale-independent here — deliberately not
	// strings.EqualFold, which case-folds full Unicode and would reopen the
	// Turkish-dotless-I class of bugs (CWE-178) on input that has not been
	// constrained first.
	seenNames := map[string]string{}
	for _, u := range users {
		low := strings.ToLower(u.Name)
		if orig, ok := seenNames[low]; ok {
			if orig == u.Name {
				problems = append(problems, userProblem{
					index:    -1,
					category: problemStructural,
					message:  fmt.Sprintf("users %q and %q have the same name", orig, u.Name),
				})
			} else {
				problems = append(problems, userProblem{
					index:    -1,
					category: problemStructural,
					message:  fmt.Sprintf("users %q and %q differ only in case; names must be unique case-insensitively", orig, u.Name),
				})
			}
		} else {
			seenNames[low] = u.Name
		}
	}

	// Rule 8: no two tokens equal, compared byte-exactly. The error never
	// prints the token itself.
	seenTokens := map[string]string{}
	for _, u := range users {
		if orig, ok := seenTokens[u.Token]; ok {
			problems = append(problems, userProblem{
				index:    -1,
				category: problemStructural,
				message:  fmt.Sprintf("users %q and %q have the same token", orig, u.Name),
			})
		} else {
			seenTokens[u.Token] = u.Name
		}
	}

	return problems
}

// resolveUsers merges the configured [[users]] entries with the
// AGED_USERNAME/AGED_TOKEN environment pair (appended last, in that order —
// see design.md D1) and validates the result. It is a server-only concern:
// loadConfig itself performs no such merge, so client commands (which only
// ever read cfg.Token) are completely unaffected by AGED_USERNAME.
//
// A non-nil error return means the environment pair itself is malformed
// (exactly one of AGED_USERNAME/AGED_TOKEN set) — a condition that is
// checked before any merge or validation happens, since it does not depend
// on the configured user set at all. A non-empty problem slice, with a nil
// error, means the merged user set failed one or more Multi-User
// Configuration rules.
func resolveUsers(cfg Config) ([]UserConfig, []userProblem, error) {
	hasToken := cfg.envToken != ""
	hasUsername := cfg.envUsername != ""

	if hasUsername && !hasToken {
		return nil, nil, errors.New(
			"AGED_USERNAME is set but AGED_TOKEN is not; both are required to define a user from the environment",
		)
	}
	if hasToken && !hasUsername {
		return nil, nil, errors.New(
			"AGED_TOKEN is set but AGED_USERNAME is not; set AGED_USERNAME to define a user from the environment, " +
				"or unset AGED_TOKEN if it is only intended for client commands",
		)
	}

	merged := append([]UserConfig{}, cfg.Users...)
	if hasToken && hasUsername {
		merged = append(merged, UserConfig{Name: cfg.envUsername, Token: cfg.envToken})
	}

	return merged, validateUserSet(merged), nil
}
