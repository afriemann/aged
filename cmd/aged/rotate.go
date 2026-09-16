package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/BurntSushi/toml"
)

// chownFunc applies an owning UID/GID to a file. Defaults to os.Chown; tests
// inject a spy here to observe the ownership-preservation call without
// requiring root privileges to construct a foreign-owned fixture file.
var chownFunc = os.Chown

// fileOwner extracts the owning UID/GID from a file's os.FileInfo. Returns
// ok=false if the platform's Sys() doesn't expose *syscall.Stat_t (not
// expected on this project's Linux-only deployment target).
func fileOwner(info os.FileInfo) (uid, gid int, ok bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(stat.Uid), int(stat.Gid), true
}

// fileOwnerFunc is the fileOwner implementation rotateToken actually calls.
// Tests override it to force the "owner undeterminable" branch
// deterministically, without needing a non-Linux Sys() to occur naturally.
var fileOwnerFunc = fileOwner

// decodeUsersValue defensively decodes a config file's raw "users" value
// into a slice of mutable entry maps, never panicking on any input shape.
// Per BurntSushi/toml v1.6.0: a genuine [[users]] array-of-tables decodes to
// []map[string]any, but a plausible operator variant — an inline
// `users = [{...}]` array — decodes to a *different* Go type, []any, whose
// elements must be converted element-wise. Any other shape, or an entry
// missing a "name"/"token" field of the expected string type, produces a
// clear, index-naming error instead of a type-assertion panic.
func decodeUsersValue(v any) ([]map[string]any, error) {
	var entries []map[string]any
	switch vv := v.(type) {
	case []map[string]any:
		entries = append([]map[string]any{}, vv...)
	case []any:
		entries = make([]map[string]any, len(vv))
		for i, elem := range vv {
			m, ok := elem.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("users[%d] is %T, expected a table with name and token fields", i, elem)
			}
			entries[i] = m
		}
	default:
		return nil, fmt.Errorf("config key \"users\" is %T, expected an array of [[users]] tables", v)
	}

	for i, e := range entries {
		nameVal, ok := e["name"]
		if !ok {
			return nil, fmt.Errorf("users[%d] is missing the required \"name\" field", i)
		}
		if _, ok := nameVal.(string); !ok {
			return nil, fmt.Errorf("users[%d].name is %T, expected a string", i, nameVal)
		}
		tokenVal, ok := e["token"]
		if !ok {
			return nil, fmt.Errorf("users[%d] is missing the required \"token\" field", i)
		}
		if _, ok := tokenVal.(string); !ok {
			return nil, fmt.Errorf("users[%d].token is %T, expected a string", i, tokenVal)
		}
	}
	return entries, nil
}

// selectRotateTarget resolves which configured user rotate-token should
// operate on. An empty username auto-selects the sole configured user; with
// more than one configured, a username is required. An unknown username's
// error always lists the configured names — not a new disclosure, since
// invoking rotate-token already requires read access to the config file.
func selectRotateTarget(names []string, username string) (int, error) {
	sorted := append([]string{}, names...)
	sort.Strings(sorted)

	if username == "" {
		if len(names) == 1 {
			return 0, nil
		}
		return -1, fmt.Errorf(
			"more than one user is configured; specify a username: aged rotate-token <username> (configured users: %s)",
			strings.Join(sorted, ", "),
		)
	}
	for i, n := range names {
		if n == username {
			return i, nil
		}
	}
	return -1, fmt.Errorf("no configured user named %q (configured users: %s)", username, strings.Join(sorted, ", "))
}

// rotateToken generates a new random bearer token for one configured user,
// updates that user's token field in the located config file, and writes the
// new token and the user's name to w. All other config file values are
// preserved, though — per BurntSushi/toml's map[string]any round-trip — key
// order and comments are not (a pre-existing limitation, unchanged by this
// command's redesign; see design.md D5.5).
//
// username selects the target: required when more than one user is
// configured, auto-selected (and always printed) when exactly one is.
func rotateToken(w io.Writer, username string) error {
	path := configFilePath()
	if path == "" {
		return errors.New("no config file found; set AGED_CONFIG or create /etc/aged/config.toml or ~/.config/aged/config.toml")
	}

	// Decode into a raw map so all fields — including ones not in Config —
	// are preserved verbatim.
	var raw map[string]any
	if _, err := toml.DecodeFile(path, &raw); err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	usersRaw, ok := raw["users"]
	if !ok {
		return errors.New("config defines no [[users]]; rotate-token requires at least one [[users]] entry")
	}
	entries, err := decodeUsersValue(usersRaw)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return errors.New("config's [[users]] array is empty; rotate-token requires at least one user")
	}

	names := make([]string, len(entries))
	users := make([]UserConfig, len(entries))
	for i, e := range entries {
		name, _ := e["name"].(string)
		token, _ := e["token"].(string)
		names[i] = name
		users[i] = UserConfig{Name: name, Token: token}
	}

	targetIdx, err := selectRotateTarget(names, username)
	if err != nil {
		return err
	}

	// Capture the original owner now, before it's replaced: os.CreateTemp
	// below creates a file owned by whoever runs this command, not the
	// original config file's owner. Without preserving it explicitly here,
	// running rotate-token as a different user than the one aged serve runs
	// as (a common operational mistake) silently locks the service out of
	// its own config on next start.
	//
	// This assumes no concurrent ownership change on the config file between
	// this stat and the rename below — the codebase has no locking around
	// concurrent rotate-token invocations elsewhere either, so this narrow
	// TOCTOU window is consistent with the rest of the command's design.
	origInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat existing config: %w", err)
	}
	origUID, origGID, haveOwner := fileOwnerFunc(origInfo)

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("generate token: %w", err)
	}
	newToken := hex.EncodeToString(b)
	entries[targetIdx]["token"] = newToken
	users[targetIdx].Token = newToken
	raw["users"] = entries

	// Post-mutation validation (design.md D5.3): the full Multi-User
	// Configuration ruleset is checked against the complete resulting user
	// set before anything is written. A structural problem anywhere aborts.
	// A malformed-token-format problem is fatal only when it belongs to a
	// user OTHER than the just-rotated one is deliberately downgraded to a
	// warning: rotate-token is itself the remediation for a malformed
	// token, so it must not be blocked by a different user's pre-existing
	// one (see design.md's deadlock rationale). A tokenFormat problem on
	// the just-rotated entry cannot occur by construction (freshly
	// generated 64 hex characters) and would indicate a bug if it did.
	var fatal *userProblem
	var warnings []userProblem
	for _, p := range validateUserSet(users) {
		p := p
		if p.category == problemTokenFormat && p.index != targetIdx {
			warnings = append(warnings, p)
			continue
		}
		if fatal == nil {
			fatal = &p
		}
	}
	if fatal != nil {
		return errors.New(fatal.message)
	}
	for _, p := range warnings {
		fmt.Fprintf(w, "warning: %s\n", p.message)
	}

	// Atomic write: stage to a temp file in the same directory (guarantees
	// same filesystem so os.Rename is atomic), then rename over the original.
	// defer os.Remove ensures no stray .config-*.toml files survive on error.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.toml")
	if err != nil {
		return fmt.Errorf("stage config: %w", err)
	}
	defer tmp.Close()           // fd cleanup on all error paths; double-close after explicit Close is harmless
	defer os.Remove(tmp.Name()) // no-op after successful Rename; cleans up on any failure

	// os.CreateTemp already creates with 0600, but use the fd-based Chmod to
	// make the intent explicit and avoid the path-based TOCTOU window.
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("set temp file permissions: %w", err)
	}
	if err := toml.NewEncoder(tmp).Encode(raw); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if haveOwner {
		if err := chownFunc(tmp.Name(), origUID, origGID); err != nil {
			return fmt.Errorf("preserve config file ownership: %w", err)
		}
	} else {
		fmt.Fprintln(w, "warning: could not determine the original config file's ownership; "+
			"it was not preserved on the rewritten file")
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}

	fmt.Fprintf(w, "token rotated for user %q in %s\n", names[targetIdx], path)
	fmt.Fprintf(w, "new token: %s\n", newToken)
	fmt.Fprintln(w, "restart the service to apply: sudo systemctl restart aged")
	return nil
}
