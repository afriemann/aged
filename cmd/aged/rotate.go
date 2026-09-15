package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

// rotateToken generates a new random bearer token, updates the token field in
// the located config file, and writes the new token to w. All other config
// file fields are preserved unchanged.
func rotateToken(w io.Writer) error {
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
	raw["token"] = newToken

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

	fmt.Fprintf(w, "token rotated in %s\n", path)
	fmt.Fprintf(w, "new token: %s\n", newToken)
	fmt.Fprintln(w, "restart the service to apply: sudo systemctl restart aged")
	return nil
}
