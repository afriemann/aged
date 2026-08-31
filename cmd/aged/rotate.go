package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

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
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}

	fmt.Fprintf(w, "token rotated in %s\n", path)
	fmt.Fprintf(w, "new token: %s\n", newToken)
	fmt.Fprintln(w, "restart the service to apply: sudo systemctl restart aged")
	return nil
}
