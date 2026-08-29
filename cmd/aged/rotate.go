package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

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

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	defer f.Close()

	if err := toml.NewEncoder(f).Encode(raw); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}

	fmt.Fprintf(w, "token rotated in %s\n", path)
	fmt.Fprintf(w, "new token: %s\n", newToken)
	fmt.Fprintln(w, "restart the service to apply: sudo systemctl restart aged")
	return nil
}
