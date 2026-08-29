package main

// spec: openspec/specs/aged/spec.md
// spec: openspec/changes/config-file/specs/aged/spec.md

import (
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Config holds all server runtime configuration. Fields are populated by
// loadConfig: config file values are applied first, then env var values
// override them.
type Config struct {
	Token      string `toml:"token"`
	Identity   string `toml:"identity"`
	SecretsDir string `toml:"secrets_dir"`
	Addr       string `toml:"addr"`
}

// loadConfig returns the effective server configuration. It searches for a
// config file in this order:
//  1. $AGED_CONFIG (if set)
//  2. /etc/aged/config.toml
//  3. ~/.config/aged/config.toml
//
// The first file found is parsed; absence of all three is not an error. After
// loading the file, any set AGED_* environment variable overrides the
// corresponding field.
func loadConfig() Config {
	cfg := Config{}

	if path := configFilePath(); path != "" {
		// Ignore decode errors for missing files; toml.DecodeFile returns an
		// error when the file does not exist, which is already handled by
		// configFilePath only returning paths that exist.
		toml.DecodeFile(path, &cfg) //nolint:errcheck // non-fatal; env vars can supply missing values
	}

	// Env var overrides.
	if v := os.Getenv("AGED_TOKEN"); v != "" {
		cfg.Token = v
	}
	if v := os.Getenv("AGED_IDENTITY"); v != "" {
		cfg.Identity = v
	}
	if v := os.Getenv("AGED_SECRETS_DIR"); v != "" {
		cfg.SecretsDir = v
	}
	if v := os.Getenv("AGED_ADDR"); v != "" {
		cfg.Addr = v
	}

	// Apply defaults for any field still unset.
	if cfg.Identity == "" {
		cfg.Identity = defaultPath(".config/aged/identity.age")
	}
	if cfg.SecretsDir == "" {
		cfg.SecretsDir = defaultPath(".config/aged/secrets")
	}
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:8743"
	}

	return cfg
}

// configFilePath returns the path of the first config file that exists, or
// empty string if none is found.
func configFilePath() string {
	candidates := []string{
		os.Getenv("AGED_CONFIG"),
		"/etc/aged/config.toml",
		defaultPath(".config/aged/config.toml"),
	}
	for _, p := range candidates {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// defaultPath joins the user's home directory with the given relative path.
func defaultPath(rel string) string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, rel)
}
