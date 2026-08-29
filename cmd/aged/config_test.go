package main

// spec: openspec/changes/config-file/specs/aged/spec.md

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_ConfigFileSetsIdentityPath(t *testing.T) {
	// spec: Config File Loading — Config file sets identity path
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.toml")
	customIdentity := filepath.Join(dir, "custom-identity.age")

	os.WriteFile(cfgFile, []byte(`identity = "`+customIdentity+`"`+"\n"), 0o600)
	t.Setenv("AGED_CONFIG", cfgFile)
	t.Setenv("AGED_IDENTITY", "") // ensure env var doesn't shadow

	cfg := loadConfig()
	if cfg.Identity != customIdentity {
		t.Errorf("got Identity %q, want %q", cfg.Identity, customIdentity)
	}
}

func TestLoadConfig_EnvVarOverridesConfigFile(t *testing.T) {
	// spec: Config File Loading — Env var overrides config file
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.toml")
	os.WriteFile(cfgFile, []byte(`addr = "0.0.0.0:9000"`+"\n"), 0o600)

	t.Setenv("AGED_CONFIG", cfgFile)
	t.Setenv("AGED_ADDR", "127.0.0.1:8743")

	cfg := loadConfig()
	if cfg.Addr != "127.0.0.1:8743" {
		t.Errorf("got Addr %q, want %q (env var should override config file)", cfg.Addr, "127.0.0.1:8743")
	}
}

func TestLoadConfig_AbsentConfigFileIsNotAnError(t *testing.T) {
	// spec: Config File Loading — Absent config file is not an error
	t.Setenv("AGED_CONFIG", "/tmp/this-file-does-not-exist-aged-test.toml")
	t.Setenv("AGED_TOKEN", "env-token")
	t.Setenv("AGED_ADDR", "127.0.0.1:18743")

	// loadConfig must not panic or return an error; it returns a Config.
	cfg := loadConfig()
	if cfg.Token != "env-token" {
		t.Errorf("got Token %q, want %q", cfg.Token, "env-token")
	}
}

func TestLoadConfig_AgedConfigPointsToCustomPath(t *testing.T) {
	// spec: Config File Loading — AGED_CONFIG points to a custom path
	dir := t.TempDir()
	customPath := filepath.Join(dir, "my-aged.toml")
	os.WriteFile(customPath, []byte(`token = "from-custom-file"`+"\n"), 0o600)

	t.Setenv("AGED_CONFIG", customPath)
	t.Setenv("AGED_TOKEN", "") // clear env so file value wins

	cfg := loadConfig()
	if cfg.Token != "from-custom-file" {
		t.Errorf("got Token %q, want %q", cfg.Token, "from-custom-file")
	}
}

func TestLoadConfig_DefaultsAppliedWhenNothingSet(t *testing.T) {
	// spec: Environment Variable Configuration — defaults
	t.Setenv("AGED_CONFIG", "/tmp/definitely-absent-aged-test.toml")
	t.Setenv("AGED_TOKEN", "")
	t.Setenv("AGED_IDENTITY", "")
	t.Setenv("AGED_SECRETS_DIR", "")
	t.Setenv("AGED_ADDR", "")

	cfg := loadConfig()

	if cfg.Addr != "127.0.0.1:8743" {
		t.Errorf("default Addr: got %q, want %q", cfg.Addr, "127.0.0.1:8743")
	}
	if cfg.Identity == "" {
		t.Error("default Identity should not be empty")
	}
	if cfg.SecretsDir == "" {
		t.Error("default SecretsDir should not be empty")
	}
}
