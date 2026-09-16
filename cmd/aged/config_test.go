package main

// spec: openspec/changes/config-file/specs/aged/spec.md
// spec: openspec/changes/client-config/specs/aged/spec.md
// spec: openspec/changes/security-hardening/specs/aged/spec.md

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
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

func TestLoadConfig_ConfigFileProvidesServerURL(t *testing.T) {
	// spec: Client Server URL Config — Config file provides server URL
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.toml")
	os.WriteFile(cfgFile, []byte(`server_url = "https://aged.example.com"`+"\n"), 0o600)
	t.Setenv("AGED_CONFIG", cfgFile)
	t.Setenv("AGED_SERVER_URL", "")

	cfg := loadConfig()
	if cfg.ServerURL != "https://aged.example.com" {
		t.Errorf("got ServerURL %q, want %q", cfg.ServerURL, "https://aged.example.com")
	}
}

func TestLoadConfig_EnvVarOverridesConfigFileServerURL(t *testing.T) {
	// spec: Client Server URL Config — Env var overrides config file server URL
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.toml")
	os.WriteFile(cfgFile, []byte(`server_url = "https://aged.example.com"`+"\n"), 0o600)
	t.Setenv("AGED_CONFIG", cfgFile)
	t.Setenv("AGED_SERVER_URL", "http://localhost:8743")

	cfg := loadConfig()
	if cfg.ServerURL != "http://localhost:8743" {
		t.Errorf("got ServerURL %q, want %q", cfg.ServerURL, "http://localhost:8743")
	}
}

func TestLoadConfig_MalformedConfigFileLogsWarning(t *testing.T) {
	// spec: Config File Loading — Malformed config file logs a warning and continues
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgFile, []byte("token = [invalid toml\n"), 0o600); err != nil {
		t.Fatalf("write malformed config: %v", err)
	}
	t.Setenv("AGED_CONFIG", cfgFile)
	t.Setenv("AGED_TOKEN", "from-env") // ensure server can start despite bad file

	// loadConfig uses log.Printf (global logger); redirect it to capture the warning.
	// No t.Parallel() is used in this package so global state mutation is safe here.
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	loadConfig()

	logged := buf.String()
	if !strings.Contains(logged, "warning") {
		t.Errorf("log output %q: expected a warning about the malformed config", logged)
	}
	if !strings.Contains(logged, cfgFile) {
		t.Errorf("log output %q: expected the config file path in the warning", logged)
	}
}

func TestLoadConfig_IdentityExplicitFlag(t *testing.T) {
	// spec: Stale Server Identity Warning (identityExplicit gate)
	t.Run("set via env var", func(t *testing.T) {
		t.Setenv("AGED_CONFIG", "/tmp/definitely-absent-aged-test.toml")
		t.Setenv("AGED_IDENTITY", "/some/identity.age")
		cfg := loadConfig()
		if !cfg.identityExplicit {
			t.Error("expected identityExplicit=true when AGED_IDENTITY is set")
		}
	})

	t.Run("set via config file", func(t *testing.T) {
		dir := t.TempDir()
		cfgFile := filepath.Join(dir, "config.toml")
		os.WriteFile(cfgFile, []byte(`identity = "/some/identity.age"`+"\n"), 0o600)
		t.Setenv("AGED_CONFIG", cfgFile)
		t.Setenv("AGED_IDENTITY", "")
		cfg := loadConfig()
		if !cfg.identityExplicit {
			t.Error("expected identityExplicit=true when config file sets identity")
		}
	})

	t.Run("left at default", func(t *testing.T) {
		t.Setenv("AGED_CONFIG", "/tmp/definitely-absent-aged-test.toml")
		t.Setenv("AGED_IDENTITY", "")
		cfg := loadConfig()
		if cfg.identityExplicit {
			t.Error("expected identityExplicit=false when identity was never set")
		}
	})
}

func TestLoadConfig_DecodesUsersArray(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.toml")
	os.WriteFile(cfgFile, []byte(`
[[users]]
name = "alice"
token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[[users]]
name = "bob"
token = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
`), 0o600)
	t.Setenv("AGED_CONFIG", cfgFile)
	t.Setenv("AGED_TOKEN", "")
	t.Setenv("AGED_USERNAME", "")

	cfg := loadConfig()
	if len(cfg.Users) != 2 {
		t.Fatalf("got %d users, want 2", len(cfg.Users))
	}
	if cfg.Users[0].Name != "alice" || cfg.Users[1].Name != "bob" {
		t.Errorf("got users %+v, want alice then bob in file order", cfg.Users)
	}
}

func TestLoadConfig_CapturesEnvUserPair(t *testing.T) {
	t.Setenv("AGED_CONFIG", "/tmp/definitely-absent-aged-test.toml")
	t.Setenv("AGED_TOKEN", "sometoken")
	t.Setenv("AGED_USERNAME", "laptop")

	cfg := loadConfig()
	if cfg.envToken != "sometoken" || cfg.envUsername != "laptop" {
		t.Errorf("got envToken=%q envUsername=%q, want sometoken/laptop", cfg.envToken, cfg.envUsername)
	}
	// loadConfig itself must not merge these into cfg.Users — that is a
	// server-only concern, and cfg.Token must remain the client's own
	// credential, untouched by AGED_USERNAME.
	if cfg.Token != "sometoken" {
		t.Errorf("cfg.Token = %q, want it to still carry the client credential", cfg.Token)
	}
	if len(cfg.Users) != 0 {
		t.Errorf("loadConfig must not merge the env pair into Users; got %+v", cfg.Users)
	}
}
