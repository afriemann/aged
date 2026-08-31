package main

// spec: openspec/changes/rotate-token/specs/aged/spec.md
// spec: openspec/changes/security-hardening/specs/aged/spec.md

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func writeTestConfig(t *testing.T, dir string, content map[string]any) string {
	t.Helper()
	path := filepath.Join(dir, "config.toml")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("create config: %v", err)
	}
	defer f.Close()
	if err := toml.NewEncoder(f).Encode(content); err != nil {
		t.Fatalf("encode config: %v", err)
	}
	return path
}

func TestRotateToken_RotatesTokenInConfigFile(t *testing.T) {
	// spec: Token Rotation — Rotates token in config file
	dir := t.TempDir()
	path := writeTestConfig(t, dir, map[string]any{
		"token":      "old-token-value",
		"server_url": "https://aged.example.com",
	})
	t.Setenv("AGED_CONFIG", path)

	var stdout bytes.Buffer
	if err := rotateToken(&stdout); err != nil {
		t.Fatalf("rotateToken: %v", err)
	}

	// Token in file must have changed.
	var updated map[string]any
	if _, err := toml.DecodeFile(path, &updated); err != nil {
		t.Fatalf("decode updated config: %v", err)
	}
	newToken, _ := updated["token"].(string)
	if newToken == "old-token-value" {
		t.Error("token was not rotated")
	}
	if newToken == "" {
		t.Error("new token is empty")
	}

	// New token printed to stdout.
	if !strings.Contains(stdout.String(), newToken) {
		t.Errorf("stdout %q does not contain new token %q", stdout.String(), newToken)
	}

	// Other fields preserved.
	if updated["server_url"] != "https://aged.example.com" {
		t.Errorf("server_url changed: got %v", updated["server_url"])
	}
}

func TestRotateToken_OldAndNewTokensDiffer(t *testing.T) {
	// spec: Token Rotation — Rotates token in config file (old and new differ)
	dir := t.TempDir()
	path := writeTestConfig(t, dir, map[string]any{"token": "original"})
	t.Setenv("AGED_CONFIG", path)

	rotateToken(&bytes.Buffer{})

	var cfg map[string]any
	toml.DecodeFile(path, &cfg)
	if cfg["token"] == "original" {
		t.Error("token unchanged after rotation")
	}
}

func TestRotateToken_NoConfigFileReturnsError(t *testing.T) {
	// spec: Token Rotation — No config file returns an error
	emptyHome := t.TempDir()
	t.Setenv("AGED_CONFIG", "/tmp/aged-definitely-does-not-exist-test.toml")
	t.Setenv("HOME", emptyHome) // prevent ~/.config/aged/config.toml from being found

	err := rotateToken(&bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error when no config file found, got nil")
	}
}

func TestRotateToken_TwoRotationsProduceDifferentTokens(t *testing.T) {
	// spec: Token Rotation — New token is cryptographically random
	dir := t.TempDir()
	path := writeTestConfig(t, dir, map[string]any{"token": "seed"})
	t.Setenv("AGED_CONFIG", path)

	rotateToken(&bytes.Buffer{})
	var first map[string]any
	toml.DecodeFile(path, &first)

	rotateToken(&bytes.Buffer{})
	var second map[string]any
	toml.DecodeFile(path, &second)

	if first["token"] == second["token"] {
		t.Error("two consecutive rotations produced the same token")
	}
}

func TestRotateToken_AtomicWrite_OriginalIntactOnError(t *testing.T) {
	// spec: Token Rotation — Failed write leaves original config intact
	if os.Getuid() == 0 {
		t.Skip("cannot test filesystem permissions as root")
	}
	dir := t.TempDir()
	path := writeTestConfig(t, dir, map[string]any{"token": "original-token"})
	t.Setenv("AGED_CONFIG", path)

	originalContent, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read original: %v", err)
	}

	// Make the directory unwritable so os.CreateTemp fails.
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	// Always restore before TempDir cleanup runs.
	t.Cleanup(func() { os.Chmod(dir, 0o755) })

	if err := rotateToken(&bytes.Buffer{}); err == nil {
		t.Fatal("expected error when directory is not writable, got nil")
	}

	// Restore permissions to read the file.
	os.Chmod(dir, 0o755)

	// Original must be unchanged.
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after failed rotate: %v", err)
	}
	if !bytes.Equal(content, originalContent) {
		t.Errorf("config file was modified: got %q, want %q", content, originalContent)
	}

	// No stray temp files must remain.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".config-") {
			t.Errorf("stray temp file not cleaned up: %s", e.Name())
		}
	}
}

func TestRotateToken_NoTempFilesAfterSuccess(t *testing.T) {
	// spec: Token Rotation — Failed write leaves original config intact (success path cleanup)
	dir := t.TempDir()
	path := writeTestConfig(t, dir, map[string]any{"token": "start"})
	t.Setenv("AGED_CONFIG", path)

	if err := rotateToken(&bytes.Buffer{}); err != nil {
		t.Fatalf("rotateToken: %v", err)
	}

	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".config-") {
			t.Errorf("stray temp file not cleaned up after success: %s", e.Name())
		}
	}
}
