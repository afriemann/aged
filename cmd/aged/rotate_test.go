package main

// spec: openspec/changes/rotate-token/specs/aged/spec.md
// spec: openspec/changes/security-hardening/specs/aged/spec.md

import (
	"bytes"
	"errors"
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

func TestFileOwner(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	uid, gid, ok := fileOwner(info)
	if !ok {
		t.Fatal("fileOwner returned ok=false on a normal file")
	}
	if uid != os.Getuid() {
		t.Errorf("uid = %d, want %d (current process)", uid, os.Getuid())
	}
	if gid != os.Getgid() {
		t.Errorf("gid = %d, want %d (current process)", gid, os.Getgid())
	}
}

func TestRotateToken_PreservesOwnership(t *testing.T) {
	// spec: Token Rotation — Preserves file ownership across rotation
	dir := t.TempDir()
	path := writeTestConfig(t, dir, map[string]any{"token": "original"})
	t.Setenv("AGED_CONFIG", path)

	origInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat original: %v", err)
	}
	wantUID, wantGID, ok := fileOwner(origInfo)
	if !ok {
		t.Fatal("fileOwner returned ok=false for the original config file")
	}

	var (
		gotPath string
		gotUID  int
		gotGID  int
		calls   int
	)
	origChown := chownFunc
	chownFunc = func(name string, uid, gid int) error {
		gotPath, gotUID, gotGID = name, uid, gid
		calls++
		return nil
	}
	t.Cleanup(func() { chownFunc = origChown })

	if err := rotateToken(&bytes.Buffer{}); err != nil {
		t.Fatalf("rotateToken: %v", err)
	}

	if calls != 1 {
		t.Fatalf("chownFunc called %d times, want exactly 1", calls)
	}
	if gotUID != wantUID || gotGID != wantGID {
		t.Errorf("chownFunc called with uid=%d gid=%d, want uid=%d gid=%d", gotUID, gotGID, wantUID, wantGID)
	}
	if gotPath == "" || gotPath == path {
		t.Errorf("chownFunc called with path %q, want the staged temp file (not the final path)", gotPath)
	}
}

func TestRotateToken_OwnershipPreservationFailureAbortsRotation(t *testing.T) {
	// spec: Token Rotation — Failed write leaves original config intact (ownership variant)
	dir := t.TempDir()
	path := writeTestConfig(t, dir, map[string]any{"token": "original-token"})
	t.Setenv("AGED_CONFIG", path)

	originalContent, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read original: %v", err)
	}

	origChown := chownFunc
	chownFunc = func(name string, uid, gid int) error {
		return errors.New("simulated chown failure")
	}
	t.Cleanup(func() { chownFunc = origChown })

	if err := rotateToken(&bytes.Buffer{}); err == nil {
		t.Fatal("expected an error when ownership preservation fails, got nil")
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after failed rotate: %v", err)
	}
	if !bytes.Equal(content, originalContent) {
		t.Errorf("config file was modified despite a chown failure: got %q, want %q", content, originalContent)
	}

	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".config-") {
			t.Errorf("stray temp file not cleaned up: %s", e.Name())
		}
	}
}

func TestRotateToken_WarnsWhenOwnerCannotBeDetermined(t *testing.T) {
	// spec: Token Rotation — Preserves file ownership across rotation (owner-undeterminable variant)
	dir := t.TempDir()
	path := writeTestConfig(t, dir, map[string]any{"token": "original"})
	t.Setenv("AGED_CONFIG", path)

	origFileOwner := fileOwnerFunc
	fileOwnerFunc = func(info os.FileInfo) (int, int, bool) { return 0, 0, false }
	t.Cleanup(func() { fileOwnerFunc = origFileOwner })

	var stdout bytes.Buffer
	if err := rotateToken(&stdout); err != nil {
		t.Fatalf("rotateToken: %v", err)
	}
	if !strings.Contains(stdout.String(), "ownership") {
		t.Errorf("stdout %q does not warn about undetermined ownership", stdout.String())
	}
}
