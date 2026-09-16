package main

// spec: openspec/changes/rotate-token/specs/aged/spec.md
// spec: openspec/changes/security-hardening/specs/aged/spec.md
// spec: openspec/changes/multi-user-support/specs/aged/spec.md

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

// oneUserConfig returns a config map with a single [[users]] entry, suitable
// for writeTestConfig, plus any extra top-level fields merged in.
func oneUserConfig(name, token string, extra map[string]any) map[string]any {
	cfg := map[string]any{
		"users": []map[string]any{{"name": name, "token": token}},
	}
	for k, v := range extra {
		cfg[k] = v
	}
	return cfg
}

// decodedUsers re-reads path and returns its users array as
// []map[string]any, regardless of whether rotateToken serialised it that way
// or the fixture was written differently.
func decodedUsers(t *testing.T, path string) []map[string]any {
	t.Helper()
	var cfg map[string]any
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	entries, err := decodeUsersValue(cfg["users"])
	if err != nil {
		t.Fatalf("decodeUsersValue: %v", err)
	}
	return entries
}

func TestRotateToken_RotatesTokenInConfigFile(t *testing.T) {
	// spec: Token Rotation — Rotates token in config file
	dir := t.TempDir()
	path := writeTestConfig(t, dir, oneUserConfig("alice", tok('a'), map[string]any{
		"server_url": "https://aged.example.com",
	}))
	t.Setenv("AGED_CONFIG", path)

	var stdout bytes.Buffer
	if err := rotateToken(&stdout, ""); err != nil {
		t.Fatalf("rotateToken: %v", err)
	}

	entries := decodedUsers(t, path)
	newToken, _ := entries[0]["token"].(string)
	if newToken == tok('a') {
		t.Error("token was not rotated")
	}
	if newToken == "" {
		t.Error("new token is empty")
	}
	if !strings.Contains(stdout.String(), newToken) {
		t.Errorf("stdout %q does not contain new token %q", stdout.String(), newToken)
	}
	if !strings.Contains(stdout.String(), "alice") {
		t.Errorf("stdout %q does not name the rotated user", stdout.String())
	}

	var updated map[string]any
	toml.DecodeFile(path, &updated)
	if updated["server_url"] != "https://aged.example.com" {
		t.Errorf("server_url changed: got %v", updated["server_url"])
	}
}

func TestRotateToken_OldAndNewTokensDiffer(t *testing.T) {
	// spec: Token Rotation — Rotates token in config file (old and new differ)
	dir := t.TempDir()
	path := writeTestConfig(t, dir, oneUserConfig("alice", tok('a'), nil))
	t.Setenv("AGED_CONFIG", path)

	rotateToken(&bytes.Buffer{}, "")

	entries := decodedUsers(t, path)
	if entries[0]["token"] == tok('a') {
		t.Error("token unchanged after rotation")
	}
}

func TestRotateToken_NoConfigFileReturnsError(t *testing.T) {
	// spec: Token Rotation — No config file returns an error
	emptyHome := t.TempDir()
	t.Setenv("AGED_CONFIG", "/tmp/aged-definitely-does-not-exist-test.toml")
	t.Setenv("HOME", emptyHome) // prevent ~/.config/aged/config.toml from being found

	err := rotateToken(&bytes.Buffer{}, "")
	if err == nil {
		t.Fatal("expected error when no config file found, got nil")
	}
}

func TestRotateToken_TwoRotationsProduceDifferentTokens(t *testing.T) {
	// spec: Token Rotation — New token is cryptographically random
	dir := t.TempDir()
	path := writeTestConfig(t, dir, oneUserConfig("alice", tok('a'), nil))
	t.Setenv("AGED_CONFIG", path)

	rotateToken(&bytes.Buffer{}, "")
	first := decodedUsers(t, path)

	rotateToken(&bytes.Buffer{}, "")
	second := decodedUsers(t, path)

	if first[0]["token"] == second[0]["token"] {
		t.Error("two consecutive rotations produced the same token")
	}
}

func TestRotateToken_AtomicWrite_OriginalIntactOnError(t *testing.T) {
	// spec: Token Rotation — Failed write leaves original config intact
	if os.Getuid() == 0 {
		t.Skip("cannot test filesystem permissions as root")
	}
	dir := t.TempDir()
	path := writeTestConfig(t, dir, oneUserConfig("alice", tok('a'), nil))
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

	if err := rotateToken(&bytes.Buffer{}, ""); err == nil {
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
	path := writeTestConfig(t, dir, oneUserConfig("alice", tok('a'), nil))
	t.Setenv("AGED_CONFIG", path)

	if err := rotateToken(&bytes.Buffer{}, ""); err != nil {
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
	path := writeTestConfig(t, dir, oneUserConfig("alice", tok('a'), nil))
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

	if err := rotateToken(&bytes.Buffer{}, ""); err != nil {
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
	path := writeTestConfig(t, dir, oneUserConfig("alice", tok('a'), nil))
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

	if err := rotateToken(&bytes.Buffer{}, ""); err == nil {
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
	path := writeTestConfig(t, dir, oneUserConfig("alice", tok('a'), nil))
	t.Setenv("AGED_CONFIG", path)

	origFileOwner := fileOwnerFunc
	fileOwnerFunc = func(info os.FileInfo) (int, int, bool) { return 0, 0, false }
	t.Cleanup(func() { fileOwnerFunc = origFileOwner })

	var stdout bytes.Buffer
	if err := rotateToken(&stdout, ""); err != nil {
		t.Fatalf("rotateToken: %v", err)
	}
	if !strings.Contains(stdout.String(), "ownership") {
		t.Errorf("stdout %q does not warn about undetermined ownership", stdout.String())
	}
}

func TestRotateToken_UsernameRequiredWithMultipleUsers(t *testing.T) {
	// spec: Token Rotation — Username required with multiple users
	dir := t.TempDir()
	path := writeTestConfig(t, dir, map[string]any{
		"users": []map[string]any{
			{"name": "alice", "token": tok('a')},
			{"name": "bob", "token": tok('b')},
		},
	})
	t.Setenv("AGED_CONFIG", path)

	err := rotateToken(&bytes.Buffer{}, "")
	if err == nil {
		t.Fatal("expected an error when username is omitted with multiple users")
	}
	if !strings.Contains(err.Error(), "alice") || !strings.Contains(err.Error(), "bob") {
		t.Errorf("error %q does not list the configured user names", err.Error())
	}
}

func TestRotateToken_UnknownUsernameListsConfiguredNames(t *testing.T) {
	// spec: Token Rotation — Unknown username lists configured names
	dir := t.TempDir()
	path := writeTestConfig(t, dir, oneUserConfig("alice", tok('a'), nil))
	t.Setenv("AGED_CONFIG", path)

	err := rotateToken(&bytes.Buffer{}, "carol")
	if err == nil {
		t.Fatal("expected an error for an unknown username")
	}
	if !strings.Contains(err.Error(), "alice") {
		t.Errorf("error %q does not list the configured user names", err.Error())
	}
}

func TestRotateToken_SingleUserAutoSelectedAndPrinted(t *testing.T) {
	// spec: Token Rotation — the argument, if omitted, SHALL default to that
	// user; its name SHALL be printed regardless of whether it was given
	// explicitly.
	dir := t.TempDir()
	path := writeTestConfig(t, dir, oneUserConfig("laptop", tok('a'), nil))
	t.Setenv("AGED_CONFIG", path)

	var stdout bytes.Buffer
	if err := rotateToken(&stdout, ""); err != nil {
		t.Fatalf("rotateToken: %v", err)
	}
	if !strings.Contains(stdout.String(), "laptop") {
		t.Errorf("stdout %q must name the auto-selected user", stdout.String())
	}
}

func TestRotateToken_MalformedUsersValueProducesCleanError(t *testing.T) {
	// spec: Token Rotation — Malformed users value produces a clean error
	for _, tc := range []struct {
		name  string
		value map[string]any
	}{
		{"inline table", map[string]any{"users": map[string]any{"name": "alice", "token": tok('a')}}},
		{"scalar", map[string]any{"users": "not-an-array"}},
		{"missing name field", map[string]any{"users": []map[string]any{{"token": tok('a')}}}},
		{"missing token field", map[string]any{"users": []map[string]any{{"name": "alice"}}}},
		{"non-string name", map[string]any{"users": []map[string]any{{"name": 42, "token": tok('a')}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeTestConfig(t, dir, tc.value)
			t.Setenv("AGED_CONFIG", path)

			// Must not panic.
			err := rotateToken(&bytes.Buffer{}, "")
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}

	t.Run("no users key at all", func(t *testing.T) {
		dir := t.TempDir()
		path := writeTestConfig(t, dir, map[string]any{"server_url": "https://example.com"})
		t.Setenv("AGED_CONFIG", path)

		err := rotateToken(&bytes.Buffer{}, "")
		if err == nil {
			t.Fatal("expected an error when the config defines no [[users]], got nil")
		}
	})
}

func TestRotateToken_InlineUsersArrayDecodesWithoutPanic(t *testing.T) {
	// spec: Token Rotation — the command SHALL decode the config file's
	// "users" value defensively; an inline `users = [{...}]` array parses
	// to []any (not []map[string]any) per BurntSushi/toml v1.6.0.
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := "users = [{ name = \"alice\", token = \"" + tok('a') + "\" }]\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("AGED_CONFIG", path)

	if err := rotateToken(&bytes.Buffer{}, ""); err != nil {
		t.Fatalf("rotateToken with inline users array: %v", err)
	}
}

func TestRotateToken_BlockedByStructuralProblemOnAnotherUser(t *testing.T) {
	// spec: Token Rotation — Rotation is blocked by a structural problem on another user
	dir := t.TempDir()
	path := writeTestConfig(t, dir, map[string]any{
		"users": []map[string]any{
			{"name": "-invalid", "token": tok('a')},
			{"name": "bob", "token": tok('b')},
		},
	})
	t.Setenv("AGED_CONFIG", path)
	originalContent, _ := os.ReadFile(path)

	err := rotateToken(&bytes.Buffer{}, "bob")
	if err == nil {
		t.Fatal("expected an error when another user has a structural problem")
	}
	content, _ := os.ReadFile(path)
	if !bytes.Equal(content, originalContent) {
		t.Error("config file was modified despite the rotation being blocked")
	}
}

func TestRotateToken_ProceedsDespiteAnotherUsersMalformedToken(t *testing.T) {
	// spec: Token Rotation — Rotation proceeds despite another user's malformed token
	dir := t.TempDir()
	path := writeTestConfig(t, dir, map[string]any{
		"users": []map[string]any{
			{"name": "alice", "token": "not-64-hex-chars"},
			{"name": "bob", "token": tok('b')},
		},
	})
	t.Setenv("AGED_CONFIG", path)

	var stdout bytes.Buffer
	if err := rotateToken(&stdout, "bob"); err != nil {
		t.Fatalf("rotateToken: %v", err)
	}
	if !strings.Contains(stdout.String(), "alice") {
		t.Errorf("stdout %q must warn naming the malformed user alice", stdout.String())
	}
	entries := decodedUsers(t, path)
	var bobToken string
	for _, e := range entries {
		if e["name"] == "bob" {
			bobToken, _ = e["token"].(string)
		}
	}
	if bobToken == tok('b') {
		t.Error("bob's token was not rotated")
	}
}
