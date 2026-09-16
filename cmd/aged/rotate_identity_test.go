package main

// spec: openspec/changes/client-side-encryption/specs/aged/spec.md

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

// rotateTestEnv sets up cfg.Identity (old) + cfg.SecretsDir pointing at a
// temp base directory, configures a single user ("testuser") via the
// AGED_USERNAME/AGED_TOKEN environment pair, and returns the old identity
// plus that user's effective secrets subtree (secrets_dir/testuser) — the
// directory rotateIdentity actually operates on with an empty username (it
// auto-selects the sole configured user). A helper to store a raw
// (possibly-unbound) ciphertext secret directly on disk, bypassing any
// envelope logic, is also provided — used to construct legacy/misfiled
// fixtures.
func rotateTestEnv(t *testing.T) (oldIdentity *age.X25519Identity, secretsDir string) {
	t.Helper()
	dir := t.TempDir()
	baseSecretsDir := filepath.Join(dir, "secrets")
	secretsDir = filepath.Join(baseSecretsDir, "testuser")
	if err := os.MkdirAll(secretsDir, 0o700); err != nil {
		t.Fatalf("mkdir secrets: %v", err)
	}

	oldIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate old identity: %v", err)
	}
	identityPath := filepath.Join(dir, "old-identity.age")
	f, _ := os.OpenFile(identityPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	fmt.Fprintf(f, "# test\n%s\n", oldIdentity)
	f.Close()

	t.Setenv("AGED_CONFIG", "/tmp/definitely-absent-aged-test.toml")
	t.Setenv("AGED_IDENTITY", identityPath)
	t.Setenv("AGED_SECRETS_DIR", baseSecretsDir)
	t.Setenv("AGED_TOKEN", tok('a'))
	t.Setenv("AGED_USERNAME", "testuser")
	t.Setenv("AGED_ADDR", "127.0.0.1:0")

	return oldIdentity, secretsDir
}

// putRawSecret encrypts plaintext (verbatim, no envelope wrapping applied)
// to recipient and writes it directly to secretsDir/name.age.
func putRawSecret(t *testing.T, secretsDir, name string, recipient age.Recipient, plaintext []byte) {
	t.Helper()
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		t.Fatalf("age.Encrypt: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	path := filepath.Join(secretsDir, name+".age")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
}

func newTestIdentityFile(t *testing.T) (path string, id *age.X25519Identity) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	dir := t.TempDir()
	path = filepath.Join(dir, "new-identity.age")
	f, _ := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	fmt.Fprintf(f, "# test\n%s\n", id)
	f.Close()
	return path, id
}

func TestRotateIdentity(t *testing.T) {
	t.Run("Dry run reports counts without writing anything", func(t *testing.T) {
		oldID, secretsDir := rotateTestEnv(t)
		putRawSecret(t, secretsDir, "legacy", oldID.Recipient(), packEnvelope("legacy", []byte("v1")))
		putRawSecret(t, secretsDir, "another", oldID.Recipient(), packEnvelope("another", []byte("v2")))
		newIdentityFile, _ := newTestIdentityFile(t)

		before, _ := os.ReadDir(secretsDir)

		var out bytes.Buffer
		if err := rotateIdentity(newIdentityFile, "", true, &out); err != nil {
			t.Fatalf("rotateIdentity --dry-run: %v", err)
		}
		if !strings.Contains(out.String(), "2 secret(s) would migrate successfully") {
			t.Errorf("output %q: expected count of 2 successful migrations", out.String())
		}

		after, _ := os.ReadDir(secretsDir)
		if len(before) != len(after) {
			t.Errorf("secrets dir contents changed: before %d entries, after %d", len(before), len(after))
		}
		siblings, _ := os.ReadDir(filepath.Dir(secretsDir))
		for _, e := range siblings {
			if strings.Contains(e.Name(), ".rotating-") {
				t.Errorf("staging directory %q left behind after dry run", e.Name())
			}
		}
	})

	t.Run("Successful rotation replaces the store atomically", func(t *testing.T) {
		oldID, secretsDir := rotateTestEnv(t)
		putRawSecret(t, secretsDir, "a", oldID.Recipient(), packEnvelope("a", []byte("value-a")))
		putRawSecret(t, secretsDir, "ns/b", oldID.Recipient(), packEnvelope("ns/b", []byte("value-b")))
		newIdentityFile, newID := newTestIdentityFile(t)

		var out bytes.Buffer
		if err := rotateIdentity(newIdentityFile, "", false, &out); err != nil {
			t.Fatalf("rotateIdentity: %v", err)
		}

		// secretsDir now holds the re-encrypted secrets, decryptable by the
		// new identity.
		for _, tc := range []struct{ name, want string }{
			{"a", "value-a"},
			{"ns/b", "value-b"},
		} {
			path := filepath.Join(secretsDir, filepath.FromSlash(tc.name)+".age")
			ciphertext, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read migrated secret %s: %v", tc.name, err)
			}
			plaintext, err := decryptCiphertext(ciphertext, []age.Identity{newID})
			if err != nil {
				t.Fatalf("decrypt migrated secret %s with new identity: %v", tc.name, err)
			}
			value, err := unpackEnvelope(tc.name, plaintext)
			if err != nil {
				t.Fatalf("unpack envelope for %s: %v", tc.name, err)
			}
			if string(value) != tc.want {
				t.Errorf("secret %s: got %q, want %q", tc.name, value, tc.want)
			}
		}

		// A timestamped backup of the old secrets dir exists.
		siblings, _ := os.ReadDir(filepath.Dir(secretsDir))
		foundBackup := false
		for _, e := range siblings {
			if strings.HasPrefix(e.Name(), filepath.Base(secretsDir)+".old-") {
				foundBackup = true
			}
		}
		if !foundBackup {
			t.Error("expected a timestamped backup directory of the previous secrets dir")
		}
	})

	t.Run("Verification failure aborts without touching the live store", func(t *testing.T) {
		oldID, secretsDir := rotateTestEnv(t)
		putRawSecret(t, secretsDir, "a", oldID.Recipient(), packEnvelope("a", []byte("value-a")))
		newIdentityFile, _ := newTestIdentityFile(t)

		before := snapshotDir(t, secretsDir)

		rotateIdentityCorruptStagedFileHook = func(stagedPath string) error {
			return os.WriteFile(stagedPath, []byte("corrupted-not-age-ciphertext"), 0o600)
		}
		t.Cleanup(func() { rotateIdentityCorruptStagedFileHook = nil })

		var out bytes.Buffer
		err := rotateIdentity(newIdentityFile, "", false, &out)
		if err == nil {
			t.Fatal("expected an error from a verification failure, got nil")
		}

		after := snapshotDir(t, secretsDir)
		if before != after {
			t.Error("secrets dir was modified despite a verification failure")
		}
	})

	t.Run("Refuses to run while the server is listening", func(t *testing.T) {
		oldID, secretsDir := rotateTestEnv(t)
		putRawSecret(t, secretsDir, "a", oldID.Recipient(), packEnvelope("a", []byte("value-a")))
		newIdentityFile, _ := newTestIdentityFile(t)

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("bind test listener: %v", err)
		}
		defer ln.Close()
		t.Setenv("AGED_ADDR", ln.Addr().String())

		var out bytes.Buffer
		if err := rotateIdentity(newIdentityFile, "", false, &out); err == nil {
			t.Error("expected refusal while address is in use, got nil error")
		}

		// --dry-run must proceed anyway.
		var dryOut bytes.Buffer
		if err := rotateIdentity(newIdentityFile, "", true, &dryOut); err != nil {
			t.Errorf("--dry-run should proceed even while the server is listening: %v", err)
		}
	})

	t.Run("Legacy unbound secret is migrated into the envelope format", func(t *testing.T) {
		oldID, secretsDir := rotateTestEnv(t)
		// Raw legacy plaintext, no envelope at all — as a pre-change server
		// would have stored it.
		putRawSecret(t, secretsDir, "legacy-secret", oldID.Recipient(), []byte("legacy-plaintext-value"))
		newIdentityFile, newID := newTestIdentityFile(t)

		var out bytes.Buffer
		if err := rotateIdentity(newIdentityFile, "", false, &out); err != nil {
			t.Fatalf("rotateIdentity: %v", err)
		}

		path := filepath.Join(secretsDir, "legacy-secret.age")
		ciphertext, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read migrated secret: %v", err)
		}
		plaintext, err := decryptCiphertext(ciphertext, []age.Identity{newID})
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		value, err := unpackEnvelope("legacy-secret", plaintext)
		if err != nil {
			t.Fatalf("expected legacy secret to now be enveloped, got unpack error: %v", err)
		}
		if string(value) != "legacy-plaintext-value" {
			t.Errorf("got %q, want %q", value, "legacy-plaintext-value")
		}
	})

	t.Run("Misfiled secret aborts the run", func(t *testing.T) {
		oldID, secretsDir := rotateTestEnv(t)
		// Envelope claims name "other", but is stored on disk as "actual".
		putRawSecret(t, secretsDir, "actual", oldID.Recipient(), packEnvelope("other", []byte("v")))
		newIdentityFile, _ := newTestIdentityFile(t)

		before := snapshotDir(t, secretsDir)

		var out bytes.Buffer
		err := rotateIdentity(newIdentityFile, "", false, &out)
		if err == nil {
			t.Fatal("expected an error for a misfiled secret, got nil")
		}
		if !strings.Contains(err.Error(), "actual") {
			t.Errorf("error %q: expected it to name the offending file", err)
		}

		after := snapshotDir(t, secretsDir)
		if before != after {
			t.Error("secrets dir was modified despite an aborted run")
		}
	})

	t.Run("New identity file with more than one identity is rejected", func(t *testing.T) {
		oldID, secretsDir := rotateTestEnv(t)
		putRawSecret(t, secretsDir, "a", oldID.Recipient(), packEnvelope("a", []byte("v")))

		id1, _ := age.GenerateX25519Identity()
		id2, _ := age.GenerateX25519Identity()
		dir := t.TempDir()
		multiPath := filepath.Join(dir, "multi.age")
		f, _ := os.OpenFile(multiPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		fmt.Fprintf(f, "# test\n%s\n%s\n", id1, id2)
		f.Close()

		var out bytes.Buffer
		err := rotateIdentity(multiPath, "", false, &out)
		if err == nil {
			t.Fatal("expected an error for a multi-identity new-identity file, got nil")
		}
	})

	t.Run("No plaintext or key material is ever printed", func(t *testing.T) {
		oldID, secretsDir := rotateTestEnv(t)
		putRawSecret(t, secretsDir, "a", oldID.Recipient(), packEnvelope("a", []byte("super-secret-plaintext")))
		newIdentityFile, newID := newTestIdentityFile(t)

		var out bytes.Buffer
		if err := rotateIdentity(newIdentityFile, "", false, &out); err != nil {
			t.Fatalf("rotateIdentity: %v", err)
		}

		output := out.String()
		if strings.Contains(output, "super-secret-plaintext") {
			t.Error("plaintext value leaked into command output")
		}
		if strings.Contains(output, oldID.String()) || strings.Contains(output, newID.String()) {
			t.Error("private key material leaked into command output")
		}
	})
}

// snapshotDir returns a stable string representation of every file's path
// and content under dir, for before/after comparison.
func snapshotDir(t *testing.T, dir string) string {
	t.Helper()
	var buf strings.Builder
	walkDirSorted(t, dir, func(path string, data []byte) {
		fmt.Fprintf(&buf, "%s:%x\n", path, data)
	})
	return buf.String()
}

func walkDirSorted(t *testing.T, dir string, fn func(path string, data []byte)) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	for _, e := range entries {
		full := filepath.Join(dir, e.Name())
		if e.IsDir() {
			walkDirSorted(t, full, fn)
			continue
		}
		data, err := os.ReadFile(full)
		if err != nil {
			t.Fatalf("read file %s: %v", full, err)
		}
		fn(full, data)
	}
}

func TestRotateIdentity_RefusesWithoutUserWhenMultipleConfigured(t *testing.T) {
	// spec: Identity Rotation — Refuses to run without --user when multiple users are configured
	oldID, secretsDir := rotateTestEnv(t)
	putRawSecret(t, secretsDir, "a", oldID.Recipient(), packEnvelope("a", []byte("v")))
	// Add a second user via a config file (env pair already defines "testuser").
	baseSecretsDir := filepath.Dir(secretsDir)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	os.WriteFile(cfgPath, []byte(fmt.Sprintf(
		"secrets_dir = %q\n[[users]]\nname = \"other\"\ntoken = \"%s\"\n",
		baseSecretsDir, tok('b'),
	)), 0o600)
	t.Setenv("AGED_CONFIG", cfgPath)

	newIdentityFile, _ := newTestIdentityFile(t)
	var out bytes.Buffer
	err := rotateIdentity(newIdentityFile, "", false, &out)
	if err == nil {
		t.Fatal("expected an error when --user is omitted with multiple users configured")
	}
	if !strings.Contains(err.Error(), "testuser") || !strings.Contains(err.Error(), "other") {
		t.Errorf("error %q must list the configured user names", err.Error())
	}
}

func TestRotateIdentity_DefaultsToSoleUserAndPrintsName(t *testing.T) {
	// spec: Identity Rotation — Defaults to the sole user when exactly one is configured
	oldID, secretsDir := rotateTestEnv(t)
	putRawSecret(t, secretsDir, "a", oldID.Recipient(), packEnvelope("a", []byte("v")))
	newIdentityFile, _ := newTestIdentityFile(t)

	var out bytes.Buffer
	if err := rotateIdentity(newIdentityFile, "", false, &out); err != nil {
		t.Fatalf("rotateIdentity: %v", err)
	}
	if !strings.Contains(out.String(), "testuser") {
		t.Errorf("output %q must name the auto-selected sole user", out.String())
	}
}

func TestRotateIdentity_OperatesOnlyOnSelectedUsersSubtree(t *testing.T) {
	// spec: Identity Rotation — Operates only on the selected user's subtree
	dir := t.TempDir()
	baseSecretsDir := filepath.Join(dir, "secrets")

	oldID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate old identity: %v", err)
	}
	identityPath := filepath.Join(dir, "old-identity.age")
	f, _ := os.OpenFile(identityPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	fmt.Fprintf(f, "# test\n%s\n", oldID)
	f.Close()

	cfgPath := filepath.Join(dir, "config.toml")
	os.WriteFile(cfgPath, []byte(fmt.Sprintf(
		"secrets_dir = %q\nidentity = %q\n[[users]]\nname = \"alice\"\ntoken = \"%s\"\n[[users]]\nname = \"bob\"\ntoken = \"%s\"\n",
		baseSecretsDir, identityPath, tok('a'), tok('b'),
	)), 0o600)
	t.Setenv("AGED_CONFIG", cfgPath)
	t.Setenv("AGED_ADDR", "127.0.0.1:0")

	aliceDir := filepath.Join(baseSecretsDir, "alice")
	bobDir := filepath.Join(baseSecretsDir, "bob")
	os.MkdirAll(aliceDir, 0o700)
	os.MkdirAll(bobDir, 0o700)
	putRawSecret(t, aliceDir, "alice-secret", oldID.Recipient(), packEnvelope("alice-secret", []byte("alice-value")))
	putRawSecret(t, bobDir, "bob-secret", oldID.Recipient(), packEnvelope("bob-secret", []byte("bob-value")))

	bobSnapshotBefore := snapshotDir(t, bobDir)

	newIdentityFile, newID := newTestIdentityFile(t)
	var out bytes.Buffer
	if err := rotateIdentity(newIdentityFile, "alice", false, &out); err != nil {
		t.Fatalf("rotateIdentity: %v", err)
	}

	// Alice's secret is now decryptable with the new identity.
	aliceCiphertext, err := os.ReadFile(filepath.Join(aliceDir, "alice-secret.age"))
	if err != nil {
		t.Fatalf("read alice's migrated secret: %v", err)
	}
	plaintext, err := decryptCiphertext(aliceCiphertext, []age.Identity{newID})
	if err != nil {
		t.Fatalf("decrypt alice's secret with new identity: %v", err)
	}
	value, err := unpackEnvelope("alice-secret", plaintext)
	if err != nil || string(value) != "alice-value" {
		t.Errorf("alice's secret: got (%q, %v), want (\"alice-value\", nil)", value, err)
	}

	// Bob's directory is completely untouched.
	if snapshotDir(t, bobDir) != bobSnapshotBefore {
		t.Error("bob's secrets were modified by a rotation scoped to alice")
	}
}

func TestRotateIdentity_WarnsAboutOtherUsersStructuralProblems(t *testing.T) {
	// spec: (SUGGESTION from code review) rotate-identity should surface,
	// as a warning, a structural problem on a user OTHER than the one
	// being operated on — mirroring rotate-token's D5.3 policy — so an
	// operator gets the same signal `aged serve` would give at its own
	// startup validation, without being blocked from operating on the
	// (valid) target user.
	dir := t.TempDir()
	baseSecretsDir := filepath.Join(dir, "secrets")

	oldID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate old identity: %v", err)
	}
	identityPath := filepath.Join(dir, "old-identity.age")
	f, _ := os.OpenFile(identityPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	fmt.Fprintf(f, "# test\n%s\n", oldID)
	f.Close()

	cfgPath := filepath.Join(dir, "config.toml")
	os.WriteFile(cfgPath, []byte(fmt.Sprintf(
		"secrets_dir = %q\nidentity = %q\n[[users]]\nname = \"alice\"\ntoken = \"%s\"\n[[users]]\nname = \"-bad\"\ntoken = \"%s\"\n",
		baseSecretsDir, identityPath, tok('a'), tok('b'),
	)), 0o600)
	t.Setenv("AGED_CONFIG", cfgPath)
	t.Setenv("AGED_ADDR", "127.0.0.1:0")

	aliceDir := filepath.Join(baseSecretsDir, "alice")
	os.MkdirAll(aliceDir, 0o700)
	putRawSecret(t, aliceDir, "secret", oldID.Recipient(), packEnvelope("secret", []byte("v")))

	newIdentityFile, _ := newTestIdentityFile(t)
	var out bytes.Buffer
	if err := rotateIdentity(newIdentityFile, "alice", false, &out); err != nil {
		t.Fatalf("rotateIdentity: %v", err)
	}
	if !strings.Contains(out.String(), "-bad") {
		t.Errorf("output %q must warn naming the other user's structural problem", out.String())
	}
}
