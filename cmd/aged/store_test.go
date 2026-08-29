package main

// spec: openspec/specs/aged/spec.md

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

// testStore creates a Store backed by a temp directory with a freshly generated
// identity. The temp directory is cleaned up automatically by t.Cleanup.
func testStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	identityFile := filepath.Join(dir, "identity.age")
	f, err := os.OpenFile(identityFile, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("write identity file: %v", err)
	}
	fmt.Fprintf(f, "# test\n%s\n", id)
	f.Close()

	secretsDir := filepath.Join(dir, "secrets")
	store, err := newStore(identityFile, secretsDir)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	return store
}

func TestStore_StoreAndRetrieveRoundTrip(t *testing.T) {
	// spec: Secret Storage — Store and retrieve round-trip
	store := testStore(t)
	want := "super-secret-value"

	if err := store.setValue("my-key", want); err != nil {
		t.Fatalf("setValue: %v", err)
	}
	got, err := store.getValue("my-key")
	if err != nil {
		t.Fatalf("getValue: %v", err)
	}
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestStore_OverwriteExistingSecret(t *testing.T) {
	// spec: Secret Storage — Overwrite existing secret
	store := testStore(t)

	if err := store.setValue("key", "first"); err != nil {
		t.Fatalf("setValue first: %v", err)
	}
	if err := store.setValue("key", "second"); err != nil {
		t.Fatalf("setValue second: %v", err)
	}
	got, err := store.getValue("key")
	if err != nil {
		t.Fatalf("getValue: %v", err)
	}
	if got != "second" {
		t.Errorf("got %q, want %q", got, "second")
	}
}

func TestStore_RetrieveNonExistentSecret(t *testing.T) {
	// spec: Secret Retrieval — Retrieve non-existent secret
	store := testStore(t)

	_, err := store.getValue("does-not-exist")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestStore_DeleteExistingSecret(t *testing.T) {
	// spec: Secret Deletion — Delete existing secret
	store := testStore(t)

	if err := store.setValue("to-delete", "value"); err != nil {
		t.Fatalf("setValue: %v", err)
	}
	if err := store.removeValue("to-delete"); err != nil {
		t.Fatalf("removeValue: %v", err)
	}
	_, err := store.getValue("to-delete")
	if !isNotFound(err) {
		t.Errorf("expected not-found error after delete, got %v", err)
	}
}

func TestStore_DeleteNonExistentSecret(t *testing.T) {
	// spec: Secret Deletion — Delete non-existent secret
	store := testStore(t)

	err := store.removeValue("ghost")
	if !isNotFound(err) {
		t.Errorf("expected not-found error, got %v", err)
	}
}

func TestStore_ListPopulatedStore(t *testing.T) {
	// spec: Secret Listing — List populated store
	store := testStore(t)

	for _, name := range []string{"alpha", "beta", "gamma"} {
		if err := store.setValue(name, name+"-val"); err != nil {
			t.Fatalf("setValue %s: %v", name, err)
		}
	}

	names, err := store.listNames()
	if err != nil {
		t.Fatalf("listNames: %v", err)
	}
	if len(names) != 3 {
		t.Errorf("got %d names, want 3: %v", len(names), names)
	}
	for _, want := range []string{"alpha", "beta", "gamma"} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("name %q missing from list %v", want, names)
		}
	}
}

func TestStore_ListEmptyStore(t *testing.T) {
	// spec: Secret Listing — List empty store
	store := testStore(t)

	names, err := store.listNames()
	if err != nil {
		t.Fatalf("listNames: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("expected empty list, got %v", names)
	}
}

func TestStore_PublicKey(t *testing.T) {
	// spec: Public Key Endpoint — Retrieve public key
	store := testStore(t)

	pk := store.publicKey()
	if !strings.HasPrefix(pk, "age1") {
		t.Errorf("public key %q does not start with age1", pk)
	}
}

func TestStore_TrailingNewlineStripped(t *testing.T) {
	// spec: Secret Retrieval — trailing newline stripped
	store := testStore(t)

	// Simulate a value written with a trailing newline (e.g. from stdin pipe)
	raw := "token-value\n"
	f, _ := os.OpenFile(filepath.Join(store.secretsDir, "nl-key.age"),
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	w, _ := age.Encrypt(f, store.identity.Recipient())
	w.Write([]byte(raw))
	w.Close()
	f.Close()

	got, err := store.getValue("nl-key")
	if err != nil {
		t.Fatalf("getValue: %v", err)
	}
	if got != "token-value" {
		t.Errorf("got %q, want %q (trailing newline not stripped)", got, "token-value")
	}
}

// TestStore_SecretsDirectoryCreated verifies the store creates the secrets dir
// with the right permissions when it doesn't exist.
func TestStore_SecretsDirectoryCreated(t *testing.T) {
	dir := t.TempDir()

	id, _ := age.GenerateX25519Identity()
	identityFile := filepath.Join(dir, "identity.age")
	f, _ := os.OpenFile(identityFile, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	fmt.Fprintf(f, "# test\n%s\n", id)
	f.Close()

	secretsDir := filepath.Join(dir, "new", "secrets")
	_, err := newStore(identityFile, secretsDir)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}

	info, err := os.Stat(secretsDir)
	if err != nil {
		t.Fatalf("stat secrets dir: %v", err)
	}
	if !info.IsDir() {
		t.Error("secrets path is not a directory")
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("secrets dir mode %o, want 0700", info.Mode().Perm())
	}
}

// isNotFound returns true if err wraps fs.ErrNotExist.
func isNotFound(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}
