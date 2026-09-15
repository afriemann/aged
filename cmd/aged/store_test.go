package main

// spec: openspec/specs/aged/spec.md
// spec: openspec/changes/client-side-encryption/specs/aged/spec.md

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

// testStore creates a Store backed by a temp directory. The server-side
// Store holds no identity and performs no crypto — it is an opaque
// ciphertext blob store. The temp directory is cleaned up automatically by
// t.Cleanup.
func testStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	secretsDir := filepath.Join(dir, "secrets")
	store, err := newStore(secretsDir)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	return store
}

// testCiphertext returns a valid age v1 ciphertext for plaintext, encrypted
// to a freshly generated throwaway identity's recipient. Store performs no
// decryption, so most Store-level tests only need bytes that satisfy the
// magic-prefix validation; testCiphertextFor below is used when a test needs
// to control (or later decrypt with) a specific identity.
func testCiphertext(t *testing.T, plaintext string) []byte {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return testCiphertextFor(t, id.Recipient(), plaintext)
}

// testCiphertextFor encrypts plaintext to the given recipient.
func testCiphertextFor(t *testing.T, recipient age.Recipient, plaintext string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		t.Fatalf("age.Encrypt: %v", err)
	}
	if _, err := io.WriteString(w, plaintext); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close age writer: %v", err)
	}
	return buf.Bytes()
}

func TestStore_StoreAndRetrieveRoundTrip(t *testing.T) {
	// spec: Secret Storage — Store and retrieve round-trip
	store := testStore(t)
	want := testCiphertext(t, "super-secret-value")

	if err := store.setValue("my-key", want); err != nil {
		t.Fatalf("setValue: %v", err)
	}
	got, err := store.getValue("my-key")
	if err != nil {
		t.Fatalf("getValue: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestStore_OverwriteExistingSecret(t *testing.T) {
	// spec: Secret Storage — Overwrite existing secret
	store := testStore(t)

	if err := store.setValue("key", testCiphertext(t, "first")); err != nil {
		t.Fatalf("setValue first: %v", err)
	}
	second := testCiphertext(t, "second")
	if err := store.setValue("key", second); err != nil {
		t.Fatalf("setValue second: %v", err)
	}
	got, err := store.getValue("key")
	if err != nil {
		t.Fatalf("getValue: %v", err)
	}
	if !bytes.Equal(got, second) {
		t.Errorf("got %q, want %q", got, second)
	}
}

func TestStore_RetrieveExistingSecret(t *testing.T) {
	// spec: Secret Retrieval — Retrieve existing secret
	store := testStore(t)
	want := testCiphertext(t, "value")
	if err := store.setValue("key", want); err != nil {
		t.Fatalf("setValue: %v", err)
	}

	got, err := store.getValue("key")
	if err != nil {
		t.Fatalf("getValue: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
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

func TestStore_FailedWriteLeavesPreviousValueIntact(t *testing.T) {
	// spec: Secret Storage — Failed write leaves the previous value intact
	store := testStore(t)
	original := testCiphertext(t, "original")
	if err := store.setValue("key", original); err != nil {
		t.Fatalf("setValue: %v", err)
	}

	// Make the namespace directory read-only so the atomic write's temp file
	// creation fails.
	if err := chmodDir(store.secretsDir, 0o500); err != nil {
		t.Fatalf("chmod secrets dir: %v", err)
	}
	t.Cleanup(func() { chmodDir(store.secretsDir, 0o700) })

	err := store.setValue("key", testCiphertext(t, "new-value"))
	if err == nil {
		t.Fatal("expected error when secrets dir is read-only, got nil")
	}

	chmodDir(store.secretsDir, 0o700)
	got, readErr := store.getValue("key")
	if readErr != nil {
		t.Fatalf("getValue: %v", readErr)
	}
	if !bytes.Equal(got, original) {
		t.Error("previous value was modified by the failed write")
	}
}

func TestStore_DeleteExistingSecret(t *testing.T) {
	// spec: Secret Deletion — Delete existing secret
	store := testStore(t)

	if err := store.setValue("to-delete", testCiphertext(t, "value")); err != nil {
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
		if err := store.setValue(name, testCiphertext(t, name+"-val")); err != nil {
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

func TestStore_ValidAgeFormattedUploadAccepted(t *testing.T) {
	// spec: Ciphertext Format Validation — Valid age-formatted upload accepted
	store := testStore(t)

	if err := store.setValue("key", testCiphertext(t, "value")); err != nil {
		t.Errorf("setValue: %v", err)
	}
}

func TestStore_NonAgeContentRejected(t *testing.T) {
	// spec: Ciphertext Format Validation — Non-age content rejected
	store := testStore(t)

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"plaintext from a pre-change client", []byte("plain-old-secret-value")},
		{"empty body", []byte{}},
		{"garbage bytes", []byte{0x00, 0x01, 0x02}},
		{"almost-magic but wrong", []byte("age-encryption.org/v2\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := store.setValue("key", tc.data)
			if !errors.Is(err, errInvalidFormat) {
				t.Errorf("setValue(%q): got err %v, want errInvalidFormat", tc.data, err)
			}
		})
	}
}

// TestStore_SecretsDirectoryCreated verifies the store creates the secrets dir
// with the right permissions when it doesn't exist.
func TestStore_SecretsDirectoryCreated(t *testing.T) {
	dir := t.TempDir()
	secretsDir := filepath.Join(dir, "new", "secrets")

	store, err := newStore(secretsDir)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	_ = store

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
