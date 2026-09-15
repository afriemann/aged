package main

// spec: openspec/changes/client-side-encryption/specs/aged/spec.md

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

// testClientEnv wires up a running test server (identical to testServer) plus
// a client config pointing at it with a freshly generated identity file at
// the given path. Returns the identity for tests that need to construct
// their own fixtures.
func testClientEnv(t *testing.T, identityPath string) *age.X25519Identity {
	t.Helper()
	srv, _ := testServer(t)

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	f, err := os.OpenFile(identityPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("write identity file: %v", err)
	}
	fmt.Fprintf(f, "# test\n%s\n", id)
	f.Close()

	t.Setenv("AGED_SERVER_URL", srv.URL)
	t.Setenv("AGED_TOKEN", testToken)
	t.Setenv("AGED_IDENTITY", identityPath)
	t.Setenv("AGED_CONFIG", "/tmp/definitely-absent-aged-test.toml")

	return id
}

func TestClientSet(t *testing.T) {
	t.Run("Set encrypts before upload", func(t *testing.T) {
		dir := t.TempDir()
		id := testClientEnv(t, filepath.Join(dir, "identity.age"))

		withStdin(t, "my-plaintext-value", func() {
			if err := set("some/key"); err != nil {
				t.Fatalf("set: %v", err)
			}
		})

		// Read back the stored ciphertext directly via the server's own
		// store to confirm the server only ever saw ciphertext.
		stored := fetchRawStoredBytes(t, "some/key")
		if !bytes.HasPrefix(stored, []byte(ageV1Magic)) {
			t.Fatalf("stored value does not look like age ciphertext: %q", stored[:min(len(stored), 40)])
		}
		if bytes.Contains(stored, []byte("my-plaintext-value")) {
			t.Error("plaintext value found unencrypted in stored ciphertext")
		}

		got, err := decryptWithIdentity(t, id, stored, "some/key")
		if err != nil {
			t.Fatalf("decrypt stored ciphertext: %v", err)
		}
		if got != "my-plaintext-value" {
			t.Errorf("got %q, want %q", got, "my-plaintext-value")
		}
	})

	t.Run("Trailing newline stripped exactly once", func(t *testing.T) {
		dir := t.TempDir()
		id := testClientEnv(t, filepath.Join(dir, "identity.age"))

		withStdin(t, "value-with-newline\n", func() {
			if err := set("key"); err != nil {
				t.Fatalf("set: %v", err)
			}
		})

		stored := fetchRawStoredBytes(t, "key")
		got, err := decryptWithIdentity(t, id, stored, "key")
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if got != "value-with-newline" {
			t.Errorf("got %q, want trailing newline stripped exactly once", got)
		}
	})

	t.Run("Only one of several trailing newlines is stripped", func(t *testing.T) {
		dir := t.TempDir()
		id := testClientEnv(t, filepath.Join(dir, "identity.age"))

		withStdin(t, "value\n\n\n", func() {
			if err := set("key"); err != nil {
				t.Fatalf("set: %v", err)
			}
		})

		stored := fetchRawStoredBytes(t, "key")
		got, err := decryptWithIdentity(t, id, stored, "key")
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if got != "value\n\n" {
			t.Errorf("got %q, want %q (only the last trailing newline stripped)", got, "value\n\n")
		}
	})

	t.Run("Client rejects invalid name before encrypting", func(t *testing.T) {
		dir := t.TempDir()
		testClientEnv(t, filepath.Join(dir, "identity.age"))

		// Point the server URL at an address nothing is listening on, so the
		// test fails loudly if set() ever attempts a network request.
		t.Setenv("AGED_SERVER_URL", "http://127.0.0.1:1")

		withStdin(t, "value", func() {
			err := set("../evil")
			if err == nil {
				t.Fatal("expected error for invalid name, got nil")
			}
		})
	})
}

func TestClientGet(t *testing.T) {
	t.Run("Get decrypts locally", func(t *testing.T) {
		dir := t.TempDir()
		id := testClientEnv(t, filepath.Join(dir, "identity.age"))
		storeCiphertextViaHTTP(t, id.Recipient(), "key", "the-secret-value")

		out := withStdout(t, func() {
			if err := get("key"); err != nil {
				t.Fatalf("get: %v", err)
			}
		})
		if out != "the-secret-value" {
			t.Errorf("got %q, want %q (no trailing newline)", out, "the-secret-value")
		}
	})

	t.Run("Multiple identities tried in order", func(t *testing.T) {
		dir := t.TempDir()
		identityPath := filepath.Join(dir, "identity.age")

		srv, _ := testServer(t)
		idOld, _ := age.GenerateX25519Identity()
		idNew, _ := age.GenerateX25519Identity()
		f, _ := os.OpenFile(identityPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		fmt.Fprintf(f, "# test\n%s\n%s\n", idOld, idNew)
		f.Close()

		t.Setenv("AGED_SERVER_URL", srv.URL)
		t.Setenv("AGED_TOKEN", testToken)
		t.Setenv("AGED_IDENTITY", identityPath)
		t.Setenv("AGED_CONFIG", "/tmp/definitely-absent-aged-test.toml")

		// Secret is encrypted to the second (new) identity, not the first.
		storeCiphertextViaHTTP(t, idNew.Recipient(), "key", "value-for-new-identity")

		out := withStdout(t, func() {
			if err := get("key"); err != nil {
				t.Fatalf("get: %v", err)
			}
		})
		if out != "value-for-new-identity" {
			t.Errorf("got %q, want %q", out, "value-for-new-identity")
		}
	})

	t.Run("No identity matches", func(t *testing.T) {
		dir := t.TempDir()
		testClientEnv(t, filepath.Join(dir, "identity.age"))

		otherID, _ := age.GenerateX25519Identity()
		storeCiphertextViaHTTP(t, otherID.Recipient(), "key", "not-for-you")

		err := get("key")
		if err == nil {
			t.Fatal("expected error when no identity matches, got nil")
		}
	})

	t.Run("Missing local identity", func(t *testing.T) {
		dir := t.TempDir()
		srv, _ := testServer(t)
		t.Setenv("AGED_SERVER_URL", srv.URL)
		t.Setenv("AGED_TOKEN", testToken)
		t.Setenv("AGED_IDENTITY", filepath.Join(dir, "does-not-exist.age"))
		t.Setenv("AGED_CONFIG", "/tmp/definitely-absent-aged-test.toml")

		err := get("key")
		if err == nil {
			t.Fatal("expected error when identity file is missing, got nil")
		}
	})
}

func TestClientPubkey(t *testing.T) {
	t.Run("Prints local recipient", func(t *testing.T) {
		dir := t.TempDir()
		identityPath := filepath.Join(dir, "identity.age")
		id, _ := age.GenerateX25519Identity()
		f, _ := os.OpenFile(identityPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		fmt.Fprintf(f, "# test\n%s\n", id)
		f.Close()

		t.Setenv("AGED_IDENTITY", identityPath)
		t.Setenv("AGED_CONFIG", "/tmp/definitely-absent-aged-test.toml")

		// A server that would fail the test if hit, to prove pubkey makes no
		// network call.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("unexpected network request to %s during aged pubkey", r.URL.Path)
		}))
		defer srv.Close()
		t.Setenv("AGED_SERVER_URL", srv.URL)

		out := withStdout(t, func() {
			if err := pubkey(); err != nil {
				t.Fatalf("pubkey: %v", err)
			}
		})
		if strings.TrimSpace(out) != id.Recipient().String() {
			t.Errorf("got %q, want %q", strings.TrimSpace(out), id.Recipient().String())
		}
	})

	t.Run("Prints every recipient during rotation overlap", func(t *testing.T) {
		dir := t.TempDir()
		identityPath := filepath.Join(dir, "identity.age")
		id1, _ := age.GenerateX25519Identity()
		id2, _ := age.GenerateX25519Identity()
		f, _ := os.OpenFile(identityPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		fmt.Fprintf(f, "# test\n%s\n%s\n", id1, id2)
		f.Close()

		t.Setenv("AGED_IDENTITY", identityPath)
		t.Setenv("AGED_CONFIG", "/tmp/definitely-absent-aged-test.toml")
		t.Setenv("AGED_SERVER_URL", "http://127.0.0.1:1")

		out := withStdout(t, func() {
			if err := pubkey(); err != nil {
				t.Fatalf("pubkey: %v", err)
			}
		})
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) != 2 {
			t.Fatalf("got %d lines, want 2: %q", len(lines), out)
		}
		if lines[0] != id1.Recipient().String() || lines[1] != id2.Recipient().String() {
			t.Errorf("got %v, want [%s %s]", lines, id1.Recipient(), id2.Recipient())
		}
	})
}

// --- test helpers ---

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// withStdin redirects os.Stdin to a pipe containing s for the duration of fn.
func withStdin(t *testing.T, s string, fn func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	orig := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = orig }()

	go func() {
		io.WriteString(w, s)
		w.Close()
	}()
	fn()
}

// withStdout redirects os.Stdout to a buffer for the duration of fn and
// returns everything written to it.
func withStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()
	w.Close()
	return <-done
}

// fetchRawStoredBytes retrieves whatever bytes the server actually has
// stored for name, bypassing any client-side decryption, to assert the
// server only ever sees ciphertext.
func fetchRawStoredBytes(t *testing.T, name string) []byte {
	t.Helper()
	data, status, err := requestBytes("GET", "/secrets/"+name, nil)
	if err != nil {
		t.Fatalf("fetchRawStoredBytes: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("fetchRawStoredBytes: got status %d", status)
	}
	return data
}

// decryptWithIdentity decrypts an aged-v1 enveloped ciphertext with id and
// unpacks the envelope, returning the plaintext value.
func decryptWithIdentity(t *testing.T, id *age.X25519Identity, ciphertext []byte, name string) (string, error) {
	t.Helper()
	r, err := age.Decrypt(bytes.NewReader(ciphertext), id)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return "", err
	}
	value, err := unpackEnvelope(name, buf.Bytes())
	if err != nil {
		return "", err
	}
	return string(value), nil
}

// storeCiphertextViaHTTP encrypts value (enveloped for name) to recipient and
// uploads it directly via the HTTP API, bypassing the client's own set() —
// used to set up fixtures with a specific (possibly non-default) recipient.
func storeCiphertextViaHTTP(t *testing.T, recipient age.Recipient, name, value string) {
	t.Helper()
	env := packEnvelope(name, []byte(value))
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		t.Fatalf("age.Encrypt: %v", err)
	}
	if _, err := w.Write(env); err != nil {
		t.Fatalf("write envelope: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close age writer: %v", err)
	}
	_, status, err := requestBytes("POST", "/secrets/"+name, bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("storeCiphertextViaHTTP request: %v", err)
	}
	if status != http.StatusNoContent {
		t.Fatalf("storeCiphertextViaHTTP: got status %d", status)
	}
}
