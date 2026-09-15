package main

// spec: openspec/changes/client-side-encryption/specs/aged/spec.md

import "testing"

func TestEnvelope(t *testing.T) {
	t.Run("Matching name round-trips", func(t *testing.T) {
		env := packEnvelope("ha/token", []byte("secret-value"))
		got, err := unpackEnvelope("ha/token", env)
		if err != nil {
			t.Fatalf("unpackEnvelope: %v", err)
		}
		if string(got) != "secret-value" {
			t.Errorf("got %q, want %q", got, "secret-value")
		}
	})

	t.Run("Swapped ciphertext files are detected", func(t *testing.T) {
		envA := packEnvelope("a", []byte("value-a"))
		// Simulate file "b" having been swapped with file "a" on disk: the
		// decrypted plaintext (envA) is presented but requested under name "b".
		_, err := unpackEnvelope("b", envA)
		if err == nil {
			t.Fatal("expected error for name mismatch, got nil")
		}
	})

	t.Run("Malformed envelope rejected", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			input []byte
		}{
			{"missing prefix entirely", []byte("just some plaintext")},
			{"prefix but no newline after name", []byte("aged-v1\nname: foo")},
			{"empty", []byte("")},
			{"prefix only", []byte("aged-v1\nname: ")},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := unpackEnvelope("foo", tc.input)
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			})
		}
	})

	t.Run("value bytes are not trimmed", func(t *testing.T) {
		env := packEnvelope("k", []byte("value-with-trailing-byte\n"))
		got, err := unpackEnvelope("k", env)
		if err != nil {
			t.Fatalf("unpackEnvelope: %v", err)
		}
		if string(got) != "value-with-trailing-byte\n" {
			t.Errorf("got %q, want trailing byte preserved", got)
		}
	})

	t.Run("value bytes may be binary", func(t *testing.T) {
		binVal := []byte{0x00, 0x01, 0xff, 0x0a, 0x00}
		env := packEnvelope("bin", binVal)
		got, err := unpackEnvelope("bin", env)
		if err != nil {
			t.Fatalf("unpackEnvelope: %v", err)
		}
		if string(got) != string(binVal) {
			t.Errorf("got %v, want %v", got, binVal)
		}
	})
}
