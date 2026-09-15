package main

// spec: openspec/changes/client-side-encryption/specs/aged/spec.md

import (
	"os"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	// spec: Secret Storage — Failed write leaves the previous value intact
	t.Run("successful write", func(t *testing.T) {
		dir := t.TempDir()
		path := dir + "/secret.age"

		if err := writeFileAtomic(path, []byte("first")); err != nil {
			t.Fatalf("writeFileAtomic: %v", err)
		}

		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read back: %v", err)
		}
		if string(got) != "first" {
			t.Errorf("got %q, want %q", got, "first")
		}
		assertNoStrayTempFiles(t, dir)
	})

	t.Run("overwrite existing file", func(t *testing.T) {
		dir := t.TempDir()
		path := dir + "/secret.age"

		if err := writeFileAtomic(path, []byte("first")); err != nil {
			t.Fatalf("writeFileAtomic first: %v", err)
		}
		if err := writeFileAtomic(path, []byte("second")); err != nil {
			t.Fatalf("writeFileAtomic second: %v", err)
		}

		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read back: %v", err)
		}
		if string(got) != "second" {
			t.Errorf("got %q, want %q", got, "second")
		}
		assertNoStrayTempFiles(t, dir)
	})

	t.Run("failed write leaves original file and no temp file behind", func(t *testing.T) {
		dir := t.TempDir()
		path := dir + "/secret.age"

		if err := writeFileAtomic(path, []byte("original")); err != nil {
			t.Fatalf("writeFileAtomic original: %v", err)
		}

		// Make the directory read-only so staging the temp file fails.
		if err := chmodDir(dir, 0o500); err != nil {
			t.Fatalf("chmod dir: %v", err)
		}
		t.Cleanup(func() { chmodDir(dir, 0o700) })

		err := writeFileAtomic(path, []byte("new-value"))
		if err == nil {
			t.Fatal("expected error when directory is read-only, got nil")
		}

		chmodDir(dir, 0o700)
		got, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read back: %v", readErr)
		}
		if string(got) != "original" {
			t.Errorf("original file was modified: got %q, want %q", got, "original")
		}
		assertNoStrayTempFiles(t, dir)
	})
}
