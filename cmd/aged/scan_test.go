package main

// spec: openspec/changes/multi-user-support/specs/aged/spec.md

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanSecretsDir(t *testing.T) {
	t.Run("loose secret file blocks startup", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "orphan.age"), []byte("age-encryption.org/v1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		var warnings strings.Builder
		err := scanSecretsDir(dir, []string{"alice"}, &warnings)
		if err == nil {
			t.Fatal("want an error for a loose .age file, got nil")
		}
		if !strings.Contains(err.Error(), "orphan.age") {
			t.Errorf("error %q does not name the offending file", err.Error())
		}
		if !strings.Contains(err.Error(), "alice") {
			t.Errorf("error %q does not list configured user names", err.Error())
		}
	})

	t.Run("unexpected non-directory entry blocks startup", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "README"), []byte("notes"), 0o600); err != nil {
			t.Fatal(err)
		}
		var warnings strings.Builder
		err := scanSecretsDir(dir, []string{"alice"}, &warnings)
		if err == nil {
			t.Fatal("want an error for an unexpected non-directory entry, got nil")
		}
		if !strings.Contains(err.Error(), "README") {
			t.Errorf("error %q does not name the offending entry", err.Error())
		}
	})

	t.Run("unknown subdirectory warns but does not block startup", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "orphaned-user"), 0o700); err != nil {
			t.Fatal(err)
		}
		var warnings strings.Builder
		err := scanSecretsDir(dir, []string{"alice"}, &warnings)
		if err != nil {
			t.Fatalf("unknown directory must not block startup, got error: %v", err)
		}
		if !strings.Contains(warnings.String(), "orphaned-user") {
			t.Errorf("want a warning naming orphaned-user, got %q", warnings.String())
		}
	})

	t.Run("known user directory produces no warning", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "alice"), 0o700); err != nil {
			t.Fatal(err)
		}
		var warnings strings.Builder
		if err := scanSecretsDir(dir, []string{"alice"}, &warnings); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if warnings.Len() != 0 {
			t.Errorf("want no warning for a known user directory, got %q", warnings.String())
		}
	})

	t.Run("absent secrets_dir is not an error", func(t *testing.T) {
		var warnings strings.Builder
		dir := filepath.Join(t.TempDir(), "does-not-exist")
		if err := scanSecretsDir(dir, []string{"alice"}, &warnings); err != nil {
			t.Fatalf("absent secrets_dir must not be an error (fresh install), got: %v", err)
		}
	})

	t.Run("dangling symlink is an offender", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Symlink(filepath.Join(dir, "does-not-exist-target"), filepath.Join(dir, "dangling")); err != nil {
			t.Fatal(err)
		}
		var warnings strings.Builder
		err := scanSecretsDir(dir, []string{"alice"}, &warnings)
		if err == nil {
			t.Fatal("want an error for a dangling symlink, got nil")
		}
	})

	t.Run("aggregates multiple offenders in one error", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "a.age"), []byte("age-encryption.org/v1\n"), 0o600)
		os.WriteFile(filepath.Join(dir, "b.age"), []byte("age-encryption.org/v1\n"), 0o600)
		var warnings strings.Builder
		err := scanSecretsDir(dir, []string{"alice"}, &warnings)
		if err == nil {
			t.Fatal("want an aggregated error")
		}
		if !strings.Contains(err.Error(), "a.age") || !strings.Contains(err.Error(), "b.age") {
			t.Errorf("error %q must name both offenders", err.Error())
		}
	})
}
