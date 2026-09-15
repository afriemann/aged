package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// writeFileAtomic stages data to a temporary file in the same directory as
// path (guaranteeing the same filesystem so os.Rename is atomic), sets it to
// mode 0600, then renames it into place. A failure at any point before the
// rename leaves any previously stored file at path unchanged and removes the
// staged temp file. Follows the same pattern as rotate.go's config rewrite.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("stage temp file: %w", err)
	}
	defer tmp.Close()           // fd cleanup on all error paths; double-close after explicit Close is harmless
	defer os.Remove(tmp.Name()) // no-op after successful rename; cleans up on any failure

	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("set temp file permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}
