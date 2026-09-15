package main

import (
	"os"
	"strings"
	"testing"
)

// chmodDir changes the permissions of a directory (test helper, distinct from
// per-secret-file 0600 handling elsewhere).
func chmodDir(dir string, mode os.FileMode) error {
	return os.Chmod(dir, mode)
}

// assertNoStrayTempFiles fails the test if any writeFileAtomic staging file
// (".tmp-*") remains in dir.
func assertNoStrayTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("stray temp file left behind: %s", e.Name())
		}
	}
}
