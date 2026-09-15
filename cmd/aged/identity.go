package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
)

// initIdentity generates a new X25519 age identity and writes it to disk.
// This is exclusively a client-side operation: the generated identity is
// used by get/set/pubkey/rotate-identity to encrypt and decrypt secret
// values on the machine it's run on. aged serve neither generates nor
// requires an identity.
func initIdentity() error {
	path := loadConfig().Identity
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("identity file already exists at %s", path)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("generate identity: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("write identity file: %w", err)
	}
	defer f.Close()

	fmt.Fprintf(f, "# aged identity — keep this file secret\n%s\n", id)
	fmt.Printf("public key:  %s\n", id.Recipient())
	fmt.Printf("identity:    %s\n", path)
	return nil
}

// loadIdentities reads and parses every identity from path. Used by get,
// set, pubkey, and rotate-identity, all of which need the caller's own
// locally-held identity/identities — never anything server-held.
func loadIdentities(path string) ([]age.Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity: %w", err)
	}
	ids, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse identity: %w", err)
	}
	return ids, nil
}
