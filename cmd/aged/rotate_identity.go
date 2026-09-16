package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
)

// rotateIdentityCorruptStagedFileHook, when non-nil, is invoked immediately
// after a secret's re-encrypted bytes are staged, before verification. It
// exists solely so tests can deterministically exercise the verification
// failure path without needing genuine disk corruption. Always nil in
// production.
var rotateIdentityCorruptStagedFileHook func(stagedPath string) error

// rotateSummary reports dry-run outcome counts.
type rotateSummary struct {
	migrated int
	failed   int
}

// selectRotateIdentityTarget resolves which configured user rotate-identity
// should operate on, using the same required-when-ambiguous policy as
// rotate-token's target selection (see design.md D6.1). Refusing when
// ambiguous is essential: without it, an omitted --user would resolve the
// shared, multi-tenant secrets base directly and attempt to re-encrypt every
// tenant's secrets to one identity in a single fleet-wide operation.
func selectRotateIdentityTarget(users []UserConfig, username string) (string, error) {
	names := make([]string, len(users))
	for i, u := range users {
		names[i] = u.Name
	}
	sorted := append([]string{}, names...)
	sort.Strings(sorted)

	if username == "" {
		switch len(names) {
		case 0:
			return "", errors.New("no users are configured; check the config file or AGED_USERNAME/AGED_TOKEN")
		case 1:
			return names[0], nil
		default:
			return "", fmt.Errorf(
				"more than one user is configured; specify --user <name> (configured users: %s)",
				strings.Join(sorted, ", "),
			)
		}
	}
	for _, n := range names {
		if n == username {
			return username, nil
		}
	}
	return "", fmt.Errorf("no configured user named %q (configured users: %s)", username, strings.Join(sorted, ", "))
}

// rotateIdentity re-encrypts every secret in one configured user's own
// secrets subtree from the currently configured identity to the identity in
// newIdentityPath, per design.md D7-D9: it either succeeds completely,
// leaving that subtree replaced and its previous contents kept as a
// timestamped backup, or aborts leaving the subtree completely untouched.
//
// username selects which user's subtree to operate on: required when more
// than one user is configured, auto-selected (and always printed) when
// exactly one is (see design.md D6.1). The command only ever touches
// secrets_dir/<name>/ — the shared multi-tenant base directory itself is
// never re-encrypted as a whole.
func rotateIdentity(newIdentityPath string, username string, dryRun bool, out io.Writer) error {
	cfg := loadConfig()

	if !dryRun {
		if err := refuseIfServerRunning(cfg.Addr); err != nil {
			return err
		}
	}

	users, _, err := resolveUsers(cfg)
	if err != nil {
		return err
	}
	selectedUser, err := selectRotateIdentityTarget(users, username)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "operating on user %q\n", selectedUser)

	// Surface (without blocking on) a validation problem on a user OTHER
	// than the one being operated on — mirroring rotate-token's D5.3
	// policy — so the operator gets the same signal aged serve's own
	// startup validation would give, without being blocked from operating
	// on a target user whose own configuration is fine.
	for i, u := range users {
		if u.Name == selectedUser {
			continue
		}
		for _, p := range validateUserSet([]UserConfig{users[i]}) {
			fmt.Fprintf(out, "warning: %s\n", p.message)
		}
	}

	effectiveRoot := filepath.Join(cfg.SecretsDir, selectedUser)

	oldIdentities, err := loadIdentities(cfg.Identity)
	if err != nil {
		return fmt.Errorf("load current identity: %w", err)
	}

	newIdentity, err := loadSingleNewIdentity(newIdentityPath)
	if err != nil {
		return err
	}

	store, err := newStore(effectiveRoot)
	if err != nil {
		return fmt.Errorf("open secrets store: %w", err)
	}
	names, err := store.listNames()
	if err != nil {
		return fmt.Errorf("list secrets: %w", err)
	}

	if dryRun {
		summary, err := dryRunRotate(store, names, oldIdentities, newIdentity)
		fmt.Fprintf(out, "dry run: %d secret(s) would migrate successfully, %d would fail\n",
			summary.migrated, summary.failed)
		return err
	}

	return performRotate(effectiveRoot, store, names, oldIdentities, newIdentity, out)
}

// refuseIfServerRunning refuses to proceed if addr appears to already be
// bound — a proxy for detecting that aged serve is currently running. It is
// a guard rail, not a lock: see design.md D7 for its documented limits
// (false positives from an unrelated process or EACCES, a false negative
// from a server on another host, and an inherent TOCTOU window before the
// caller starts work).
func refuseIfServerRunning(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("refusing to run: %s appears to already be in use — "+
			"stop `aged serve` before rotating (or pass --dry-run): %w", addr, err)
	}
	return ln.Close()
}

// loadSingleNewIdentity parses newIdentityPath and requires it to contain
// exactly one identity: re-encryption has exactly one target recipient, so
// an ambiguous file is rejected rather than silently picking one or
// encrypting to multiple (an explicit non-goal).
func loadSingleNewIdentity(path string) (*age.X25519Identity, error) {
	ids, err := loadIdentities(path)
	if err != nil {
		return nil, fmt.Errorf("load new identity: %w", err)
	}
	if len(ids) != 1 {
		return nil, fmt.Errorf("new identity file must contain exactly one identity, found %d", len(ids))
	}
	x25519, ok := ids[0].(*age.X25519Identity)
	if !ok {
		return nil, fmt.Errorf("new identity must be an X25519 key")
	}
	return x25519, nil
}

// migrateOneSecret decrypts the named secret with oldIdentities and returns
// its normalised plaintext, ready for re-encryption: already-bound secrets
// matching name are returned unchanged; unbound (legacy, pre-change) secrets
// are wrapped in the name-binding envelope; a secret bound to a different
// name (misfiled) aborts by returning an error, as does a name that fails
// the same validation gate enforced everywhere else.
func migrateOneSecret(store *Store, name string, oldIdentities []age.Identity) ([]byte, error) {
	if !validName(name) {
		return nil, fmt.Errorf("secret name %q derived from disk is invalid; refusing to migrate", name)
	}

	ciphertext, err := store.getValue(name)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", name, err)
	}
	plaintext, err := decryptCiphertext(ciphertext, oldIdentities)
	if err != nil {
		return nil, fmt.Errorf("decrypt %q with current identity: %w", name, err)
	}

	_, unpackErr := unpackEnvelope(name, plaintext)
	switch {
	case unpackErr == nil:
		// Already correctly bound to this name — carry the envelope as-is.
		return plaintext, nil
	case errors.Is(unpackErr, errEnvelopeNameMismatch):
		return nil, fmt.Errorf("secret %q is misfiled (its envelope is bound to a different name): %w", name, unpackErr)
	default:
		// errEnvelopeMalformed: an unbound, pre-change (legacy) secret.
		return packEnvelope(name, plaintext), nil
	}
}

// dryRunRotate performs the full decrypt/normalise/encrypt/verify pipeline
// entirely in memory, writing nothing to disk, and reports success/failure
// counts. An abort condition (invalid name, misfiled secret) still aborts
// the entire dry run immediately, exactly as a real run would.
func dryRunRotate(store *Store, names []string, oldIdentities []age.Identity, newIdentity *age.X25519Identity) (rotateSummary, error) {
	var summary rotateSummary
	for _, name := range names {
		normalized, err := migrateOneSecret(store, name, oldIdentities)
		if err != nil {
			return summary, err
		}

		ciphertext, err := encryptTo(newIdentity.Recipient(), normalized)
		if err != nil {
			zeroBytes(normalized)
			summary.failed++
			continue
		}
		verified, err := decryptCiphertext(ciphertext, []age.Identity{newIdentity})
		ok := err == nil && bytes.Equal(verified, normalized)
		zeroBytes(normalized)
		zeroBytes(verified)
		if !ok {
			summary.failed++
			continue
		}
		summary.migrated++
	}
	return summary, nil
}

// performRotate runs the real (non-dry-run) rotation: every secret is
// migrated into a staging directory and individually verified; only if
// every one succeeds is the live secrets directory replaced.
func performRotate(secretsDir string, store *Store, names []string, oldIdentities []age.Identity, newIdentity *age.X25519Identity, out io.Writer) error {
	backupDir := secretsDir + ".old-" + time.Now().UTC().Format("20060102T150405Z")
	if _, err := os.Stat(backupDir); err == nil {
		return fmt.Errorf("backup directory %s already exists; aborting", backupDir)
	}

	stagingDir, err := os.MkdirTemp(filepath.Dir(secretsDir), filepath.Base(secretsDir)+".rotating-*")
	if err != nil {
		return fmt.Errorf("create staging directory: %w", err)
	}
	// No-ops after a successful swap below, since stagingDir no longer
	// exists at that path; cleans up on every abort path.
	defer os.RemoveAll(stagingDir)
	if err := os.Chmod(stagingDir, 0o700); err != nil {
		return fmt.Errorf("set staging directory permissions: %w", err)
	}

	for _, name := range names {
		normalized, err := migrateOneSecret(store, name, oldIdentities)
		if err != nil {
			return err
		}

		ciphertext, err := encryptTo(newIdentity.Recipient(), normalized)
		if err != nil {
			return fmt.Errorf("re-encrypt %q: %w", name, err)
		}

		stagedPath := filepath.Join(stagingDir, filepath.FromSlash(name)+".age")
		if err := os.MkdirAll(filepath.Dir(stagedPath), 0o700); err != nil {
			return fmt.Errorf("create staging namespace dir for %q: %w", name, err)
		}
		if err := writeFileAtomic(stagedPath, ciphertext); err != nil {
			return fmt.Errorf("stage %q: %w", name, err)
		}

		if rotateIdentityCorruptStagedFileHook != nil {
			if err := rotateIdentityCorruptStagedFileHook(stagedPath); err != nil {
				return err
			}
		}

		stagedCiphertext, err := os.ReadFile(stagedPath)
		if err != nil {
			return fmt.Errorf("read back staged %q: %w", name, err)
		}
		verified, err := decryptCiphertext(stagedCiphertext, []age.Identity{newIdentity})
		ok := err == nil && bytes.Equal(verified, normalized)
		zeroBytes(normalized)
		zeroBytes(verified)
		if !ok {
			return fmt.Errorf("verification failed for %q: staged content does not round-trip", name)
		}
	}

	if err := os.Rename(secretsDir, backupDir); err != nil {
		return fmt.Errorf("rename secrets directory to backup: %w", err)
	}
	if err := os.Rename(stagingDir, secretsDir); err != nil {
		fmt.Fprintf(out, "CRITICAL: the swap failed after the backup was created.\n"+
			"secrets/ is currently absent. Recovery — choose one:\n"+
			"  complete the rotation: mv %q %q\n"+
			"  abandon it (keep the old identity): mv %q %q\n",
			stagingDir, secretsDir, backupDir, secretsDir)
		return fmt.Errorf("rename staging directory into place: %w", err)
	}

	fmt.Fprintf(out, "rotated %d secret(s)\n", len(names))
	fmt.Fprintf(out, "previous secrets kept at: %s\n", backupDir)
	fmt.Fprintln(out, "verify `aged get` works from a real client machine using the new identity, "+
		"then delete the backup directory and securely destroy the old identity file")
	return nil
}

// encryptTo encrypts plaintext to recipient using the age v1 format.
func encryptTo(recipient age.Recipient, plaintext []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// zeroBytes overwrites b with zeros in place. Best-effort hygiene only —
// Go's garbage collector may already have copied the underlying data
// elsewhere (e.g. during a slice append or GC compaction), so this is not a
// guarantee that the plaintext is unrecoverable in memory, only a reduction
// of the window during which it remains in this particular buffer.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
