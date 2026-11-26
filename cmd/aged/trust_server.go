package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	// reservedNamespace is the first name segment reserved for aged's own
	// bookkeeping; validName rejects it so no /secrets route can touch it.
	reservedNamespace = ".aged"

	// trustHeader carries the manifest version a secret upload was encrypted
	// against; trustNone means the client saw no manifest.
	trustHeader = "X-Aged-Trust"
	trustNone   = "none"
)

var (
	errTrustMoved     = errors.New("trust manifest changed")
	errTrustRequired  = errors.New("trust manifest version header required")
	errSecretChanged  = errors.New("secret changed since it was read")
	errPreconditionNA = errors.New("If-Match or If-None-Match header required")
)

// blobVersion is the opaque version of a stored blob: the quoted SHA-256 hex
// of its bytes, used as the HTTP ETag. The server never decrypts, so a
// content hash is the only version it can compute.
func blobVersion(data []byte) string {
	sum := sha256.Sum256(data)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

func sameVersion(a, b string) bool {
	return strings.Trim(a, `"`) == strings.Trim(b, `"`)
}

func isReservedName(name string) bool {
	first, _, _ := strings.Cut(name, "/")
	return strings.EqualFold(first, reservedNamespace)
}

func (s *Store) trustPath() string {
	return filepath.Join(s.secretsDir, reservedNamespace, "trust")
}

// getTrust returns the stored manifest blob, or fs.ErrNotExist.
func (s *Store) getTrust() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readTrustLocked()
}

func (s *Store) readTrustLocked() ([]byte, error) {
	path := s.trustPath()
	if err := s.verifyExistingWithinRoot(path); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

// putTrust replaces the manifest blob. Exactly one of ifNoneMatch ("*") and
// ifMatch must be given: create-only, or compare-and-swap on the version.
// It returns the new version.
func (s *Store) putTrust(data []byte, ifMatch string, ifNoneMatch string) (string, error) {
	if !strings.HasPrefix(string(data), ageV1Magic) {
		return "", errInvalidFormat
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cur, err := s.readTrustLocked()
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	switch {
	case ifNoneMatch == "*":
		if exists {
			return "", errTrustMoved
		}
	case ifMatch != "":
		if !exists || !sameVersion(ifMatch, blobVersion(cur)) {
			return "", errTrustMoved
		}
	default:
		return "", errPreconditionNA
	}
	if err := s.writeWithinRoot(s.trustPath(), data); err != nil {
		return "", err
	}
	return blobVersion(data), nil
}

// setValueGuarded is setValue gated on the caller's view of the world: the
// manifest version its recipients came from, and optionally the stored
// secret it is replacing. Check and write happen under the store lock so a
// concurrent manifest or secret write cannot slip between them.
func (s *Store) setValueGuarded(name string, data []byte, trustVersion, ifMatch string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	manifest, err := s.readTrustLocked()
	switch {
	case err == nil:
		if trustVersion == "" {
			return errTrustRequired
		}
		if !sameVersion(trustVersion, blobVersion(manifest)) {
			return errTrustMoved
		}
	case errors.Is(err, fs.ErrNotExist):
		if trustVersion != "" && trustVersion != trustNone {
			return errTrustMoved
		}
	default:
		return err
	}

	if ifMatch != "" {
		cur, err := s.getValue(name)
		if err != nil || !sameVersion(ifMatch, blobVersion(cur)) {
			return errSecretChanged
		}
	}
	return s.setValue(name, data)
}

// preconditionStatus maps a precondition error to its HTTP status, or 0.
func preconditionStatus(err error) int {
	switch {
	case errors.Is(err, errTrustMoved), errors.Is(err, errSecretChanged):
		return http.StatusPreconditionFailed
	case errors.Is(err, errTrustRequired), errors.Is(err, errPreconditionNA):
		return http.StatusPreconditionRequired
	}
	return 0
}

func handleTrustGet(w http.ResponseWriter, _ *http.Request, t *tenant) {
	blob, err := t.store.getTrust()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		log.Println("get trust error:", err)
		return
	}
	w.Header().Set("ETag", blobVersion(blob))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(blob)
}

func handleTrustPut(w http.ResponseWriter, r *http.Request, t *tenant) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	version, err := t.store.putTrust(body, r.Header.Get("If-Match"), r.Header.Get("If-None-Match"))
	if err != nil {
		if errors.Is(err, errInvalidFormat) {
			http.Error(w, "invalid manifest format", http.StatusBadRequest)
			return
		}
		if status := preconditionStatus(err); status != 0 {
			http.Error(w, http.StatusText(status), status)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		log.Println("put trust error:", fmt.Errorf("store manifest: %w", err))
		return
	}
	w.Header().Set("ETag", version)
	w.WriteHeader(http.StatusNoContent)
}
