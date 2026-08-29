package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"filippo.io/age"
)

// nameRe validates each segment of a secret name (segments are split on /).
// Slashes are allowed as namespace separators; the full name is validated by validName.
var nameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]+(/[a-zA-Z0-9._-]+)*$`)

// validName returns true if name passes the regex and contains no .. segments.
// This is the single authoritative gate called by all HTTP handlers.
func validName(name string) bool {
	if !nameRe.MatchString(name) {
		return false
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." || seg == "." {
			return false
		}
	}
	return true
}

// Store holds an age identity and manages the encrypted secret files on disk.
type Store struct {
	identity   *age.X25519Identity
	secretsDir string
}

func newStore(identityFile, secretsDir string) (*Store, error) {
	data, err := os.ReadFile(identityFile)
	if err != nil {
		return nil, fmt.Errorf("read identity: %w", err)
	}

	ids, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse identity: %w", err)
	}
	if len(ids) == 0 {
		return nil, errors.New("no identities found in identity file")
	}

	id, ok := ids[0].(*age.X25519Identity)
	if !ok {
		return nil, errors.New("identity must be an X25519 key")
	}

	if err := os.MkdirAll(secretsDir, 0o700); err != nil {
		return nil, fmt.Errorf("create secrets dir: %w", err)
	}

	return &Store{identity: id, secretsDir: secretsDir}, nil
}

func (s *Store) publicKey() string { return s.identity.Recipient().String() }

// secretPath returns the absolute path for a secret file, verifying it lies
// within the secrets directory to prevent path traversal.
func (s *Store) secretPath(name string) (string, error) {
	path := filepath.Join(s.secretsDir, filepath.FromSlash(name)+".age")
	rel, err := filepath.Rel(s.secretsDir, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("invalid secret name: path escapes secrets directory")
	}
	return path, nil
}

func (s *Store) getValue(name string) (string, error) {
	path, err := s.secretPath(name)
	if err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	r, err := age.Decrypt(f, s.identity)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return "", fmt.Errorf("read decrypted value: %w", err)
	}
	return strings.TrimRight(buf.String(), "\n"), nil
}

func (s *Store) setValue(name, value string) error {
	path, err := s.secretPath(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create namespace dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create secret file: %w", err)
	}
	defer f.Close()

	w, err := age.Encrypt(f, s.identity.Recipient())
	if err != nil {
		return fmt.Errorf("create age writer: %w", err)
	}
	if _, err := io.WriteString(w, value); err != nil {
		return fmt.Errorf("write secret: %w", err)
	}
	return w.Close()
}

func (s *Store) removeValue(name string) error {
	path, err := s.secretPath(name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fs.ErrNotExist
		}
		return err
	}
	// Clean up empty parent namespace directories (but not secretsDir itself).
	for dir := filepath.Dir(path); dir != s.secretsDir; dir = filepath.Dir(dir) {
		entries, _ := os.ReadDir(dir)
		if len(entries) != 0 {
			break
		}
		os.Remove(dir)
	}
	return nil
}

func (s *Store) listNames() ([]string, error) {
	var names []string
	err := filepath.WalkDir(s.secretsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".age") {
			return err
		}
		rel, err := filepath.Rel(s.secretsDir, path)
		if err != nil {
			return err
		}
		names = append(names, filepath.ToSlash(strings.TrimSuffix(rel, ".age")))
		return nil
	})
	return names, err
}

// serve starts the HTTP server using configuration from loadConfig.
func serve() error {
	cfg := loadConfig()
	if cfg.Token == "" {
		return errors.New("AGED_TOKEN environment variable (or config file token) is required")
	}

	store, err := newStore(cfg.Identity, cfg.SecretsDir)
	if err != nil {
		return fmt.Errorf("init store: %w", err)
	}

	addr := cfg.Addr
	auth := bearerMiddleware(cfg.Token)
	mux := http.NewServeMux()

	mux.HandleFunc("GET /pubkey", auth(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, store.publicKey())
	}))

	mux.HandleFunc("GET /secrets", auth(func(w http.ResponseWriter, _ *http.Request) {
		names, err := store.listNames()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			log.Println("list error:", err)
			return
		}
		if names == nil {
			names = []string{} // return [] not null
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(names); err != nil {
			log.Println("encode error:", err)
		}
	}))

	mux.HandleFunc("GET /secrets/{name...}", auth(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if !validName(name) {
			http.Error(w, "invalid secret name", http.StatusBadRequest)
			return
		}
		value, err := store.getValue(name)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			log.Println("get error:", err)
			return
		}
		fmt.Fprint(w, value)
	}))

	mux.HandleFunc("POST /secrets/{name...}", auth(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if !validName(name) {
			http.Error(w, "invalid secret name", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		value := strings.TrimRight(string(body), "\n")
		if err := store.setValue(name, value); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			log.Println("set error:", err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	mux.HandleFunc("DELETE /secrets/{name...}", auth(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if !validName(name) {
			http.Error(w, "invalid secret name", http.StatusBadRequest)
			return
		}
		if err := store.removeValue(name); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			log.Println("delete error:", err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	log.Printf("aged listening on %s", addr)
	return http.ListenAndServe(addr, mux)
}

// initIdentity generates a new X25519 age identity and writes it to disk.
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

// bearerMiddleware returns an HTTP middleware that enforces Bearer token auth
// using constant-time comparison to prevent timing attacks.
func bearerMiddleware(token string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}
}
