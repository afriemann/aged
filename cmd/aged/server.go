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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

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

// newHTTPServer constructs an http.Server with hardened per-connection
// timeouts. Extracted for testability; serve() calls it directly.
func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
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
	log.SetFlags(0) // disable timestamp prefix; journald records its own timestamps
	auth := bearerMiddleware(cfg.Token, os.Stderr)
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
	return newHTTPServer(addr, mux).ListenAndServe()
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

// sanitiseLogField replaces CR, LF, and all other ASCII control characters
// with '_' to prevent CRLF log-injection when attacker-controlled request
// fields (method, URL path) are interpolated into log lines.
func sanitiseLogField(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, s)
}

// resolveClientIP returns the real client IP for use in log lines.
//
// Trust model: proxy headers are honoured only when the immediate peer
// (r.RemoteAddr) is a loopback address, which means the request arrived
// through the local reverse proxy (Caddy). A direct, non-loopback peer is
// untrusted and could forge headers, so its own IP is used directly.
//
// X-Forwarded-For is intentionally not consulted: it is a comma-delimited
// list whose leftmost entry is attacker-controlled, adding spoofable surface
// with no benefit over X-Real-IP set by Caddy via header_up X-Real-IP
// {remote_host}.
func resolveClientIP(r *http.Request) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr has no port (unusual but safe to handle gracefully).
		peer = r.RemoteAddr
	}
	// Trust X-Real-IP only when the direct TCP peer is a loopback address —
	// meaning the request arrived through the local reverse proxy (Caddy).
	// net.IP.IsLoopback() handles 127.0.0.1, ::1, ::ffff:127.0.0.1, and the
	// full 127.0.0.0/8 range. A direct non-loopback peer is untrusted and
	// could forge headers, so its own IP is used directly.
	// X-Forwarded-For is intentionally not consulted.
	ip := net.ParseIP(peer)
	if ip != nil && ip.IsLoopback() {
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return xri
		}
		return peer
	}
	return peer
}

// bearerMiddleware returns an HTTP middleware that enforces Bearer token auth
// using constant-time comparison to prevent timing attacks. Every request
// produces exactly one log line written to logDst recording the outcome
// and resolved client IP; see resolveClientIP and sanitiseLogField.
func bearerMiddleware(token string, logDst io.Writer) func(http.HandlerFunc) http.HandlerFunc {
	logger := log.New(logDst, "", 0)
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			ip := resolveClientIP(r)
			method := sanitiseLogField(r.Method)
			path := sanitiseLogField(r.URL.Path)
			if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="aged"`)
				logger.Printf("auth failure: %s %s from %s", method, path, sanitiseLogField(ip))
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			logger.Printf("auth ok: %s %s from %s", method, path, sanitiseLogField(ip))
			next(w, r)
		}
	}
}
