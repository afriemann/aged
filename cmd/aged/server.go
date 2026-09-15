package main

import (
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
)

// nameRe validates each segment of a secret name (segments are split on /).
// Slashes are allowed as namespace separators; the full name is validated by validName.
var nameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]+(/[a-zA-Z0-9._-]+)*$`)

// validName returns true if name passes the regex and contains no .. segments.
// This is the single authoritative gate called by all HTTP handlers, and by
// the CLI client before constructing a name-binding envelope.
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

// ageV1Magic is the fixed literal every age v1 file begins with (verified
// against filippo.io/age@v1.2.1's internal/format.intro). The server checks
// only for this prefix — it never attempts to decrypt, so it never
// constructs or holds any identity, real or otherwise.
const ageV1Magic = "age-encryption.org/v1\n"

// maxUploadBytes bounds POST /secrets/{name} bodies. The pre-change limit of
// 64KiB applied to plaintext; since the body is now ciphertext, 96KiB
// preserves that same effective plaintext headroom after age v1 overhead
// (a fixed per-recipient header, a 16-byte nonce, and 16 bytes of AEAD tag
// per 64KiB STREAM chunk) plus the name-binding envelope.
const maxUploadBytes = 96 * 1024

// errInvalidFormat is returned by Store.setValue when uploaded content does
// not begin with the age v1 magic. The HTTP handler maps it to a 400 with a
// generic body — the underlying age library error text is never disclosed.
var errInvalidFormat = errors.New("content does not begin with the age v1 file format magic")

// Store manages opaque, age-encrypted secret blobs on disk. It holds no
// identity and performs no encryption or decryption: all cryptography is the
// responsibility of the CLI client. The server can therefore never read a
// secret's plaintext value, even with full filesystem access.
type Store struct {
	secretsDir string
}

func newStore(secretsDir string) (*Store, error) {
	if err := os.MkdirAll(secretsDir, 0o700); err != nil {
		return nil, fmt.Errorf("create secrets dir: %w", err)
	}
	return &Store{secretsDir: secretsDir}, nil
}

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

// getValue returns the stored ciphertext bytes for name, verbatim — no
// decryption, no trimming, no transformation of any kind.
func (s *Store) getValue(name string) ([]byte, error) {
	path, err := s.secretPath(name)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

// setValue validates that data begins with the age v1 file magic and, if so,
// persists it verbatim via an atomic write. The server never encrypts,
// decrypts, or otherwise transforms the content.
func (s *Store) setValue(name string, data []byte) error {
	if !strings.HasPrefix(string(data), ageV1Magic) {
		return errInvalidFormat
	}
	path, err := s.secretPath(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create namespace dir: %w", err)
	}
	return writeFileAtomic(path, data)
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

// checkServeConfig validates the configuration serve() needs before it does
// anything else. Extracted so the guard condition itself — not a hand-copied
// mirror of it — can be exercised directly by tests.
func checkServeConfig(cfg Config) error {
	if cfg.Token == "" {
		return errors.New("AGED_TOKEN environment variable (or config file token) is required")
	}
	return nil
}

// serve starts the HTTP server using configuration from loadConfig.
func serve() error {
	cfg := loadConfig()
	if err := checkServeConfig(cfg); err != nil {
		return err
	}

	log.SetFlags(0) // disable timestamp prefix; journald records its own timestamps
	warnIfIdentityConfigured(cfg, os.Stderr)

	store, err := newStore(cfg.SecretsDir)
	if err != nil {
		return fmt.Errorf("init store: %w", err)
	}

	addr := cfg.Addr
	auth := bearerMiddleware(cfg.Token, os.Stderr)
	mux := http.NewServeMux()

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
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(value)
	}))

	mux.HandleFunc("POST /secrets/{name...}", auth(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if !validName(name) {
			http.Error(w, "invalid secret name", http.StatusBadRequest)
			return
		}
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
		if err := store.setValue(name, body); err != nil {
			if errors.Is(err, errInvalidFormat) {
				http.Error(w, "invalid secret format", http.StatusBadRequest)
				return
			}
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

// warnIfIdentityConfigured logs a one-line warning if the server was started
// with an explicitly configured identity/AGED_IDENTITY value. It intentionally
// does NOT fire merely because a file happens to exist at the default
// identity path — that path is the correct default location for a
// client-only identity on a combined server-and-client host, and a warning
// that fires on every healthy default-path setup would train operators to
// ignore it.
func warnIfIdentityConfigured(cfg Config, dst io.Writer) {
	if !cfg.identityExplicit {
		return
	}
	fmt.Fprintf(dst, "warning: identity/AGED_IDENTITY (%s) is configured but no longer used by aged serve — "+
		"encryption now happens client-side. Secure or remove this file once migration is verified "+
		"(see: aged rotate-identity).\n", cfg.Identity)
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
