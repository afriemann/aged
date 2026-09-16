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

	// canonicalDir is secretsDir with all symlinks resolved, computed once
	// at construction. secretPath's containment check is purely lexical
	// (filepath.Rel is a string operation and never touches the
	// filesystem), so a symlink inside secretsDir could point outside it
	// undetected; canonicalDir is the security boundary each per-operation
	// check below re-verifies the resolved, symlink-free target against.
	canonicalDir string
}

func newStore(secretsDir string) (*Store, error) {
	// filepath.Clean normalises a trailing separator (e.g. the documented
	// default "~/.config/aged/secrets/") so that removeValue's cleanup-loop
	// root comparison (dir != s.secretsDir) can never be defeated by one —
	// without this, the loop climbs above the intended root and deletes the
	// secrets directory itself once it empties.
	secretsDir = filepath.Clean(secretsDir)
	if err := os.MkdirAll(secretsDir, 0o700); err != nil {
		return nil, fmt.Errorf("create secrets dir: %w", err)
	}
	canonicalDir, err := filepath.EvalSymlinks(secretsDir)
	if err != nil {
		return nil, fmt.Errorf("resolve secrets dir: %w", err)
	}
	return &Store{secretsDir: secretsDir, canonicalDir: canonicalDir}, nil
}

// secretPath returns the absolute path for a secret file, verifying it lies
// within the secrets directory to prevent path traversal.
//
// This is a purely lexical check (see withinRoot) and is deliberately the
// precise form: nameRe allows "." inside a segment, so "..foo" is a valid
// secret name whose filepath.Rel result is exactly "..foo" — the old lenient
// strings.HasPrefix(rel, "..") form rejected that legitimate name. Symlink
// escapes are not caught here at all (Rel never touches the filesystem) —
// see verifyExistingWithinRoot and the parent-resolution step in setValue.
func (s *Store) secretPath(name string) (string, error) {
	path := filepath.Join(s.secretsDir, filepath.FromSlash(name)+".age")
	rel, err := filepath.Rel(s.secretsDir, path)
	if err != nil || !withinRoot(rel) {
		return "", fmt.Errorf("invalid secret name: path escapes secrets directory")
	}
	return path, nil
}

// withinRoot reports whether rel (as produced by filepath.Rel(root, path))
// stays within root, using the precise form rather than a lenient prefix
// check — see secretPath's doc comment for why the distinction matters.
func withinRoot(rel string) bool {
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// verifyExistingWithinRoot resolves path (which the caller expects to
// already exist) via filepath.EvalSymlinks and confirms the resolved,
// symlink-free target lies within s.canonicalDir. A symlink whose target
// escapes the store's real root is rejected here even though it passed
// secretPath's lexical check. fs.ErrNotExist is returned unchanged so
// callers can map it to their existing 404 path unmodified.
func (s *Store) verifyExistingWithinRoot(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fs.ErrNotExist
		}
		return fmt.Errorf("resolve secret path: %w", err)
	}
	rel, err := filepath.Rel(s.canonicalDir, resolved)
	if err != nil || !withinRoot(rel) {
		return fmt.Errorf("invalid secret name: resolved path escapes secrets directory")
	}
	return nil
}

// getValue returns the stored ciphertext bytes for name, verbatim — no
// decryption, no trimming, no transformation of any kind.
func (s *Store) getValue(name string) ([]byte, error) {
	path, err := s.secretPath(name)
	if err != nil {
		return nil, err
	}
	if err := s.verifyExistingWithinRoot(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fs.ErrNotExist
		}
		return nil, err
	}
	return os.ReadFile(path)
}

// setValue validates that data begins with the age v1 file magic and, if so,
// persists it verbatim via an atomic write. The server never encrypts,
// decrypts, or otherwise transforms the content.
//
// Unlike getValue/removeValue, the target file need not already exist, so
// EvalSymlinks cannot be applied to the full path (it fails on a missing
// final component). Instead the *parent* namespace directory is resolved and
// re-verified against canonicalDir, and the final "<name>.age" element is
// appended to the resolved parent. This is sufficient: writeFileAtomic
// stages to a fresh os.CreateTemp file and os.Renames over the destination,
// and Rename does not traverse a symlink at the destination path — it
// replaces it — so the leaf element is never a pre-existing symlink target
// the store would otherwise follow.
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
	resolvedParent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("resolve namespace dir: %w", err)
	}
	rel, err := filepath.Rel(s.canonicalDir, resolvedParent)
	if err != nil || !withinRoot(rel) {
		return fmt.Errorf("invalid secret name: resolved path escapes secrets directory")
	}
	finalPath := filepath.Join(resolvedParent, filepath.Base(path))
	return writeFileAtomic(finalPath, data)
}

func (s *Store) removeValue(name string) error {
	path, err := s.secretPath(name)
	if err != nil {
		return err
	}
	if err := s.verifyExistingWithinRoot(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fs.ErrNotExist
		}
		return err
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fs.ErrNotExist
		}
		return err
	}
	// Clean up empty parent namespace directories (but not secretsDir
	// itself). secretsDir was Cleaned in newStore, so this comparison is
	// correct regardless of whether the configured path carried a trailing
	// separator.
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
// mirror of it — can be exercised directly by tests. It delegates to
// resolveUsers, which owns the merge (config-file [[users]] plus the
// AGED_USERNAME/AGED_TOKEN environment pair) and the full validation
// ruleset; every problem serve() would refuse to start on is fatal here too.
func checkServeConfig(cfg Config) error {
	_, problems, err := resolveUsers(cfg)
	if err != nil {
		return err
	}
	if len(problems) > 0 {
		return errors.New(problems[0].message)
	}
	return nil
}

// serve starts the HTTP server using configuration from loadConfig.
//
// Startup order (see design.md D2.4): resolve and validate the configured
// user set (pure, no I/O) before any filesystem side effect; scan
// secrets_dir for unmigrated pre-multi-user-support secrets before
// constructing any per-user store, so a rejected start creates no
// directories; construct every user's store eagerly, so a name collision or
// permission error is a startup failure and never a runtime 500 on that
// user's first request; only then warn about a stale configured identity
// and start accepting connections.
func serve() error {
	cfg := loadConfig()
	users, problems, err := resolveUsers(cfg)
	if err != nil {
		return err
	}
	if len(problems) > 0 {
		return errors.New(problems[0].message)
	}

	log.SetFlags(0) // disable timestamp prefix; journald records its own timestamps

	userNames := make([]string, len(users))
	for i, u := range users {
		userNames[i] = u.Name
	}
	if err := scanSecretsDir(cfg.SecretsDir, userNames, os.Stderr); err != nil {
		return err
	}

	tenants := make([]tenant, len(users))
	for i, u := range users {
		store, err := newStore(filepath.Join(cfg.SecretsDir, u.Name))
		if err != nil {
			return fmt.Errorf("init store for user %q: %w", u.Name, err)
		}
		tenants[i] = tenant{name: u.Name, token: u.Token, store: store}
	}

	warnIfIdentityConfigured(cfg, os.Stderr)

	addr := cfg.Addr
	auth := bearerMiddleware(tenants, os.Stderr)
	mux := http.NewServeMux()

	mux.HandleFunc("GET /secrets", auth(func(w http.ResponseWriter, _ *http.Request, t *tenant) {
		names, err := t.store.listNames()
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

	mux.HandleFunc("GET /secrets/{name...}", auth(func(w http.ResponseWriter, r *http.Request, t *tenant) {
		name := r.PathValue("name")
		if !validName(name) {
			http.Error(w, "invalid secret name", http.StatusBadRequest)
			return
		}
		value, err := t.store.getValue(name)
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

	mux.HandleFunc("POST /secrets/{name...}", auth(func(w http.ResponseWriter, r *http.Request, t *tenant) {
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
		if err := t.store.setValue(name, body); err != nil {
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

	mux.HandleFunc("DELETE /secrets/{name...}", auth(func(w http.ResponseWriter, r *http.Request, t *tenant) {
		name := r.PathValue("name")
		if !validName(name) {
			http.Error(w, "invalid secret name", http.StatusBadRequest)
			return
		}
		if err := t.store.removeValue(name); err != nil {
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

// tenant identifies one authenticated caller: the user's name (used in the
// success log line and, where relevant, in error messages) and its own
// storage subtree. token is used only inside bearerMiddleware's comparison
// loop and is never logged or otherwise exposed.
type tenant struct {
	name  string
	token string
	store *Store
}

// tenantHandler is the handler shape bearerMiddleware wraps: the resolved
// tenant is passed as an explicit parameter rather than smuggled through
// request context. This makes it statically impossible to write a handler
// that runs without a resolved tenant — context.WithValue would instead
// require an unexported key type plus a getter that can fail, forcing every
// handler to carry an untestable "no tenant in context" branch.
type tenantHandler func(http.ResponseWriter, *http.Request, *tenant)

// bearerMiddleware returns an HTTP middleware that enforces Bearer token auth
// against every configured tenant, using constant-time comparison to prevent
// timing attacks, and routes an authenticated request to its own tenant.
//
// Every configured tenant is compared on every request, with no early exit:
// the loop performs no data-dependent branching (ConstantTimeCompare and
// ConstantTimeSelect are pure bit operations), so timing analysis cannot
// reveal which tenant matched or whether any matched. It does not conceal
// how many tenants are configured — total loop cost scales with the
// configured count, which is operator-visible configuration, not a secret.
//
// Every request produces exactly one log line written to logDst recording
// the outcome and resolved client IP; see resolveClientIP and
// sanitiseLogField. The success line additionally names the matched
// tenant; the failure line is unchanged (a documented, fail2ban-consumed
// machine interface — see contrib/fail2ban/filter.d/aged-auth.conf).
// bearerMiddlewareCompareHook, when non-nil, is invoked once per
// subtle.ConstantTimeCompare call inside bearerMiddleware's tenant loop. It
// exists solely so tests can prove the loop performs no early exit — every
// configured tenant is compared exactly once per request, regardless of
// where (or whether) a match occurs — without resorting to a flaky
// wall-clock timing measurement. Always nil in production (see the
// analogous rotateIdentityCorruptStagedFileHook in rotate_identity.go for
// the same pattern).
var bearerMiddlewareCompareHook func()

func bearerMiddleware(tenants []tenant, logDst io.Writer) func(tenantHandler) http.HandlerFunc {
	logger := log.New(logDst, "", 0)
	return func(next tenantHandler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			ip := resolveClientIP(r)
			method := sanitiseLogField(r.Method)
			path := sanitiseLogField(r.URL.Path)

			// No break/return/continue in this loop: every configured
			// tenant is compared exactly once per request, regardless of
			// where (or whether) a match occurs.
			matched := 0
			idx := 0
			for i := range tenants {
				eq := subtle.ConstantTimeCompare([]byte(got), []byte(tenants[i].token))
				if bearerMiddlewareCompareHook != nil {
					bearerMiddlewareCompareHook()
				}
				matched |= eq
				idx = subtle.ConstantTimeSelect(eq, i, idx)
			}

			// Single branch, after the loop, on the aggregate outcome only.
			if matched != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="aged"`)
				logger.Printf("auth failure: %s %s from %s", method, path, sanitiseLogField(ip))
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			t := &tenants[idx]
			logger.Printf("auth ok: %s %s from %s as %s", method, path, sanitiseLogField(ip), sanitiseLogField(t.name))
			next(w, r, t)
		}
	}
}
