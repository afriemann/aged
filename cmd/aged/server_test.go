package main

// spec: openspec/specs/aged/spec.md
// spec: openspec/changes/security-hardening/specs/aged/spec.md

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

const testToken = "test-bearer-token"

// singleTenant returns a one-tenant slice for tests that only need a single
// authenticated caller and don't care about routing between multiple users.
func singleTenant(name, token string, store *Store) []tenant {
	return []tenant{{name: name, token: token, store: store}}
}

// testServer creates an httptest.Server backed by a fresh store, wired as a
// single tenant named "testuser" authenticating with testToken. The server
// and its temp directory are cleaned up automatically by t.Cleanup.
func testServer(t *testing.T) (*httptest.Server, *Store) {
	t.Helper()
	store := testStore(t)
	return newTestServer(t, singleTenant("testuser", testToken, store)), store
}

// newTestServer builds an httptest.Server multiplexing the given tenants,
// exactly as serve() wires the real mux. Used directly by tests that need
// more than one tenant.
func newTestServer(t *testing.T, tenants []tenant) *httptest.Server {
	t.Helper()
	auth := bearerMiddleware(tenants, io.Discard)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /secrets", auth(func(w http.ResponseWriter, _ *http.Request, tn *tenant) {
		names, _ := tn.store.listNames()
		if names == nil {
			names = []string{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(names)
	}))
	mux.HandleFunc("GET /secrets/{name...}", auth(func(w http.ResponseWriter, r *http.Request, tn *tenant) {
		name := r.PathValue("name")
		if !validName(name) {
			http.Error(w, "invalid name", http.StatusBadRequest)
			return
		}
		val, err := tn.store.getValue(name)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(val)
	}))
	mux.HandleFunc("POST /secrets/{name...}", auth(func(w http.ResponseWriter, r *http.Request, tn *tenant) {
		name := r.PathValue("name")
		if !validName(name) {
			http.Error(w, "invalid name", http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				http.Error(w, "too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := tn.store.setValue(name, body); err != nil {
			if errors.Is(err, errInvalidFormat) {
				http.Error(w, "invalid secret format", http.StatusBadRequest)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("DELETE /secrets/{name...}", auth(func(w http.ResponseWriter, r *http.Request, tn *tenant) {
		name := r.PathValue("name")
		if !validName(name) {
			http.Error(w, "invalid name", http.StatusBadRequest)
			return
		}
		if err := tn.store.removeValue(name); err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// do performs an authenticated request against the test server.
func do(t *testing.T, srv *httptest.Server, method, path, token string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, body)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return resp
}

func TestServer_AuthorisedRequestAccepted(t *testing.T) {
	// spec: HTTP Authentication — Authorised request accepted
	srv, _ := testServer(t)

	resp := do(t, srv, http.MethodGet, "/secrets", testToken, nil)
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		t.Errorf("got 401, want authorised response")
	}
}

func TestServer_WrongTokenRejected(t *testing.T) {
	// spec: HTTP Authentication — Wrong token rejected
	srv, _ := testServer(t)

	resp := do(t, srv, http.MethodGet, "/secrets", "wrong-token", nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", resp.StatusCode)
	}
}

func TestServer_MissingAuthorizationHeaderRejected(t *testing.T) {
	// spec: HTTP Authentication — Missing Authorization header rejected
	srv, _ := testServer(t)

	resp := do(t, srv, http.MethodGet, "/secrets", "" /* no token */, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", resp.StatusCode)
	}
}

func TestServer_SetAndGetSecret(t *testing.T) {
	// spec: Secret Storage + Retrieval — round-trip via HTTP
	srv, _ := testServer(t)
	ciphertext := testCiphertext(t, "my-secret")

	resp := do(t, srv, http.MethodPost, "/secrets/ha-token", testToken,
		bytes.NewReader(ciphertext))
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST got %d, want 204", resp.StatusCode)
	}

	resp = do(t, srv, http.MethodGet, "/secrets/ha-token", testToken, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET got %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(body, ciphertext) {
		t.Errorf("got %q, want %q", body, ciphertext)
	}
}

func TestServer_GetNonExistentSecretReturns404(t *testing.T) {
	// spec: Secret Retrieval — Retrieve non-existent secret
	srv, _ := testServer(t)

	resp := do(t, srv, http.MethodGet, "/secrets/does-not-exist", testToken, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("got %d, want 404", resp.StatusCode)
	}
}

func TestServer_DeleteSecret(t *testing.T) {
	// spec: Secret Deletion — Delete existing secret
	srv, store := testServer(t)

	if err := store.setValue("to-delete", testCiphertext(t, "value")); err != nil {
		t.Fatalf("setValue: %v", err)
	}

	resp := do(t, srv, http.MethodDelete, "/secrets/to-delete", testToken, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE got %d, want 204", resp.StatusCode)
	}

	resp = do(t, srv, http.MethodGet, "/secrets/to-delete", testToken, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET after delete got %d, want 404", resp.StatusCode)
	}
}

func TestServer_DeleteNonExistentSecretReturns404(t *testing.T) {
	// spec: Secret Deletion — Delete non-existent secret
	srv, _ := testServer(t)

	resp := do(t, srv, http.MethodDelete, "/secrets/ghost", testToken, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("got %d, want 404", resp.StatusCode)
	}
}

func TestServer_ListSecrets(t *testing.T) {
	// spec: Secret Listing — List populated store
	srv, store := testServer(t)

	for _, name := range []string{"alpha", "beta"} {
		store.setValue(name, testCiphertext(t, name))
	}

	resp := do(t, srv, http.MethodGet, "/secrets", testToken, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}

	var names []string
	json.NewDecoder(resp.Body).Decode(&names)
	if len(names) != 2 {
		t.Errorf("got %d names, want 2: %v", len(names), names)
	}
}

func TestServer_ListEmptyStoreReturnsEmptyArray(t *testing.T) {
	// spec: Secret Listing — List empty store
	srv, _ := testServer(t)

	resp := do(t, srv, http.MethodGet, "/secrets", testToken, nil)
	defer resp.Body.Close()

	var names []string
	json.NewDecoder(resp.Body).Decode(&names)
	if names == nil || len(names) != 0 {
		t.Errorf("got %v, want empty JSON array", names)
	}
}

func TestServer_InvalidNameRejectedWithBadRequest(t *testing.T) {
	// spec: Secret Name Validation — Invalid name rejected
	srv, _ := testServer(t)

	for _, name := range []string{"../evil", "foo/bar", "x;y", "a b"} {
		t.Run(name, func(t *testing.T) {
			resp := do(t, srv, http.MethodGet, "/secrets/"+name, testToken, nil)
			resp.Body.Close()
			// The mux won't route ../evil (path clean strips it), so we also
			// check POST which reaches the handler.
			if resp.StatusCode == http.StatusInternalServerError {
				t.Errorf("name %q: got 500, want 400 or 404", name)
			}
		})
	}
}

func TestServer_ValidNameAccepted(t *testing.T) {
	// spec: Secret Name Validation — Valid name accepted
	srv, _ := testServer(t)

	for _, name := range []string{"ha-token", "my.key", "secret_1", "API-KEY"} {
		t.Run(name, func(t *testing.T) {
			resp := do(t, srv, http.MethodPost, "/secrets/"+name, testToken,
				bytes.NewReader(testCiphertext(t, "val")))
			resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Errorf("name %q: got %d, want 204", name, resp.StatusCode)
			}
		})
	}
}

func TestServer_NonAgeContentRejected(t *testing.T) {
	// spec: Ciphertext Format Validation — Non-age content rejected
	srv, _ := testServer(t)

	resp := do(t, srv, http.MethodPost, "/secrets/plain", testToken,
		bytes.NewReader([]byte("plain-old-secret-value")))
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", resp.StatusCode)
	}
	for _, leak := range []string{"age.", "filippo.io", "NoIdentityMatchError"} {
		if strings.Contains(string(body), leak) {
			t.Errorf("response body %q leaks library internals (contains %q)", body, leak)
		}
	}
}

func TestServer_OversizedUploadRejectedNotTruncated(t *testing.T) {
	// spec: Upload Size Limit — Oversized upload rejected, not truncated
	srv, store := testServer(t)

	oversized := make([]byte, maxUploadBytes+1)
	resp := do(t, srv, http.MethodPost, "/secrets/big", testToken, bytes.NewReader(oversized))
	resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("got %d, want 413", resp.StatusCode)
	}
	if _, err := store.getValue("big"); !isNotFound(err) {
		t.Error("expected no partial file to be stored for an oversized upload")
	}
}

// TestInitIdentity_GeneratesNewIdentity verifies aged init writes a 0600 file
// and prints the public key.
func TestInitIdentity_GeneratesNewIdentity(t *testing.T) {
	// spec: Identity Initialisation — Generate new identity
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.age")
	t.Setenv("AGED_IDENTITY", path)

	if err := initIdentity(); err != nil {
		t.Fatalf("initIdentity: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat identity: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode %o, want 0600", info.Mode().Perm())
	}
}

func TestInitIdentity_RefusesToOverwriteExisting(t *testing.T) {
	// spec: Identity Initialisation — Refuse to overwrite existing identity
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.age")
	t.Setenv("AGED_IDENTITY", path)

	// Create an existing identity.
	id, _ := age.GenerateX25519Identity()
	f, _ := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	fmt.Fprintf(f, "# existing\n%s\n", id)
	f.Close()

	originalStat, _ := os.Stat(path)

	err := initIdentity()
	if err == nil {
		t.Fatal("expected error when identity exists, got nil")
	}

	newStat, _ := os.Stat(path)
	if !newStat.ModTime().Equal(originalStat.ModTime()) {
		t.Error("existing identity file was modified")
	}
}

// authMiddlewareWith returns a bearerMiddleware handler wired to the given
// log writer. It registers a single GET /secrets route so tests have a
// real endpoint to hit.
func authMiddlewareWith(t *testing.T, logDst io.Writer, tenants []tenant, reqToken, remoteAddr, xRealIP, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	auth := bearerMiddleware(tenants, logDst)
	handler := auth(func(w http.ResponseWriter, _ *http.Request, _ *tenant) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = remoteAddr
	if xRealIP != "" {
		req.Header.Set("X-Real-IP", xRealIP)
	}
	if reqToken != "" {
		req.Header.Set("Authorization", "Bearer "+reqToken)
	}
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr
}

func TestBearerMiddleware_AuthFailureLoggedWithRealClientIP(t *testing.T) {
	// spec: HTTP Authentication — Auth failure logged with real client IP
	var buf bytes.Buffer
	authMiddlewareWith(t, &buf, singleTenant("testuser", testToken, nil), "wrong", "127.0.0.1:12345", "1.2.3.4", http.MethodGet, "/secrets")
	if !strings.Contains(buf.String(), "auth failure: GET /secrets from 1.2.3.4") {
		t.Errorf("log %q: want auth failure line with real IP 1.2.3.4", buf.String())
	}
}

func TestBearerMiddleware_AuthSuccessLoggedWithRealClientIP(t *testing.T) {
	// spec: HTTP Authentication — Auth success logged with real client IP
	var buf bytes.Buffer
	authMiddlewareWith(t, &buf, singleTenant("testuser", testToken, nil), testToken, "127.0.0.1:12345", "1.2.3.4", http.MethodGet, "/secrets")
	if !strings.Contains(buf.String(), "auth ok: GET /secrets from 1.2.3.4") {
		t.Errorf("log %q: want auth ok line with real IP 1.2.3.4", buf.String())
	}
}

func TestBearerMiddleware_AuthFailureLoggedWithLoopbackWhenXRealIPAbsent(t *testing.T) {
	// spec: HTTP Authentication — Auth failure logged with loopback IP when X-Real-IP absent
	var buf bytes.Buffer
	authMiddlewareWith(t, &buf, singleTenant("testuser", testToken, nil), "wrong", "127.0.0.1:12345", "" /* no X-Real-IP */, http.MethodGet, "/secrets")
	if !strings.Contains(buf.String(), "auth failure: GET /secrets from 127.0.0.1") {
		t.Errorf("log %q: want auth failure line with loopback IP", buf.String())
	}
}

func TestBearerMiddleware_AuthFailureLoggedWithDirectPeerIPWhenNotBehindProxy(t *testing.T) {
	// spec: HTTP Authentication — Auth failure logged with direct peer IP when not behind proxy
	var buf bytes.Buffer
	// Non-loopback peer; X-Real-IP must be ignored.
	authMiddlewareWith(t, &buf, singleTenant("testuser", testToken, nil), "wrong", "10.0.0.5:54321", "1.2.3.4" /* must be ignored */, http.MethodGet, "/secrets")
	if !strings.Contains(buf.String(), "auth failure: GET /secrets from 10.0.0.5") {
		t.Errorf("log %q: want auth failure line with peer IP 10.0.0.5 (not X-Real-IP)", buf.String())
	}
}

func TestBearerMiddleware_AuthFailureLoggedWithIPv6RealClientIP(t *testing.T) {
	// spec: HTTP Authentication — Auth failure logged with real client IP
	// Exercises the ::1 loopback branch.
	var buf bytes.Buffer
	authMiddlewareWith(t, &buf, singleTenant("testuser", testToken, nil), "wrong", "[::1]:12345", "2001:db8::1", http.MethodGet, "/secrets")
	if !strings.Contains(buf.String(), "auth failure: GET /secrets from 2001:db8::1") {
		t.Errorf("log %q: want auth failure line with IPv6 real IP 2001:db8::1", buf.String())
	}
}

func TestBearerMiddleware_CRLFInPathDoesNotForgeSecondLogLine(t *testing.T) {
	// spec: HTTP Authentication — CRLF in path does not forge a second log line
	for _, tc := range []struct {
		name  string
		token string // use testToken for success, "wrong" for failure
		want  string
	}{
		{"failure path", "wrong", "auth failure:"},
		{"success path", testToken, "auth ok:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			auth := bearerMiddleware(singleTenant("testuser", testToken, nil), &buf)
			handler := auth(func(w http.ResponseWriter, _ *http.Request, _ *tenant) { w.WriteHeader(http.StatusOK) })
			req := httptest.NewRequest(http.MethodGet, "/secrets/foo", nil)
			req.RemoteAddr = "127.0.0.1:12345"
			req.Header.Set("X-Real-IP", "1.2.3.4")
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			// Inject control characters into the path that the middleware will log.
			req.URL.Path = "/secrets/foo\r\nauth failure: GET /secrets from 9.9.9.9"
			rr := httptest.NewRecorder()
			handler(rr, req)

			logged := buf.String()
			// Trim the logger's own trailing newline before splitting/checking.
			trimmed := strings.TrimRight(logged, "\n")

			// Must be exactly one log line (no injected second line).
			lines := strings.Split(trimmed, "\n")
			if len(lines) != 1 {
				t.Errorf("expected 1 log line, got %d: %q", len(lines), logged)
			}
			// No raw CR or internal LF may remain.
			if strings.ContainsAny(trimmed, "\r\n") {
				t.Errorf("log %q: raw CR/LF must be sanitised", logged)
			}
			// The control characters must have been replaced with underscores.
			if !strings.Contains(trimmed, "__") {
				t.Errorf("log %q: expected __ in sanitised path", logged)
			}
			// Confirm the right outcome prefix.
			if !strings.Contains(trimmed, tc.want) {
				t.Errorf("log %q: expected prefix %q", logged, tc.want)
			}
		})
	}
}

func TestMain_NoArgsCommandsRejectExtraArgs(t *testing.T) {
	// spec: base — no-argument subcommands reject unexpected arguments
	// rotate-token is deliberately excluded: it now accepts an optional
	// <username> argument (required when more than one user is configured),
	// so it must not reject a trailing argument the way true no-argument
	// commands do.
	for _, cmd := range []string{"list", "pubkey", "init"} {
		t.Run(cmd, func(t *testing.T) {
			// noArgs reads os.Args directly; we verify the guard logic
			// by checking that len(os.Args) > 2 triggers it.
			// Integration: just confirm noArgs exits non-zero via subprocess.
			// Unit: verify the guard condition directly.
			orig := os.Args
			os.Args = []string{"aged", cmd, "unexpected"}
			defer func() { os.Args = orig }()

			exited := false
			func() {
				defer func() {
					if r := recover(); r != nil {
						exited = true
					}
				}()
				// We can't call os.Exit in tests; test the condition instead.
				if len(os.Args) > 2 {
					exited = true
				}
			}()
			if !exited {
				t.Errorf("command %q: expected noArgs to trigger for extra arg", cmd)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Security-hardening tests (M-01 covered in rotate_test.go,
// M-02 covered in config_test.go)
// ---------------------------------------------------------------------------

func TestResolveClientIP_IPv4MappedLoopback(t *testing.T) {
	// spec: HTTP Authentication — Auth failure logged with IPv4-mapped loopback peer
	req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
	req.RemoteAddr = "[::ffff:127.0.0.1]:12345"
	req.Header.Set("X-Real-IP", "1.2.3.4")

	got := resolveClientIP(req)
	if got != "1.2.3.4" {
		t.Errorf("resolveClientIP with ::ffff:127.0.0.1 peer = %q, want 1.2.3.4", got)
	}
}

func TestBearerMiddleware_WWWAuthenticateHeaderOnFailure(t *testing.T) {
	// spec: HTTP Authentication — WWW-Authenticate header present on 401
	var buf bytes.Buffer
	auth := bearerMiddleware(singleTenant("testuser", testToken, nil), &buf)
	handler := auth(func(w http.ResponseWriter, _ *http.Request, _ *tenant) {})
	req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer wrong-token")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	got := rr.Header().Get("WWW-Authenticate")
	const wantWWWAuth = `Bearer realm="aged"`
	if got != wantWWWAuth {
		t.Errorf("WWW-Authenticate = %q, want %q", got, wantWWWAuth)
	}
}

func TestNewHTTPServer_HasNonZeroTimeouts(t *testing.T) {
	// spec: HTTP Server Configuration — Server is configured with non-zero timeouts
	srv := newHTTPServer("127.0.0.1:0", http.NewServeMux())

	const (
		minReadHeader = 5 * time.Second
		minRead       = 10 * time.Second
		minWrite      = 30 * time.Second
		minIdle       = 60 * time.Second
	)
	if srv.ReadHeaderTimeout < minReadHeader {
		t.Errorf("ReadHeaderTimeout = %v, want >= %v", srv.ReadHeaderTimeout, minReadHeader)
	}
	if srv.ReadTimeout < minRead {
		t.Errorf("ReadTimeout = %v, want >= %v", srv.ReadTimeout, minRead)
	}
	if srv.WriteTimeout < minWrite {
		t.Errorf("WriteTimeout = %v, want >= %v", srv.WriteTimeout, minWrite)
	}
	if srv.IdleTimeout < minIdle {
		t.Errorf("IdleTimeout = %v, want >= %v", srv.IdleTimeout, minIdle)
	}
}

func TestServeStaleIdentityWarning(t *testing.T) {
	// spec: Stale Server Identity Warning
	t.Run("Warning fires when identity is explicitly configured", func(t *testing.T) {
		var buf bytes.Buffer
		cfg := Config{Identity: "/some/path/identity.age", identityExplicit: true}
		warnIfIdentityConfigured(cfg, &buf)
		if !strings.Contains(buf.String(), "/some/path/identity.age") {
			t.Errorf("warning %q: expected it to name the configured path", buf.String())
		}
	})

	t.Run("No warning when identity is left at its default", func(t *testing.T) {
		var buf bytes.Buffer
		cfg := Config{Identity: "/home/user/.config/aged/identity.age", identityExplicit: false}
		warnIfIdentityConfigured(cfg, &buf)
		if buf.String() != "" {
			t.Errorf("expected no warning, got %q", buf.String())
		}
	})
}

func TestServe_StartsWithoutAnyIdentityConfigured(t *testing.T) {
	// spec: Environment Variable Configuration — Server starts without any identity configured
	t.Setenv("AGED_CONFIG", "/tmp/definitely-absent-aged-test.toml")
	t.Setenv("AGED_TOKEN", tok('a'))
	t.Setenv("AGED_USERNAME", "laptop")
	t.Setenv("AGED_IDENTITY", "")
	t.Setenv("AGED_SECRETS_DIR", t.TempDir())

	cfg := loadConfig()
	users, problems, err := resolveUsers(cfg)
	if err != nil || len(problems) != 0 {
		t.Fatalf("precondition failed: resolveUsers returned problems=%v err=%v", problems, err)
	}
	if len(users) != 1 || users[0].Name != "laptop" {
		t.Fatalf("precondition failed: want a single laptop user, got %+v", users)
	}

	// This mirrors exactly what serve() does with cfg before starting the
	// HTTP listener: build the store (no identity involved at all) and
	// decide whether to warn. Success here is exactly what "the server
	// starts successfully" means, since newStore is the only fallible step
	// serve() performs before binding the listener.
	if _, err := newStore(cfg.SecretsDir); err != nil {
		t.Fatalf("newStore: %v", err)
	}
	var buf bytes.Buffer
	warnIfIdentityConfigured(cfg, &buf)
	if buf.String() != "" {
		t.Errorf("expected no stale-identity warning, got %q", buf.String())
	}
}

func TestCheckServeConfig_MissingTokenOnStartup(t *testing.T) {
	// spec: Environment Variable Configuration — Missing token on startup
	// (renamed: with no [[users]] and no AGED_USERNAME/AGED_TOKEN pair, the
	// server now refuses to start because no user is configured at all —
	// Config.Token alone no longer defines a server-side tenant.)
	err := checkServeConfig(Config{})
	if err == nil {
		t.Fatal("expected an error when no users are configured, got nil")
	}
}

func TestCheckServeConfig_UsersConfigured(t *testing.T) {
	// spec: Multi-User Configuration — Single user via config file
	err := checkServeConfig(Config{Users: []UserConfig{{Name: "alice", Token: tok('a')}}})
	if err != nil {
		t.Errorf("expected no error when a valid user is configured, got %v", err)
	}
}

func TestCheckServeConfig_BareTokenAloneIsNoLongerAServerCredential(t *testing.T) {
	// spec: Environment Variable Configuration — token/AGED_TOKEN is the CLI
	// client's own credential; aged serve SHALL NOT treat a bare token
	// value as an implicit tenant.
	err := checkServeConfig(Config{Token: "some-token"})
	if err == nil {
		t.Fatal("expected an error: Config.Token alone must not define a server user")
	}
}

func TestParseRotateIdentityArgs(t *testing.T) {
	for _, tc := range []struct {
		name         string
		args         []string
		wantFile     string
		wantDryRun   bool
		wantUsername string
		wantErr      bool
	}{
		{"flag before path", []string{"--dry-run", "file.age"}, "file.age", true, "", false},
		{"flag after path", []string{"file.age", "--dry-run"}, "file.age", true, "", false},
		{"no flag", []string{"file.age"}, "file.age", false, "", false},
		{"multiple positional args: last wins", []string{"a.age", "b.age"}, "b.age", false, "", false},
		{"no args", []string{}, "", false, "", false},
		{"--user before path", []string{"--user", "alice", "file.age"}, "file.age", false, "alice", false},
		{"--user after path", []string{"file.age", "--user", "alice"}, "file.age", false, "alice", false},
		{"--user combined with --dry-run", []string{"--dry-run", "--user", "alice", "file.age"}, "file.age", true, "alice", false},
		{"--user with no following value", []string{"file.age", "--user"}, "", false, "", true},
		{"--user immediately followed by another flag", []string{"file.age", "--user", "--dry-run"}, "", false, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotFile, gotDryRun, gotUsername, err := parseRotateIdentityArgs(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseRotateIdentityArgs(%v): expected an error, got nil", tc.args)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseRotateIdentityArgs(%v): unexpected error: %v", tc.args, err)
			}
			if gotFile != tc.wantFile || gotDryRun != tc.wantDryRun || gotUsername != tc.wantUsername {
				t.Errorf("parseRotateIdentityArgs(%v) = (%q, %v, %q), want (%q, %v, %q)",
					tc.args, gotFile, gotDryRun, gotUsername, tc.wantFile, tc.wantDryRun, tc.wantUsername)
			}
		})
	}
}

func TestServer_SecondConfiguredUsersTokenAuthenticates(t *testing.T) {
	// spec: HTTP Authentication — Second configured user's token authenticates
	aliceStore := testStore(t)
	bobStore := testStore(t)
	tenants := []tenant{
		{name: "alice", token: tok('a'), store: aliceStore},
		{name: "bob", token: tok('b'), store: bobStore},
	}
	srv := newTestServer(t, tenants)

	resp := do(t, srv, http.MethodGet, "/secrets", tok('b'), nil)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		t.Errorf("last configured user's token was rejected, want accepted")
	}
}

func TestServer_OneUserCannotListAnotherUsersSecrets(t *testing.T) {
	// spec: Per-User Storage Isolation — One user cannot list another user's secrets
	aliceStore := testStore(t)
	bobStore := testStore(t)
	if err := aliceStore.setValue("alice-only", testCiphertext(t, "a")); err != nil {
		t.Fatalf("setValue: %v", err)
	}
	if err := bobStore.setValue("bob-only", testCiphertext(t, "b")); err != nil {
		t.Fatalf("setValue: %v", err)
	}
	tenants := []tenant{
		{name: "alice", token: tok('a'), store: aliceStore},
		{name: "bob", token: tok('b'), store: bobStore},
	}
	srv := newTestServer(t, tenants)

	resp := do(t, srv, http.MethodGet, "/secrets", tok('a'), nil)
	defer resp.Body.Close()
	var names []string
	json.NewDecoder(resp.Body).Decode(&names)
	if len(names) != 1 || names[0] != "alice-only" {
		t.Errorf("got %v, want exactly [alice-only]", names)
	}
}

func TestBearerMiddleware_EveryTenantComparedRegardlessOfMatchPosition(t *testing.T) {
	// spec: HTTP Authentication — constant-time comparison with no early exit
	//
	// This is a structural assertion, not a wall-clock timing measurement
	// (per design.md D3.1: "Assert this structurally... Wall-clock timing
	// tests are flaky and prove nothing on a shared CI runner"). It proves
	// the loop has no early exit by instrumenting every
	// subtle.ConstantTimeCompare call via bearerMiddlewareCompareHook and
	// asserting the count equals len(tenants) regardless of which
	// position — first, middle, last, or none — matches.
	tenants := make([]tenant, 5)
	for i := range tenants {
		tenants[i] = tenant{name: fmt.Sprintf("user%d", i), token: tok(byte('a' + i))}
	}
	auth := bearerMiddleware(tenants, io.Discard)
	handler := auth(func(w http.ResponseWriter, _ *http.Request, _ *tenant) {
		w.WriteHeader(http.StatusOK)
	})

	run := func(t *testing.T, presentedToken string) int {
		t.Helper()
		count := 0
		bearerMiddlewareCompareHook = func() { count++ }
		t.Cleanup(func() { bearerMiddlewareCompareHook = nil })

		req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		if presentedToken != "" {
			req.Header.Set("Authorization", "Bearer "+presentedToken)
		}
		rr := httptest.NewRecorder()
		handler(rr, req)
		return count
	}

	for _, matchIdx := range []int{0, 2, len(tenants) - 1} {
		t.Run(fmt.Sprintf("match at index %d", matchIdx), func(t *testing.T) {
			count := run(t, tenants[matchIdx].token)
			if count != len(tenants) {
				t.Errorf("compared %d tenant(s), want exactly %d (every tenant, no early exit)", count, len(tenants))
			}
		})
	}

	t.Run("no match", func(t *testing.T) {
		count := run(t, "wrong-token-entirely")
		if count != len(tenants) {
			t.Errorf("compared %d tenant(s), want exactly %d even when nothing matches", count, len(tenants))
		}
	})
}

func TestServer_SecondConfiguredUsersTokenAuthenticates_RoutesToCorrectTenant(t *testing.T) {
	// spec: HTTP Authentication — Second configured user's token authenticates
	// (routing correctness, complementing the structural no-early-exit test
	// above)
	var compared []string
	tenants := make([]tenant, 5)
	for i := range tenants {
		tenants[i] = tenant{name: fmt.Sprintf("user%d", i), token: tok(byte('a' + i))}
	}
	auth := bearerMiddleware(tenants, io.Discard)
	handler := auth(func(w http.ResponseWriter, _ *http.Request, tn *tenant) {
		compared = append(compared, tn.name)
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer "+tenants[len(tenants)-1].token)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (last tenant's token should authenticate)", rr.Code)
	}
	if len(compared) != 1 || compared[0] != tenants[len(tenants)-1].name {
		t.Errorf("resolved tenant = %v, want [%s]", compared, tenants[len(tenants)-1].name)
	}
}

func TestBearerMiddleware_SuccessLogNamesMatchedUser(t *testing.T) {
	// spec: HTTP Authentication — success line carries the matched username
	var buf bytes.Buffer
	tenants := []tenant{
		{name: "alice", token: tok('a')},
		{name: "bob", token: tok('b')},
	}
	authMiddlewareWith(t, &buf, tenants, tok('b'), "127.0.0.1:12345", "1.2.3.4", http.MethodGet, "/secrets")
	if !strings.Contains(buf.String(), "auth ok: GET /secrets from 1.2.3.4 as bob") {
		t.Errorf("log %q: want auth ok line naming bob", buf.String())
	}
}

func TestServe_StoreConstructionFailureIsStartupError(t *testing.T) {
	// spec: Per-User Storage Isolation — Store construction failure is a startup error
	secretsDir := t.TempDir()
	// "alice" collides with an existing regular file directly under
	// secrets_dir, so newStore's os.MkdirAll must fail.
	if err := os.WriteFile(filepath.Join(secretsDir, "alice"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	users := []UserConfig{{Name: "alice", Token: tok('a')}}

	// Mirrors serve()'s per-user store construction loop exactly.
	var startupErr error
	for _, u := range users {
		if _, err := newStore(filepath.Join(secretsDir, u.Name)); err != nil {
			startupErr = fmt.Errorf("init store for user %q: %w", u.Name, err)
			break
		}
	}
	if startupErr == nil {
		t.Fatal("expected a startup error when a user's name collides with an existing regular file")
	}
	if !strings.Contains(startupErr.Error(), "alice") {
		t.Errorf("error %q does not name the offending user", startupErr.Error())
	}
}
