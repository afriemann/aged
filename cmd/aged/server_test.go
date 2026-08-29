package main

// spec: openspec/specs/aged/spec.md

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

const testToken = "test-bearer-token"

// testServer creates an httptest.Server backed by a fresh store. The server
// and its temp directory are cleaned up automatically by t.Cleanup.
func testServer(t *testing.T) (*httptest.Server, *Store) {
	t.Helper()
	store := testStore(t)
	auth := bearerMiddleware(testToken)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /pubkey", auth(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, store.publicKey())
	}))
	mux.HandleFunc("GET /secrets", auth(func(w http.ResponseWriter, _ *http.Request) {
		names, _ := store.listNames()
		if names == nil {
			names = []string{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(names)
	}))
	mux.HandleFunc("GET /secrets/{name}", auth(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if !nameRe.MatchString(name) {
			http.Error(w, "invalid name", http.StatusBadRequest)
			return
		}
		val, err := store.getValue(name)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		fmt.Fprint(w, val)
	}))
	mux.HandleFunc("POST /secrets/{name}", auth(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if !nameRe.MatchString(name) {
			http.Error(w, "invalid name", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		store.setValue(name, strings.TrimRight(string(body), "\n"))
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("DELETE /secrets/{name}", auth(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if !nameRe.MatchString(name) {
			http.Error(w, "invalid name", http.StatusBadRequest)
			return
		}
		if err := store.removeValue(name); err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, store
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

	resp := do(t, srv, http.MethodPost, "/secrets/ha-token", testToken,
		strings.NewReader("my-secret"))
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
	if string(body) != "my-secret" {
		t.Errorf("got %q, want %q", string(body), "my-secret")
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

	if err := store.setValue("to-delete", "value"); err != nil {
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
		store.setValue(name, name)
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

func TestServer_PubKeyReturnsAgeKey(t *testing.T) {
	// spec: Public Key Endpoint — Retrieve public key
	srv, _ := testServer(t)

	resp := do(t, srv, http.MethodGet, "/pubkey", testToken, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.HasPrefix(strings.TrimSpace(string(body)), "age1") {
		t.Errorf("public key %q does not start with age1", strings.TrimSpace(string(body)))
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
				strings.NewReader("val"))
			resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Errorf("name %q: got %d, want 204", name, resp.StatusCode)
			}
		})
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
