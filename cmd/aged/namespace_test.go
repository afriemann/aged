package main

// spec: openspec/changes/namespace-support/specs/aged/spec.md

import (
	"bytes"
	"net/http"
	"os"
	"testing"
)

func TestStore_NamespacedRoundTrip(t *testing.T) {
	// spec: Namespaced Secret Names — Namespaced secret round-trip
	store := testStore(t)
	want := testCiphertext(t, "secret-value")
	if err := store.setValue("ha/token", want); err != nil {
		t.Fatalf("setValue: %v", err)
	}
	got, err := store.getValue("ha/token")
	if err != nil {
		t.Fatalf("getValue: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestStore_DeeplyNestedNamespace(t *testing.T) {
	// spec: Namespaced Secret Names — Deeply nested namespace
	store := testStore(t)
	want := testCiphertext(t, "db-pass")
	if err := store.setValue("infra/db/password", want); err != nil {
		t.Fatalf("setValue: %v", err)
	}
	got, err := store.getValue("infra/db/password")
	if err != nil {
		t.Fatalf("getValue: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestStore_ListReturnsNamespacedNames(t *testing.T) {
	// spec: Namespaced Secret Names — List returns namespaced names
	store := testStore(t)
	for _, name := range []string{"ha/token", "ha/client-id", "grafana/key"} {
		if err := store.setValue(name, testCiphertext(t, name)); err != nil {
			t.Fatalf("setValue %s: %v", name, err)
		}
	}
	names, err := store.listNames()
	if err != nil {
		t.Fatalf("listNames: %v", err)
	}
	want := map[string]bool{"ha/token": true, "ha/client-id": true, "grafana/key": true}
	for _, n := range names {
		delete(want, n)
	}
	if len(want) != 0 {
		t.Errorf("missing names: %v (got %v)", want, names)
	}
}

func TestStore_DeleteRemovesEmptyNamespaceDir(t *testing.T) {
	// spec: Namespaced Secret Names — Delete removes empty namespace directories
	store := testStore(t)
	if err := store.setValue("ns/only", testCiphertext(t, "v")); err != nil {
		t.Fatalf("setValue: %v", err)
	}
	if err := store.removeValue("ns/only"); err != nil {
		t.Fatalf("removeValue: %v", err)
	}
	// The ns/ directory should no longer exist.
	nsDir := store.secretsDir + "/ns"
	if _, err := os.Stat(nsDir); err == nil {
		t.Error("empty namespace directory was not removed")
	}
}

func TestServer_NamespaceEndpointRoundTrip(t *testing.T) {
	// spec: Namespaced Secret Names — HTTP round-trip
	srv, _ := testServer(t)

	resp := do(t, srv, http.MethodPost, "/secrets/ha/token", testToken,
		bytes.NewReader(testCiphertext(t, "ha-token-value")))
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST got %d, want 204", resp.StatusCode)
	}

	resp = do(t, srv, http.MethodGet, "/secrets/ha/token", testToken, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET got %d, want 200", resp.StatusCode)
	}
}

func TestServer_InvalidNameDoubleSlashRejected(t *testing.T) {
	// spec: Namespaced Secret Names — Invalid name with double slash rejected
	// double slash gets path-cleaned by the HTTP stack; test the regex directly.
	if nameRe.MatchString("foo//bar") {
		t.Error("nameRe accepted double slash")
	}
}

func TestServer_InvalidNameDotDotSegmentRejected(t *testing.T) {
	// spec: Namespaced Secret Names — Invalid name with .. segment rejected
	for _, bad := range []string{"../evil", "foo/../bar", "..", "foo/.."} {
		if validName(bad) {
			t.Errorf("validName(%q) returned true, want false", bad)
		}
	}
}
