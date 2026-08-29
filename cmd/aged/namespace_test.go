package main

// spec: openspec/changes/namespace-support/specs/aged/spec.md

import (
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestStore_NamespacedRoundTrip(t *testing.T) {
	// spec: Namespaced Secret Names — Namespaced secret round-trip
	store := testStore(t)
	if err := store.setValue("ha/token", "secret-value"); err != nil {
		t.Fatalf("setValue: %v", err)
	}
	got, err := store.getValue("ha/token")
	if err != nil {
		t.Fatalf("getValue: %v", err)
	}
	if got != "secret-value" {
		t.Errorf("got %q, want %q", got, "secret-value")
	}
}

func TestStore_DeeplyNestedNamespace(t *testing.T) {
	// spec: Namespaced Secret Names — Deeply nested namespace
	store := testStore(t)
	if err := store.setValue("infra/db/password", "db-pass"); err != nil {
		t.Fatalf("setValue: %v", err)
	}
	got, err := store.getValue("infra/db/password")
	if err != nil {
		t.Fatalf("getValue: %v", err)
	}
	if got != "db-pass" {
		t.Errorf("got %q, want %q", got, "db-pass")
	}
}

func TestStore_ListReturnsNamespacedNames(t *testing.T) {
	// spec: Namespaced Secret Names — List returns namespaced names
	store := testStore(t)
	for name, val := range map[string]string{
		"ha/token":     "t1",
		"ha/client-id": "t2",
		"grafana/key":  "t3",
	} {
		if err := store.setValue(name, val); err != nil {
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
	if err := store.setValue("ns/only", "v"); err != nil {
		t.Fatalf("setValue: %v", err)
	}
	if err := store.removeValue("ns/only"); err != nil {
		t.Fatalf("removeValue: %v", err)
	}
	// The ns/ directory should no longer exist.
	import_path := store.secretsDir + "/ns"
	if _, err := os.Stat(import_path); err == nil {
		t.Error("empty namespace directory was not removed")
	}
}

func TestServer_NamespaceEndpointRoundTrip(t *testing.T) {
	// spec: Namespaced Secret Names — HTTP round-trip
	srv, _ := testServer(t)

	resp := do(t, srv, http.MethodPost, "/secrets/ha/token", testToken,
		strings.NewReader("ha-token-value"))
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
