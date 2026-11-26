package main

// spec: openspec/specs/aged/spec.md

import (
	"net/http"
	"strings"
	"testing"
)

// ageBlob is a minimal body that passes the server's age v1 magic check.
const ageBlob = ageV1Magic + "payload"

func send(t *testing.T, srvURL, method, path string, body string, hdr map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, srvURL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestServerTrust_ReservedNameRejectedOnEveryRoute(t *testing.T) {
	srv, _ := testServer(t)
	for _, name := range []string{".aged/trust", ".AGED/trust", ".Aged/x/y"} {
		for _, m := range []string{"GET", "POST", "DELETE"} {
			resp := send(t, srv.URL, m, "/secrets/"+name, ageBlob, nil)
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("%s %s: status %d, want 400", m, name, resp.StatusCode)
			}
		}
	}
}

func TestServerTrust_CreateOnlyManifestWrite(t *testing.T) {
	srv, _ := testServer(t)
	resp := send(t, srv.URL, "PUT", "/trust", ageBlob, map[string]string{"If-None-Match": "*"})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("create: status %d", resp.StatusCode)
	}
	etag := resp.Header.Get("ETag")
	if etag == "" {
		t.Fatal("no ETag returned")
	}
	get := send(t, srv.URL, "GET", "/trust", "", nil)
	if get.StatusCode != http.StatusOK || get.Header.Get("ETag") != etag {
		t.Errorf("GET /trust: status %d etag %q want %q", get.StatusCode, get.Header.Get("ETag"), etag)
	}
	again := send(t, srv.URL, "PUT", "/trust", ageBlob+"2", map[string]string{"If-None-Match": "*"})
	if again.StatusCode != http.StatusPreconditionFailed {
		t.Errorf("second create: status %d, want 412", again.StatusCode)
	}
}

func TestServerTrust_StaleManifestWriteRejected(t *testing.T) {
	srv, _ := testServer(t)
	send(t, srv.URL, "PUT", "/trust", ageBlob, map[string]string{"If-None-Match": "*"})
	resp := send(t, srv.URL, "PUT", "/trust", ageBlob+"2", map[string]string{"If-Match": `"stale"`})
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("status %d, want 412", resp.StatusCode)
	}
	cur := send(t, srv.URL, "GET", "/trust", "", nil)
	if cur.Header.Get("ETag") == "" || cur.StatusCode != http.StatusOK {
		t.Fatal("manifest unexpectedly missing")
	}
}

func TestServerTrust_ManifestWriteRequiresPrecondition(t *testing.T) {
	srv, _ := testServer(t)
	resp := send(t, srv.URL, "PUT", "/trust", ageBlob, nil)
	if resp.StatusCode != http.StatusPreconditionRequired {
		t.Errorf("status %d, want 428", resp.StatusCode)
	}
}

func TestServerTrust_SetAgainstMovedManifestRejected(t *testing.T) {
	srv, _ := testServer(t)
	first := send(t, srv.URL, "PUT", "/trust", ageBlob, map[string]string{"If-None-Match": "*"})
	old := first.Header.Get("ETag")
	send(t, srv.URL, "PUT", "/trust", ageBlob+"2", map[string]string{"If-Match": old})
	resp := send(t, srv.URL, "POST", "/secrets/foo", ageBlob, map[string]string{"X-Aged-Trust": old})
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Errorf("status %d, want 412", resp.StatusCode)
	}
	if g := send(t, srv.URL, "GET", "/secrets/foo", "", nil); g.StatusCode != http.StatusNotFound {
		t.Errorf("secret was stored despite 412 (GET status %d)", g.StatusCode)
	}
}

func TestServerTrust_MissingTrustHeaderRejectedOnceManifestExists(t *testing.T) {
	srv, _ := testServer(t)
	if r := send(t, srv.URL, "POST", "/secrets/pre", ageBlob, nil); r.StatusCode != http.StatusNoContent {
		t.Fatalf("no manifest: status %d, want 204", r.StatusCode)
	}
	send(t, srv.URL, "PUT", "/trust", ageBlob, map[string]string{"If-None-Match": "*"})
	if r := send(t, srv.URL, "POST", "/secrets/foo", ageBlob, nil); r.StatusCode != http.StatusPreconditionRequired {
		t.Errorf("status %d, want 428", r.StatusCode)
	}
}

func TestServerTrust_SetWithCurrentManifestAcceptedAndSecretIfMatch(t *testing.T) {
	srv, _ := testServer(t)
	m := send(t, srv.URL, "PUT", "/trust", ageBlob, map[string]string{"If-None-Match": "*"})
	hdr := map[string]string{"X-Aged-Trust": m.Header.Get("ETag")}
	if r := send(t, srv.URL, "POST", "/secrets/foo", ageBlob, hdr); r.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d, want 204", r.StatusCode)
	}
	g := send(t, srv.URL, "GET", "/secrets/foo", "", nil)
	etag := g.Header.Get("ETag")
	if etag == "" {
		t.Fatal("secret GET returned no ETag")
	}
	hdr["If-Match"] = `"other"`
	if r := send(t, srv.URL, "POST", "/secrets/foo", ageBlob+"2", hdr); r.StatusCode != http.StatusPreconditionFailed {
		t.Errorf("stale If-Match: status %d, want 412", r.StatusCode)
	}
	hdr["If-Match"] = etag
	if r := send(t, srv.URL, "POST", "/secrets/foo", ageBlob+"2", hdr); r.StatusCode != http.StatusNoContent {
		t.Errorf("matching If-Match: status %d, want 204", r.StatusCode)
	}
}

func TestServerTrust_ManifestHiddenFromListing(t *testing.T) {
	srv, store := testServer(t)
	send(t, srv.URL, "PUT", "/trust", ageBlob, map[string]string{"If-None-Match": "*"})
	if err := store.setValue("a", []byte(ageBlob)); err != nil {
		t.Fatal(err)
	}
	names, err := store.listNames()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "a" {
		t.Errorf("listNames = %v, want [a]", names)
	}
}

func TestServerTrust_GetWithoutManifestIs404(t *testing.T) {
	srv, _ := testServer(t)
	if r := send(t, srv.URL, "GET", "/trust", "", nil); r.StatusCode != http.StatusNotFound {
		t.Errorf("status %d, want 404", r.StatusCode)
	}
}

func TestServerTrust_NonAgeManifestRejected(t *testing.T) {
	srv, _ := testServer(t)
	r := send(t, srv.URL, "PUT", "/trust", "plain", map[string]string{"If-None-Match": "*"})
	if r.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", r.StatusCode)
	}
}
