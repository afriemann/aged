package main

// spec: openspec/specs/aged/spec.md

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"filippo.io/age"
)

type device struct {
	id   *age.X25519Identity
	path string
}

func (d device) key() string { return d.id.Recipient().String() }

func newDevice(t *testing.T) device {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identity.age")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("# test\n%s\n", id)), 0o600); err != nil {
		t.Fatal(err)
	}
	return device{id: id, path: path}
}

// use points the client at srv as device d, with first-use pin confirmation
// auto-accepted.
func (d device) use(t *testing.T, srv string) {
	t.Helper()
	t.Setenv("AGED_SERVER_URL", srv)
	t.Setenv("AGED_TOKEN", testToken)
	t.Setenv("AGED_IDENTITY", d.path)
	t.Setenv("AGED_CONFIG", "/tmp/definitely-absent-aged-test.toml")
	t.Setenv("AGED_TRUST_YES", "1")
}

// canRead reports whether d can decrypt the stored secret name.
func canRead(t *testing.T, d device, name string) bool {
	t.Helper()
	data, status, err := requestBytes("GET", "/secrets/"+name, nil)
	if err != nil || status != http.StatusOK {
		t.Fatalf("fetch %s: status %d err %v", name, status, err)
	}
	_, err = decryptWithIdentity(t, d.id, data, name)
	return err == nil
}

func trust(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := runTrust(args, &out)
	return out.String(), err
}

func mustTrust(t *testing.T, args ...string) string {
	t.Helper()
	out, err := trust(t, args...)
	if err != nil {
		t.Fatalf("trust %v: %v\n%s", args, err, out)
	}
	return out
}

func sorted(s []string) []string {
	c := append([]string(nil), s...)
	sort.Strings(c)
	return c
}

func TestTrustBody_EffectiveSet(t *testing.T) {
	b := trustBody{Default: []string{"U", "Y"}, Overrides: map[string]trustOverride{
		"foo": {Add: []string{"X"}},
		"bar": {Remove: []string{"Y"}},
	}}
	cases := map[string][]string{
		"foo":   {"U", "X", "Y"},
		"bar":   {"U"},
		"other": {"U", "Y"},
	}
	for name, want := range cases {
		if got := sorted(b.effective(name)); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("effective(%s) = %v, want %v", name, got, want)
		}
	}
}

func TestTrust_AddBootstrapsManifestAndReencrypts(t *testing.T) {
	srv, _ := testServer(t)
	a, x := newDevice(t), newDevice(t)
	a.use(t, srv.URL)
	if err := set("foo", []byte("v")); err != nil {
		t.Fatal(err)
	}
	mustTrust(t, "add", x.key())

	if !canRead(t, x, "foo") || !canRead(t, a, "foo") {
		t.Error("foo must be readable by both the local key and X")
	}
	if _, status, _ := requestBytes("GET", "/trust", nil); status != http.StatusOK {
		t.Errorf("manifest not stored (status %d)", status)
	}
}

func TestTrust_SetEncryptsToEveryEffectiveRecipient(t *testing.T) {
	srv, _ := testServer(t)
	a, v := newDevice(t), newDevice(t)
	a.use(t, srv.URL)
	mustTrust(t, "add", v.key())
	if err := set("n", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if !canRead(t, a, "n") || !canRead(t, v, "n") {
		t.Error("secret must be decryptable by both default-set keys")
	}
}

func TestTrust_SetWithoutManifestEncryptsToLocalKeyOnly(t *testing.T) {
	srv, _ := testServer(t)
	a, other := newDevice(t), newDevice(t)
	a.use(t, srv.URL)
	if err := set("n", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if !canRead(t, a, "n") || canRead(t, other, "n") {
		t.Error("without a manifest only the local key may decrypt")
	}
}

func TestTrust_PerSecretAdditionFollowsLaterDefaultChanges(t *testing.T) {
	srv, _ := testServer(t)
	u, x, y := newDevice(t), newDevice(t), newDevice(t)
	u.use(t, srv.URL)
	mustTrust(t, "add", u.key()) // bootstrap with just U
	if err := set("foo", []byte("0451")); err != nil {
		t.Fatal(err)
	}
	if err := set("bar", []byte("b")); err != nil {
		t.Fatal(err)
	}
	mustTrust(t, "add", x.key(), "--secret", "foo")
	mustTrust(t, "add", y.key())

	for _, tc := range []struct {
		name string
		d    device
		want bool
	}{
		{"foo", u, true}, {"foo", x, true}, {"foo", y, true},
		{"bar", u, true}, {"bar", x, false}, {"bar", y, true},
	} {
		if got := canRead(t, tc.d, tc.name); got != tc.want {
			t.Errorf("canRead(%s, %s) = %v, want %v", tc.name, tc.d.key()[:8], got, tc.want)
		}
	}
}

func TestTrust_PerSecretRemovalWinsOverDefault(t *testing.T) {
	srv, _ := testServer(t)
	u, v := newDevice(t), newDevice(t)
	u.use(t, srv.URL)
	mustTrust(t, "add", v.key())
	for _, n := range []string{"foo", "bar"} {
		if err := set(n, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	mustTrust(t, "remove", v.key(), "--secret", "foo")
	if canRead(t, v, "foo") || !canRead(t, u, "foo") {
		t.Error("foo must be readable by U only")
	}
	if !canRead(t, v, "bar") {
		t.Error("bar must stay readable by V")
	}
	if err := set("foo", []byte("again")); err != nil {
		t.Fatal(err)
	}
	if canRead(t, v, "foo") {
		t.Error("re-set must keep the per-secret removal")
	}
}

func TestTrust_ExistingSecretKeepsEffectiveSetOnReset(t *testing.T) {
	srv, _ := testServer(t)
	u, x := newDevice(t), newDevice(t)
	u.use(t, srv.URL)
	mustTrust(t, "add", u.key())
	if err := set("foo", []byte("a")); err != nil {
		t.Fatal(err)
	}
	mustTrust(t, "add", x.key(), "--secret", "foo")
	if err := set("foo", []byte("b")); err != nil {
		t.Fatal(err)
	}
	if !canRead(t, x, "foo") {
		t.Error("X must still read foo after a re-set")
	}
}

func TestTrust_DryRunChangesNothing(t *testing.T) {
	srv, _ := testServer(t)
	a, x := newDevice(t), newDevice(t)
	a.use(t, srv.URL)
	if err := set("foo", []byte("v")); err != nil {
		t.Fatal(err)
	}
	before := fetchRawStoredBytes(t, "foo")
	out := mustTrust(t, "add", x.key(), "--dry-run")
	if !strings.Contains(out, "foo") {
		t.Errorf("dry run must list affected secrets, got %q", out)
	}
	if !bytes.Equal(before, fetchRawStoredBytes(t, "foo")) {
		t.Error("secret changed during dry run")
	}
	if _, status, _ := requestBytes("GET", "/trust", nil); status != http.StatusNotFound {
		t.Errorf("manifest written during dry run (status %d)", status)
	}
}

func TestTrust_RemoveRevokesAffectedSecretAndWarns(t *testing.T) {
	srv, _ := testServer(t)
	a, x := newDevice(t), newDevice(t)
	a.use(t, srv.URL)
	if err := set("with", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := set("without", []byte("2")); err != nil {
		t.Fatal(err)
	}
	mustTrust(t, "add", x.key(), "--secret", "with")

	out := mustTrust(t, "remove", x.key())
	if canRead(t, x, "with") {
		t.Error("X must no longer decrypt 'with'")
	}
	if !canRead(t, a, "without") {
		t.Error("A must still decrypt 'without'")
	}
	if !strings.Contains(out, "previously copied") {
		t.Errorf("missing residual-access warning: %q", out)
	}
}

func TestTrust_RemoveRefusesLastOrLocalKeyWithoutForce(t *testing.T) {
	srv, _ := testServer(t)
	a := newDevice(t)
	a.use(t, srv.URL)
	mustTrust(t, "add", newDevice(t).key())
	if _, err := trust(t, "remove", a.key()); err == nil {
		t.Fatal("removing the local key must be refused without --force")
	}
	if _, err := trust(t, "remove", a.key(), "--force"); err != nil {
		t.Errorf("--force must allow it: %v", err)
	}
}

func TestTrust_SyncRepairsPartialRun(t *testing.T) {
	srv, _ := testServer(t)
	a, v := newDevice(t), newDevice(t)
	a.use(t, srv.URL)
	mustTrust(t, "add", v.key())
	// A secret written by a device that predates the trust change: encrypted
	// to A only, uploaded against the current manifest version.
	_, _, hdr := fetchTrust(t)
	ct := encryptForTest(t, "foo", "v", a.id.Recipient())
	if status := postForTest(t, "foo", ct, map[string]string{trustHeader: hdr.Get("ETag")}); status != http.StatusNoContent {
		t.Fatalf("seed upload: %d", status)
	}
	if canRead(t, v, "foo") {
		t.Fatal("precondition: V must not read foo yet")
	}
	mustTrust(t, "sync")
	if !canRead(t, v, "foo") {
		t.Error("sync must re-encrypt foo to the manifest's default set")
	}
}

func TestTrust_UndecryptableSecretBlocksManifestAdvance(t *testing.T) {
	srv, _ := testServer(t)
	a, x := newDevice(t), newDevice(t)
	a.use(t, srv.URL)
	foreign := newDevice(t)
	storeCiphertextViaHTTP(t, foreign.id.Recipient(), "locked", "z")
	if err := set("fine", []byte("y")); err != nil {
		t.Fatal(err)
	}
	fineBefore := fetchRawStoredBytes(t, "fine")

	out, err := trust(t, "add", x.key())
	if err == nil || !strings.Contains(out+err.Error(), "locked") {
		t.Fatalf("expected failure naming the skipped secret, got err=%v out=%q", err, out)
	}
	if _, status, _ := requestBytes("GET", "/trust", nil); status != http.StatusNotFound {
		t.Errorf("manifest advanced despite skipped secret (status %d)", status)
	}
	if !bytes.Equal(fineBefore, fetchRawStoredBytes(t, "fine")) {
		t.Error("a decryptable secret was rewritten although the run was refused")
	}
	if _, err := trust(t, "add", x.key(), "--allow-skipped"); err != nil {
		t.Errorf("--allow-skipped must proceed: %v", err)
	}
}

func TestTrust_ConcurrentManifestChangeIsRetried(t *testing.T) {
	srv, _ := testServer(t)
	a, x, y := newDevice(t), newDevice(t), newDevice(t)
	a.use(t, srv.URL)
	mustTrust(t, "add", x.key())

	fired := false
	trustAttemptHook = func() {
		if fired {
			return
		}
		fired = true
		// Another run of the same device lands between read and write.
		trustAttemptHook = nil
		mustTrust(t, "add", y.key())
	}
	t.Cleanup(func() { trustAttemptHook = nil })

	v := newDevice(t)
	mustTrust(t, "add", v.key())
	if !fired {
		t.Fatal("hook never fired")
	}
	out := mustTrust(t, "list")
	for _, d := range []device{a, x, y, v} {
		if !strings.Contains(out, d.key()) {
			t.Errorf("default set lost %s after the retry", d.key()[:10])
		}
	}
}

func TestTrust_AddOfTrustedKeyIsIdempotent(t *testing.T) {
	srv, _ := testServer(t)
	a, x := newDevice(t), newDevice(t)
	a.use(t, srv.URL)
	mustTrust(t, "add", x.key())
	before, _, hdr := fetchTrust(t)
	mustTrust(t, "add", x.key())
	after, _, hdr2 := fetchTrust(t)
	if !bytes.Equal(before, after) || hdr.Get("ETag") != hdr2.Get("ETag") {
		t.Error("re-adding a trusted key must not rewrite the manifest")
	}
}

func TestTrust_UntrustedDeviceIsToldSo(t *testing.T) {
	srv, _ := testServer(t)
	a, stranger := newDevice(t), newDevice(t)
	a.use(t, srv.URL)
	mustTrust(t, "add", newDevice(t).key())

	stranger.use(t, srv.URL)
	for name, fn := range map[string]func() error{
		"set":   func() error { return set("n", []byte("v")) },
		"trust": func() error { _, err := trust(t, "list"); return err },
	} {
		if err := fn(); !errors.Is(err, errNotTrusted) {
			t.Errorf("%s: err = %v, want errNotTrusted", name, err)
		}
	}
}

func TestTrust_FirstUseRequiresConfirmation(t *testing.T) {
	srv, _ := testServer(t)
	a, b := newDevice(t), newDevice(t)
	a.use(t, srv.URL)
	mustTrust(t, "add", b.key())

	b.use(t, srv.URL)
	t.Setenv("AGED_TRUST_YES", "")
	var prompt string
	confirmPin = func(p string) bool { prompt = p; return false }
	t.Cleanup(func() { confirmPin = defaultConfirmPin })
	if err := set("n", []byte("v")); err == nil {
		t.Fatal("set must fail when the pin confirmation is declined")
	}
	if !strings.Contains(prompt, a.key()) || !strings.Contains(prompt, b.key()) {
		t.Errorf("prompt must show the default recipients, got %q", prompt)
	}
	confirmPin = func(string) bool { return true }
	if err := set("n", []byte("v")); err != nil {
		t.Fatalf("set after confirming: %v", err)
	}
	confirmPin = func(string) bool { t.Fatal("must not prompt twice"); return false }
	if err := set("n2", []byte("v")); err != nil {
		t.Fatal(err)
	}
}

func TestTrust_ForgedManifestRejected(t *testing.T) {
	srv, _ := testServer(t)
	a := newDevice(t)
	a.use(t, srv.URL)
	mustTrust(t, "add", newDevice(t).key())
	pins := pinStorePath()
	pinned, err := os.ReadFile(pins)
	if err != nil {
		t.Fatal(err)
	}
	// Replace the pinned signing key with a different one: the stored
	// manifest now looks forged relative to the pin.
	forged := bytes.Replace(pinned, []byte(`"signing_pub":"`), []byte(`"signing_pub":"AAAA`), 1)
	if bytes.Equal(forged, pinned) {
		t.Fatalf("pin file layout unexpected: %s", pinned)
	}
	if err := os.WriteFile(pins, forged, 0o600); err != nil {
		t.Fatal(err)
	}
	confirmRepin = func(string) bool { return false }
	t.Cleanup(func() { confirmRepin = defaultConfirmRepin })
	if err := set("n", []byte("v")); err == nil || !strings.Contains(err.Error(), "signing key") {
		t.Errorf("err = %v, want signing key mismatch", err)
	}
}

func TestTrust_RemoveRotatesSigningKeyAndOtherDevicesRepin(t *testing.T) {
	srv, _ := testServer(t)
	a, b, x := newDevice(t), newDevice(t), newDevice(t)
	a.use(t, srv.URL)
	mustTrust(t, "add", b.key())
	mustTrust(t, "add", x.key())
	b.use(t, srv.URL)
	if err := set("warm", []byte("v")); err != nil {
		t.Fatal(err)
	}
	pinBefore, err := os.ReadFile(pinStorePath())
	if err != nil {
		t.Fatal(err)
	}

	a.use(t, srv.URL)
	mustTrust(t, "remove", x.key())

	b.use(t, srv.URL)
	if err := os.WriteFile(pinStorePath(), pinBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	var prompt string
	confirmRepin = func(p string) bool { prompt = p; return false }
	t.Cleanup(func() { confirmRepin = defaultConfirmRepin })
	if err := set("n", []byte("v")); err == nil {
		t.Fatal("set must fail until the new signing key is confirmed")
	}
	if !strings.Contains(prompt, "different key") {
		t.Errorf("prompt = %q", prompt)
	}
	confirmRepin = func(string) bool { return true }
	if err := set("n", []byte("v")); err != nil {
		t.Fatalf("set after confirming new key: %v", err)
	}
}

func TestTrust_RemoveSyncsEverySecretToTheNewSet(t *testing.T) {
	srv, store := testServer(t)
	a, x := newDevice(t), newDevice(t)
	a.use(t, srv.URL)
	mustTrust(t, "add", x.key())

	// A write by another device that still used the old recipient set lands
	// after the remove's manifest write, i.e. before its follow-up sync.
	calls := 0
	trustAttemptHook = func() {
		calls++
		if calls != 2 {
			return
		}
		ct, err := encryptToKeys([]string{a.key(), x.key()}, packEnvelope("late", []byte("v")))
		if err != nil {
			t.Error(err)
			return
		}
		if err := store.setValue("late", ct); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { trustAttemptHook = nil })
	mustTrust(t, "remove", x.key())
	if canRead(t, x, "late") {
		t.Error("X must not decrypt a secret written to the old set after the remove")
	}
	if !canRead(t, a, "late") {
		t.Error("A must still decrypt it")
	}
}

func TestTrust_RolledBackManifestRejected(t *testing.T) {
	srv, _ := testServer(t)
	a := newDevice(t)
	a.use(t, srv.URL)
	mustTrust(t, "add", newDevice(t).key())
	old, _, _ := fetchTrust(t)
	mustTrust(t, "add", newDevice(t).key())
	_, _, cur := fetchTrust(t)

	// A malicious server restores the older manifest.
	if status := putTrustForTest(t, old, cur.Get("ETag")); status != http.StatusNoContent {
		t.Fatalf("restore old manifest: %d", status)
	}
	if err := set("n", []byte("v")); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Errorf("err = %v, want rollback error", err)
	}
}

func TestTrust_ReservedNameRejectedByClientBeforeAnyRequest(t *testing.T) {
	a := newDevice(t)
	a.use(t, "http://127.0.0.1:1") // nothing listens
	if err := set(".aged/trust", []byte("v")); err == nil || strings.Contains(err.Error(), "request failed") {
		t.Errorf("set: err = %v, want local rejection", err)
	}
	if err := get(".AGED/trust"); err == nil || strings.Contains(err.Error(), "request failed") {
		t.Errorf("get: err = %v, want local rejection", err)
	}
	if err := del(".aged/trust"); err == nil || strings.Contains(err.Error(), "request failed") {
		t.Errorf("delete: err = %v, want local rejection", err)
	}
}

func fetchTrust(t *testing.T) ([]byte, int, http.Header) {
	t.Helper()
	resp, err := doRequest("GET", "/trust", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return resp.Body, resp.Status, resp.Header
}

func putTrustForTest(t *testing.T, blob []byte, ifMatch string) int {
	t.Helper()
	resp, err := doRequest("PUT", "/trust", bytes.NewReader(blob), map[string]string{"If-Match": ifMatch})
	if err != nil {
		t.Fatal(err)
	}
	return resp.Status
}

func postForTest(t *testing.T, name string, ct []byte, hdr map[string]string) int {
	t.Helper()
	resp, err := doRequest("POST", "/secrets/"+name, bytes.NewReader(ct), hdr)
	if err != nil {
		t.Fatal(err)
	}
	return resp.Status
}

func encryptForTest(t *testing.T, name, value string, r age.Recipient) []byte {
	t.Helper()
	ct, err := encryptTo([]age.Recipient{r}, packEnvelope(name, []byte(value)))
	if err != nil {
		t.Fatal(err)
	}
	return ct
}

func TestTrust_BadSignatureRejected(t *testing.T) {
	srv, _ := testServer(t)
	a := newDevice(t)
	a.use(t, srv.URL)
	mustTrust(t, "add", newDevice(t).key())
	_, _, hdr := fetchTrust(t)

	ids, err := loadClientIdentities()
	if err != nil {
		t.Fatal(err)
	}
	st, err := loadManifest(ids)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(st.body)
	plain, _ := json.Marshal(signedManifest{Body: raw, Sig: make([]byte, ed25519.SignatureSize)})
	blob, err := encryptToKeys(st.body.Default, packEnvelope(trustManifestName, plain))
	if err != nil {
		t.Fatal(err)
	}
	if status := putTrustForTest(t, blob, hdr.Get("ETag")); status != http.StatusNoContent {
		t.Fatalf("PUT forged manifest: %d", status)
	}
	if err := set("n", []byte("v")); err == nil || !strings.Contains(err.Error(), "bad signature") {
		t.Errorf("err = %v, want bad signature", err)
	}
}

func TestTrust_MissingManifestAfterPinningIsRejected(t *testing.T) {
	srv, store := testServer(t)
	a := newDevice(t)
	a.use(t, srv.URL)
	mustTrust(t, "add", newDevice(t).key())
	if err := os.Remove(store.trustPath()); err != nil {
		t.Fatal(err)
	}
	if err := set("n", []byte("v")); err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Errorf("err = %v, want a pinned-but-missing error", err)
	}
}

func TestTrust_RemoveOfUntrustedKeyKeepsManifestAndSigningKey(t *testing.T) {
	srv, _ := testServer(t)
	a := newDevice(t)
	a.use(t, srv.URL)
	mustTrust(t, "add", newDevice(t).key())
	before, _, _ := fetchTrust(t)
	out := mustTrust(t, "remove", newDevice(t).key())
	after, _, _ := fetchTrust(t)
	if !bytes.Equal(before, after) {
		t.Errorf("manifest changed for a key that was never trusted: %q", out)
	}
}

func TestConfirmRepin_IgnoresTrustYes(t *testing.T) {
	if tty, err := os.Open("/dev/tty"); err == nil {
		tty.Close()
		t.Skip("a controlling terminal would be prompted")
	}
	t.Setenv("AGED_TRUST_YES", "1")
	t.Setenv("AGED_TRUST_REPIN", "")
	if defaultConfirmRepin("p") {
		t.Error("AGED_TRUST_YES must not confirm a changed signing key")
	}
	t.Setenv("AGED_TRUST_REPIN", "1")
	if !defaultConfirmRepin("p") {
		t.Error("AGED_TRUST_REPIN=1 must confirm")
	}
}
