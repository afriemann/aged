package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"filippo.io/age"
)

const (
	// trustManifestName is the name the manifest envelope is bound to. It is
	// in the reserved namespace, so no secret can ever carry it.
	trustManifestName = reservedNamespace + "/trust"

	// trustSigPrefix domain-separates manifest signatures.
	trustSigPrefix = "aged-trust-v1\n"

	// trustRetries bounds how often a command re-reads and retries after the
	// server reports that the manifest moved underneath it.
	trustRetries = 3
)

var (
	errNotTrusted = errors.New("this device is not trusted: none of your identities matches the trust manifest's recipients; " +
		"run `aged trust add <your-pubkey>` from a trusted device")
	errTrustChurn = errors.New("trust manifest kept changing; try again")
	errTrustPin   = errors.New("trust manifest rejected")
)

// trustOverride adjusts one secret's recipients relative to the default set.
type trustOverride struct {
	Add    []string `json:"add,omitempty"`
	Remove []string `json:"remove,omitempty"`
}

// trustBody is the signed content of the manifest. The signing private key
// lives inside it so that only holders of a default-set key (who can decrypt
// the manifest) can produce a valid successor.
type trustBody struct {
	Counter     uint64                   `json:"counter"`
	Default     []string                 `json:"default"`
	Overrides   map[string]trustOverride `json:"overrides,omitempty"`
	SigningPub  ed25519.PublicKey        `json:"signing_pub"`
	SigningPriv ed25519.PrivateKey       `json:"signing_priv"`
}

// signedManifest is the manifest plaintext (inside the name-binding
// envelope): the exact body bytes and a signature over them.
type signedManifest struct {
	Body json.RawMessage `json:"body"`
	Sig  []byte          `json:"sig"`
}

// trustState is a verified manifest together with the server version it was
// read at.
type trustState struct {
	body    trustBody
	version string
}

// effective returns the recipients for the named secret: its overrides' adds
// unioned with the default set, minus its overrides' removes.
func (b trustBody) effective(name string) []string {
	ov := b.Overrides[name]
	keys := unionKeys(b.Default, ov.Add)
	return slices.DeleteFunc(keys, func(k string) bool { return slices.Contains(ov.Remove, k) })
}

func (b trustBody) clone() trustBody {
	c := b
	c.Default = slices.Clone(b.Default)
	c.Overrides = make(map[string]trustOverride, len(b.Overrides))
	for n, ov := range b.Overrides {
		c.Overrides[n] = trustOverride{Add: slices.Clone(ov.Add), Remove: slices.Clone(ov.Remove)}
	}
	return c
}

// unionKeys returns the sorted set union of the given key lists.
func unionKeys(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		for _, k := range l {
			if !slices.Contains(out, k) {
				out = append(out, k)
			}
		}
	}
	slices.Sort(out)
	return out
}

func sameKeys(a, b []string) bool {
	return slices.Equal(unionKeys(a), unionKeys(b))
}

// localRecipients returns the recipient strings of every X25519 identity in
// the caller's identity file.
func localRecipients(ids []age.Identity) ([]string, error) {
	var keys []string
	for _, id := range ids {
		if x, ok := id.(*age.X25519Identity); ok {
			keys = append(keys, x.Recipient().String())
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("identity file does not contain an X25519 identity")
	}
	return keys, nil
}

func encryptTo(recipients []age.Recipient, plaintext []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return nil, fmt.Errorf("create age writer: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	return buf.Bytes(), nil
}

func parseRecipient(key string) (age.Recipient, error) {
	r, err := age.ParseX25519Recipient(key)
	if err != nil {
		return nil, fmt.Errorf("invalid age public key %q: %w", key, err)
	}
	return r, nil
}

func encryptToKeys(keys []string, plaintext []byte) ([]byte, error) {
	recipients := make([]age.Recipient, 0, len(keys))
	for _, k := range keys {
		r, err := parseRecipient(k)
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, r)
	}
	return encryptTo(recipients, plaintext)
}

// newTrustBody creates the initial manifest body for a first trust command:
// the local keys as the default set and a fresh signing key pair.
func newTrustBody(local []string) (trustBody, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return trustBody{}, fmt.Errorf("generate signing key: %w", err)
	}
	return trustBody{Default: unionKeys(local), SigningPub: pub, SigningPriv: priv}, nil
}

// sealManifest signs body, wraps it in the name-binding envelope and
// encrypts it to the body's default set.
func sealManifest(body trustBody) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("encode manifest: %w", err)
	}
	sig := ed25519.Sign(body.SigningPriv, append([]byte(trustSigPrefix), raw...))
	plain, err := json.Marshal(signedManifest{Body: raw, Sig: sig})
	if err != nil {
		return nil, fmt.Errorf("encode manifest: %w", err)
	}
	return encryptToKeys(body.Default, packEnvelope(trustManifestName, plain))
}

// openManifest decrypts and parses a manifest and checks that its signature
// verifies under the signing key it carries. That proves integrity only;
// authenticity comes from comparing that key with the pinned one.
func openManifest(ciphertext []byte, ids []age.Identity) (trustBody, error) {
	plain, err := decryptCiphertext(ciphertext, ids)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return trustBody{}, errNotTrusted
		}
		return trustBody{}, fmt.Errorf("decrypt trust manifest: %w", err)
	}
	inner, err := unpackEnvelope(trustManifestName, plain)
	if err != nil {
		return trustBody{}, fmt.Errorf("trust manifest: %w", err)
	}
	var sm signedManifest
	if err := json.Unmarshal(inner, &sm); err != nil {
		return trustBody{}, fmt.Errorf("parse trust manifest: %w", err)
	}
	var body trustBody
	if err := json.Unmarshal(sm.Body, &body); err != nil {
		return trustBody{}, fmt.Errorf("parse trust manifest: %w", err)
	}
	if len(body.SigningPub) != ed25519.PublicKeySize ||
		!ed25519.Verify(body.SigningPub, append([]byte(trustSigPrefix), sm.Body...), sm.Sig) {
		return trustBody{}, fmt.Errorf("%w: bad signature", errTrustPin)
	}
	return body, nil
}

// loadManifest fetches, decrypts and verifies the manifest, applying the
// pin check. It returns (nil, nil) when no manifest exists.
func loadManifest(ids []age.Identity) (*trustState, error) {
	resp, err := doRequest("GET", "/trust", nil, nil)
	if err != nil {
		return nil, err
	}
	switch resp.Status {
	case http.StatusOK:
	case http.StatusNotFound:
		pins, err := readPins()
		if err != nil {
			return nil, err
		}
		if _, pinned := pins[pinKey()]; pinned {
			return nil, fmt.Errorf("%w: the server has no manifest but one was pinned earlier; "+
				"if you reset it on purpose, delete this server's entry from %s", errTrustPin, pinStorePath())
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("server returned %d: %s", resp.Status, strings.TrimRight(string(resp.Body), "\n"))
	}
	body, err := openManifest(resp.Body, ids)
	if err != nil {
		return nil, err
	}
	if err := checkPin(body); err != nil {
		return nil, err
	}
	return &trustState{body: body, version: resp.Header.Get("ETag")}, nil
}

// trustPin records, per server and user, the signing key accepted on first
// use and the highest manifest counter seen.
type trustPin struct {
	SigningPub []byte `json:"signing_pub"`
	Counter    uint64 `json:"counter"`
}

// pinStorePath keeps pins beside the identity file, so each device's pins
// live and are backed up (or not) with that device's own key.
func pinStorePath() string {
	return filepath.Join(filepath.Dir(loadConfig().Identity), "trust-pins.json")
}

// pinKey identifies a server and user: the URL plus a truncated hash of the
// token, which is never stored itself.
func pinKey() string {
	sum := sha256.Sum256([]byte(loadConfig().Token))
	return serverURL() + "|" + hex.EncodeToString(sum[:8])
}

func readPins() (map[string]trustPin, error) {
	data, err := os.ReadFile(pinStorePath())
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]trustPin{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read trust pins: %w", err)
	}
	pins := map[string]trustPin{}
	if err := json.Unmarshal(data, &pins); err != nil {
		return nil, fmt.Errorf("parse trust pins: %w", err)
	}
	return pins, nil
}

func writePin(key string, pin trustPin) error {
	pins, err := readPins()
	if err != nil {
		return err
	}
	pins[key] = pin
	data, err := json.Marshal(pins)
	if err != nil {
		return fmt.Errorf("encode trust pins: %w", err)
	}
	path := pinStorePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create pin directory: %w", err)
	}
	return writeFileAtomic(path, data)
}

// signingFingerprint is a short, comparable rendering of a signing key.
func signingFingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// confirmPin asks the user to accept a first-seen manifest. A variable so
// tests can drive it.
var confirmPin = defaultConfirmPin

// trustAssumeYes reports whether pin confirmation is pre-approved.
func trustAssumeYes() bool {
	return os.Getenv("AGED_TRUST_YES") == "1"
}

// confirmRepin asks the user to accept a changed signing key. AGED_TRUST_YES
// does not cover it: a changed key is the one signal of a forged manifest.
var confirmRepin = defaultConfirmRepin

func defaultConfirmRepin(prompt string) bool {
	if os.Getenv("AGED_TRUST_REPIN") == "1" {
		return true
	}
	return askTTY(prompt, "Accept the new signing key?")
}

func defaultConfirmPin(prompt string) bool {
	if trustAssumeYes() {
		return true
	}
	return askTTY(prompt, "Trust this manifest?")
}

func askTTY(prompt, question string) bool {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return false
	}
	defer tty.Close()
	fmt.Fprint(os.Stderr, prompt+"\n"+question+" [y/N] ")
	var answer string
	if _, err := fmt.Fscanln(tty, &answer); err != nil && !errors.Is(err, io.EOF) {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(answer), "y") || strings.EqualFold(answer, "yes")
}

// checkPin authenticates a verified manifest body against the stored pin:
// the first manifest seen for this server and user is shown to the user and
// pinned on confirmation; afterwards the signing key must match and the
// counter must never decrease.
func checkPin(body trustBody) error {
	key := pinKey()
	pins, err := readPins()
	if err != nil {
		return err
	}
	pin, pinned := pins[key]
	if !pinned {
		prompt := fmt.Sprintf("First use of the trust manifest on %s.\nSigning key fingerprint: %s\nTrusted recipients:\n  %s",
			serverURL(), signingFingerprint(body.SigningPub), strings.Join(body.Default, "\n  "))
		if !confirmPin(prompt) {
			return fmt.Errorf("%w: not confirmed (set AGED_TRUST_YES=1, or pass --yes to `aged trust`, to confirm non-interactively)", errTrustPin)
		}
		return writePin(key, trustPin{SigningPub: body.SigningPub, Counter: body.Counter})
	}
	if body.Counter < pin.Counter {
		return fmt.Errorf("%w: rollback detected (counter %d is lower than the last seen %d)", errTrustPin, body.Counter, pin.Counter)
	}
	if !bytes.Equal(pin.SigningPub, body.SigningPub) {
		prompt := fmt.Sprintf("The trust manifest on %s is signed by a different key.\nPinned fingerprint: %s\nNew fingerprint: %s\nTrusted recipients:\n  %s\nThis is expected after `aged trust remove`; otherwise the server or token may be compromised.",
			serverURL(), signingFingerprint(pin.SigningPub), signingFingerprint(body.SigningPub), strings.Join(body.Default, "\n  "))
		if !confirmRepin(prompt) {
			return fmt.Errorf("%w: signing key differs from the pinned key (fingerprint %s); confirm interactively or set AGED_TRUST_REPIN=1", errTrustPin, signingFingerprint(body.SigningPub))
		}
		return writePin(key, trustPin{SigningPub: body.SigningPub, Counter: body.Counter})
	}
	if body.Counter > pin.Counter {
		return writePin(key, trustPin{SigningPub: pin.SigningPub, Counter: body.Counter})
	}
	return nil
}
