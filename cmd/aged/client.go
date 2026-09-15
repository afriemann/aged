package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"filippo.io/age"
)

// serverURL returns the configured server base URL.
func serverURL() string {
	if url := loadConfig().ServerURL; url != "" {
		return strings.TrimRight(url, "/")
	}
	return "http://localhost:8743"
}

// requestBytes performs an authenticated HTTP request and returns the raw
// response body, the status code, and any transport error. Unlike request,
// it applies no trimming — callers handling binary ciphertext must use this,
// not request, to avoid corrupting a body whose last byte happens to be '\n'.
func requestBytes(method, path string, body io.Reader) ([]byte, int, error) {
	cfg := loadConfig()
	if cfg.Token == "" {
		return nil, 0, errors.New("AGED_TOKEN environment variable (or config file token) is required")
	}

	req, err := http.NewRequest(method, serverURL()+path, body)
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	return data, resp.StatusCode, err
}

// request performs an authenticated HTTP request and returns the trimmed
// body as a string, the status code, and any transport error. It is a thin
// wrapper over requestBytes for callers (list, delete, and non-2xx error
// display) that only ever handle text.
func request(method, path string, body io.Reader) (string, int, error) {
	data, status, err := requestBytes(method, path, body)
	return strings.TrimRight(string(data), "\n"), status, err
}

// loadClientIdentities loads every identity from the configured identity
// file, with an actionable error if it's missing.
func loadClientIdentities() ([]age.Identity, error) {
	path := loadConfig().Identity
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("no identity found at %s; run `aged init` first", path)
	}
	return loadIdentities(path)
}

// get fetches a secret's ciphertext, decrypts it locally using every
// identity found in the caller's identity file, verifies the name-binding
// envelope, and prints the value to stdout with no trailing newline, making
// it suitable as a chezmoi secret backend command. The server never
// performs or assists with decryption.
func get(name string) error {
	identities, err := loadClientIdentities()
	if err != nil {
		return err
	}

	ciphertext, status, err := requestBytes("GET", "/secrets/"+name, nil)
	if err != nil {
		return err
	}
	switch status {
	case http.StatusOK:
		// fall through
	case http.StatusNotFound:
		return fmt.Errorf("secret %q not found", name)
	default:
		return fmt.Errorf("server returned %d: %s", status, strings.TrimRight(string(ciphertext), "\n"))
	}

	plaintext, err := decryptCiphertext(ciphertext, identities)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return fmt.Errorf("secret %q was not encrypted to any identity in your identity file "+
				"(wrong machine, or a key rotated without migrating this secret)", name)
		}
		return fmt.Errorf("decrypt %q: %w", name, err)
	}

	value, err := unpackEnvelope(name, plaintext)
	if err != nil {
		return fmt.Errorf("secret %q: %w", name, err)
	}

	fmt.Print(string(value))
	return nil
}

// decryptCiphertext decrypts ciphertext trying every identity in identities.
func decryptCiphertext(ciphertext []byte, identities []age.Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), identities...)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// set reads a secret value from stdin, encrypts it locally to the caller's
// own identity — wrapped in a name-binding envelope — and uploads only the
// resulting ciphertext. The server never sees the plaintext value.
func set(name string) error {
	if !validName(name) {
		return fmt.Errorf("invalid secret name: %q", name)
	}

	identities, err := loadClientIdentities()
	if err != nil {
		return err
	}
	// set encrypts to the caller's own identity, so exactly one identity is
	// required; the first is used, matching the single-identity default case.
	// (Multiple identities in the file are meaningful for get's rotation
	// overlap, not for choosing an encryption target here.)
	x25519, ok := identities[0].(*age.X25519Identity)
	if !ok {
		return fmt.Errorf("identity file does not contain an X25519 identity")
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	// Strip exactly one trailing newline, if present — not all of them.
	// strings/bytes.TrimRight would strip every trailing '\n', silently
	// dropping bytes that are part of the actual value (e.g. a value whose
	// last two bytes are both '\n'). TrimSuffix removes the suffix once.
	data = bytes.TrimSuffix(data, []byte("\n"))

	envelope := packEnvelope(name, data)

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, x25519.Recipient())
	if err != nil {
		return fmt.Errorf("create age writer: %w", err)
	}
	if _, err := w.Write(envelope); err != nil {
		return fmt.Errorf("encrypt secret: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("encrypt secret: %w", err)
	}

	body, status, err := requestBytes("POST", "/secrets/"+name, bytes.NewReader(buf.Bytes()))
	if err != nil {
		return err
	}
	if status != http.StatusNoContent {
		return fmt.Errorf("server returned %d: %s", status, strings.TrimRight(string(body), "\n"))
	}
	return nil
}

// list prints one secret name per line.
func list() error {
	val, status, err := request("GET", "/secrets", nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("server returned %d: %s", status, val)
	}

	var names []string
	if err := json.Unmarshal([]byte(val), &names); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}
	for _, n := range names {
		fmt.Println(n)
	}
	return nil
}

// del removes a secret from the server.
func del(name string) error {
	_, status, err := request("DELETE", "/secrets/"+name, nil)
	if err != nil {
		return err
	}
	switch status {
	case http.StatusNoContent:
		return nil
	case http.StatusNotFound:
		return fmt.Errorf("secret %q not found", name)
	default:
		return fmt.Errorf("server returned %d", status)
	}
}

// pubkey reads the caller's own local identity file and prints the recipient
// (public key) of every identity found in it, one per line. It makes no
// network request: the server holds no identity to ask.
func pubkey() error {
	identities, err := loadClientIdentities()
	if err != nil {
		return err
	}
	for _, id := range identities {
		x25519, ok := id.(*age.X25519Identity)
		if !ok {
			continue
		}
		fmt.Println(x25519.Recipient().String())
	}
	return nil
}
