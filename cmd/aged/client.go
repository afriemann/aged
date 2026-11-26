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

// apiResponse is the full result of an authenticated API call.
type apiResponse struct {
	Body   []byte
	Status int
	Header http.Header
}

// doRequest performs an authenticated HTTP request with optional extra
// headers. It applies no trimming: callers handling binary ciphertext must
// not alter the body, since its last byte may legitimately be '\n'.
func doRequest(method, path string, body io.Reader, headers map[string]string) (*apiResponse, error) {
	cfg := loadConfig()
	if cfg.Token == "" {
		return nil, errors.New("AGED_TOKEN environment variable (or config file token) is required")
	}

	req, err := http.NewRequest(method, serverURL()+path, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	return &apiResponse{Body: data, Status: resp.StatusCode, Header: resp.Header}, err
}

// requestBytes is doRequest without headers, returning only body and status.
func requestBytes(method, path string, body io.Reader) ([]byte, int, error) {
	resp, err := doRequest(method, path, body, nil)
	if resp == nil {
		return nil, 0, err
	}
	return resp.Body, resp.Status, err
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
	if !validName(name) {
		return fmt.Errorf("invalid secret name: %q", name)
	}
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

// resolveSetValue determines the plaintext secret value the set command
// should use: an explicit CLI argument when hasArg is true, or content read
// from stdin otherwise. It is an error to supply both an explicit argument
// and piped stdin data (an ambiguous invocation), and an error for the
// resolved value to be empty.
//
// Exactly one trailing newline is stripped from stdin content — not all of
// them, matching ordinary shell echo/pipe conventions where a single
// newline terminates the line but a value's own trailing newlines are
// significant (see the analogous note on set's own former stdin handling).
// An explicit argument value is used verbatim: the shell, not aged, is
// responsible for whatever bytes it passes as an argument.
func resolveSetValue(argValue string, hasArg bool, hasPipedStdin bool, stdin io.Reader) ([]byte, error) {
	if hasArg && hasPipedStdin {
		return nil, errors.New("value supplied as both an argument and via piped stdin; use only one")
	}

	var value []byte
	if hasArg {
		value = []byte(argValue)
	} else {
		data, err := io.ReadAll(stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		value = bytes.TrimSuffix(data, []byte("\n"))
	}

	if len(value) == 0 {
		return nil, errors.New("value must not be empty")
	}
	return value, nil
}

// set encrypts value locally to the secret's effective recipients (the trust
// manifest's default set adjusted by the secret's overrides, plus the local
// key; the local key alone when no manifest exists) — wrapped in a
// name-binding envelope — and uploads only the resulting ciphertext. The
// upload names the manifest version the recipients came from; the server
// refuses it if the manifest has moved on, in which case set re-reads and
// retries. The caller (main, via resolveSetValue) resolves value from an
// explicit argument or from stdin.
func set(name string, value []byte) error {
	if !validName(name) {
		return fmt.Errorf("invalid secret name: %q", name)
	}
	identities, err := loadClientIdentities()
	if err != nil {
		return err
	}
	local, err := localRecipients(identities)
	if err != nil {
		return err
	}
	envelope := packEnvelope(name, value)

	for range trustRetries {
		state, err := loadManifest(identities)
		if err != nil {
			return err
		}
		recipients, version := local, trustNone
		if state != nil {
			recipients, version = unionKeys(state.body.effective(name), local), state.version
		}
		ciphertext, err := encryptToKeys(recipients, envelope)
		if err != nil {
			return err
		}
		resp, err := doRequest("POST", "/secrets/"+name, bytes.NewReader(ciphertext), map[string]string{trustHeader: version})
		if err != nil {
			return err
		}
		switch resp.Status {
		case http.StatusNoContent:
			return nil
		case http.StatusPreconditionFailed:
			continue
		default:
			return fmt.Errorf("server returned %d: %s", resp.Status, strings.TrimRight(string(resp.Body), "\n"))
		}
	}
	return errTrustChurn
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
	if !validName(name) {
		return fmt.Errorf("invalid secret name: %q", name)
	}
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
