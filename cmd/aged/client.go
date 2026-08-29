package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// serverURL returns the configured server base URL.
func serverURL() string {
	if url := loadConfig().ServerURL; url != "" {
		return strings.TrimRight(url, "/")
	}
	return "http://localhost:8743"
}

// request performs an authenticated HTTP request and returns the trimmed body,
// the status code, and any transport error.
func request(method, path string, body io.Reader) (string, int, error) {
	cfg := loadConfig()
	if cfg.Token == "" {
		return "", 0, errors.New("AGED_TOKEN environment variable (or config file token) is required")
	}

	req, err := http.NewRequest(method, serverURL()+path, body)
	if err != nil {
		return "", 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	if body != nil {
		req.Header.Set("Content-Type", "text/plain")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	return strings.TrimRight(string(data), "\n"), resp.StatusCode, err
}

// get fetches a secret value and prints it to stdout with no trailing newline,
// making it suitable as a chezmoi secret backend command.
func get(name string) error {
	val, status, err := request("GET", "/secrets/"+name, nil)
	if err != nil {
		return err
	}
	switch status {
	case http.StatusOK:
		fmt.Print(val)
		return nil
	case http.StatusNotFound:
		return fmt.Errorf("secret %q not found", name)
	default:
		return fmt.Errorf("server returned %d: %s", status, val)
	}
}

// set reads a secret value from stdin and stores it on the server.
func set(name string) error {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	value := strings.TrimRight(string(data), "\n")

	_, status, err := request("POST", "/secrets/"+name, strings.NewReader(value))
	if err != nil {
		return err
	}
	if status != http.StatusNoContent {
		return fmt.Errorf("server returned %d", status)
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

// pubkey prints the server's age public key.
func pubkey() error {
	val, status, err := request("GET", "/pubkey", nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("server returned %d: %s", status, val)
	}
	fmt.Println(val)
	return nil
}
