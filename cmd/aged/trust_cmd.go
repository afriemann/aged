package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"

	"filippo.io/age"
)

const trustUsage = `usage:
  aged trust list [--secret <name>]
  aged trust add <age1-key> [--secret <name>] [--dry-run] [--allow-skipped]
  aged trust remove <age1-key> [--secret <name>] [--dry-run] [--allow-skipped] [--force]
  aged trust sync [--dry-run] [--allow-skipped]
  (any: --yes confirms a first-seen manifest non-interactively)`

// trustOpts are the flags shared by the trust subcommands.
type trustOpts struct {
	Secret       string
	DryRun       bool
	Force        bool
	AllowSkipped bool
}

// trustAttemptHook, when non-nil, runs after a trust command has read the
// manifest and before it writes anything. Tests use it to interleave a
// concurrent writer.
var trustAttemptHook func()

// parseTrustArgs splits `aged trust` arguments (after "trust") into the
// subcommand, its optional key argument and the flags.
func parseTrustArgs(args []string) (sub string, key string, opts trustOpts, err error) {
	if len(args) == 0 {
		return "", "", opts, errors.New(trustUsage)
	}
	sub = args[0]
	for i := 1; i < len(args); i++ {
		switch a := args[i]; a {
		case "--secret":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return "", "", opts, errors.New("--secret requires a value")
			}
			i++
			opts.Secret = args[i]
		case "--dry-run":
			opts.DryRun = true
		case "--force":
			opts.Force = true
		case "--allow-skipped":
			opts.AllowSkipped = true
		case "--yes":
			os.Setenv("AGED_TRUST_YES", "1")
		default:
			if strings.HasPrefix(a, "--") || key != "" {
				return "", "", opts, fmt.Errorf("unexpected argument %q\n%s", a, trustUsage)
			}
			key = a
		}
	}
	switch sub {
	case "add", "remove":
		if key == "" {
			return "", "", opts, fmt.Errorf("aged trust %s requires an age public key\n%s", sub, trustUsage)
		}
	case "list", "sync":
		if key != "" {
			return "", "", opts, fmt.Errorf("aged trust %s takes no key\n%s", sub, trustUsage)
		}
	default:
		return "", "", opts, fmt.Errorf("unknown trust subcommand %q\n%s", sub, trustUsage)
	}
	return sub, key, opts, nil
}

// runTrust executes `aged trust <args...>`.
func runTrust(args []string, out io.Writer) error {
	sub, key, opts, err := parseTrustArgs(args)
	if err != nil {
		return err
	}
	if key != "" {
		if _, err := parseRecipient(key); err != nil {
			return err
		}
	}
	ids, err := loadClientIdentities()
	if err != nil {
		return err
	}
	if sub == "list" {
		return trustList(ids, opts, out)
	}

	local, err := localRecipients(ids)
	if err != nil {
		return err
	}
	var mutate func(*trustBody) error
	switch sub {
	case "add":
		mutate = func(b *trustBody) error { addTrust(b, key, opts.Secret); return nil }
	case "remove":
		mutate = func(b *trustBody) error { return removeTrust(b, key, opts, local) }
	case "sync":
		mutate = func(*trustBody) error { return nil }
	}
	if err := attemptWithRetries(ids, local, sub == "sync", opts, mutate, out); err != nil {
		return err
	}
	if sub != "remove" || opts.DryRun {
		return nil
	}
	fmt.Fprintln(out, "warning: the removed key keeps access to any previously copied ciphertext; "+
		"rotate the affected secret values if that matters.")
	if opts.Secret == "" && slices.Contains(local, key) {
		fmt.Fprintln(out, "this device no longer trusts itself, so the follow-up sync was skipped; run `aged trust sync` from another trusted device")
		return nil
	}
	// A device that wrote a secret while this run was uploading may have
	// encrypted it to the removed key; a full sync re-encrypts it.
	fmt.Fprintln(out, "syncing every secret to the new trusted set")
	return attemptWithRetries(ids, local, true, trustOpts{AllowSkipped: opts.AllowSkipped}, func(*trustBody) error { return nil }, out)
}

func attemptWithRetries(ids []age.Identity, local []string, syncAll bool, opts trustOpts, mutate func(*trustBody) error, out io.Writer) error {
	for range trustRetries {
		err := trustAttempt(ids, local, syncAll, opts, mutate, out)
		if !errors.Is(err, errTrustChurn) {
			return err
		}
	}
	return errTrustChurn
}

func trustList(ids []age.Identity, opts trustOpts, out io.Writer) error {
	state, err := loadManifest(ids)
	if err != nil {
		return err
	}
	if state == nil {
		fmt.Fprintln(out, "no trust manifest: secrets are encrypted to each device's own key only")
		return nil
	}
	if opts.Secret != "" {
		fmt.Fprintln(out, strings.Join(state.body.effective(opts.Secret), "\n"))
		return nil
	}
	fmt.Fprintln(out, "default:")
	for _, k := range state.body.Default {
		fmt.Fprintln(out, "  "+k)
	}
	names := make([]string, 0, len(state.body.Overrides))
	for n := range state.body.Overrides {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		ov := state.body.Overrides[n]
		fmt.Fprintf(out, "%s:\n", n)
		for _, k := range ov.Add {
			fmt.Fprintln(out, "  +"+k)
		}
		for _, k := range ov.Remove {
			fmt.Fprintln(out, "  -"+k)
		}
	}
	return nil
}

// addTrust adds key to the default set, or to one secret's overrides.
func addTrust(b *trustBody, key, secret string) {
	if secret == "" {
		b.Default = unionKeys(b.Default, []string{key})
		return
	}
	ov := b.Overrides[secret]
	ov.Add = unionKeys(ov.Add, []string{key})
	ov.Remove = slices.DeleteFunc(ov.Remove, func(k string) bool { return k == key })
	b.Overrides[secret] = ov
}

// removeTrust removes key from the default set (dropping every per-secret add
// of it), or excludes it from one secret.
func removeTrust(b *trustBody, key string, opts trustOpts, local []string) error {
	if opts.Secret != "" {
		ov := b.Overrides[opts.Secret]
		ov.Remove = unionKeys(ov.Remove, []string{key})
		ov.Add = slices.DeleteFunc(ov.Add, func(k string) bool { return k == key })
		b.Overrides[opts.Secret] = ov
		return nil
	}
	if !opts.Force {
		if slices.Contains(local, key) {
			return errors.New("refusing to remove this device's own key; pass --force to do it anyway")
		}
		if len(b.Default) == 1 && b.Default[0] == key {
			return errors.New("refusing to remove the last trusted key; pass --force to do it anyway")
		}
	}
	if slices.Contains(b.Default, key) {
		// Only default-set devices can decrypt the manifest; the removed one
		// may hold the signing private key, so rotate it.
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generate signing key: %w", err)
		}
		b.SigningPub, b.SigningPriv = pub, priv
	}
	b.Default = slices.DeleteFunc(b.Default, func(k string) bool { return k == key })
	for n, ov := range b.Overrides {
		ov.Add = slices.DeleteFunc(ov.Add, func(k string) bool { return k == key })
		b.Overrides[n] = ov
	}
	return nil
}

// pruneOverrides drops empty overrides and, when live is non-nil, overrides
// of secrets that no longer exist.
func pruneOverrides(b *trustBody, live map[string]bool) {
	for n, ov := range b.Overrides {
		if (len(ov.Add) == 0 && len(ov.Remove) == 0) || (live != nil && !live[n]) {
			delete(b.Overrides, n)
		}
	}
}

// reencrypted is a secret re-encrypted and verified in memory, ready to
// upload against the version it was read at.
type reencrypted struct {
	name       string
	ciphertext []byte
	version    string
}

// trustAttempt runs one read-modify-write cycle: read the manifest, compute
// the new one, re-encrypt only the secrets whose recipients change, upload
// them, and write the manifest last with a compare-and-swap. It returns
// errTrustChurn when the server reports a concurrent change, so the caller
// can start over from a fresh read.
func trustAttempt(ids []age.Identity, local []string, syncAll bool, opts trustOpts, mutate func(*trustBody) error, out io.Writer) error {
	state, err := loadManifest(ids)
	if err != nil {
		return err
	}
	fresh := state == nil
	var old trustBody
	manifestVersion := ""
	if fresh {
		if syncAll {
			return errors.New("no trust manifest exists; run `aged trust add <key>` first")
		}
		if old, err = newTrustBody(local); err != nil {
			return err
		}
	} else {
		old, manifestVersion = state.body, state.version
	}
	if trustAttemptHook != nil {
		trustAttemptHook()
	}

	next := old.clone()
	if err := mutate(&next); err != nil {
		return err
	}
	names, err := listSecretNames()
	if err != nil {
		return err
	}
	if opts.Secret != "" && !slices.Contains(names, opts.Secret) {
		return fmt.Errorf("secret %q not found", opts.Secret)
	}
	if syncAll {
		live := make(map[string]bool, len(names))
		for _, n := range names {
			live[n] = true
		}
		pruneOverrides(&next, live)
	}
	pruneOverrides(&next, nil)

	var todo []reencrypted
	var skipped []string
	for _, name := range names {
		if !syncAll && sameKeys(unionKeys(old.effective(name), local), unionKeys(next.effective(name), local)) {
			continue
		}
		item, err := reencryptSecret(name, unionKeys(next.effective(name), local), ids)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s (%v)", name, err))
			continue
		}
		todo = append(todo, item)
	}

	manifestChanged := fresh || !bodiesEqual(old, next)
	if !manifestChanged && !syncAll {
		fmt.Fprintln(out, "already up to date")
		return nil
	}
	if opts.DryRun {
		fmt.Fprintf(out, "dry run: would re-encrypt %d secret(s)", len(todo))
		for _, r := range todo {
			fmt.Fprintf(out, "\n  %s", r.name)
		}
		fmt.Fprintf(out, "\nmanifest would change: %v\n", manifestChanged)
		for _, s := range skipped {
			fmt.Fprintf(out, "skipped: %s\n", s)
		}
		return nil
	}

	if len(skipped) > 0 && !opts.AllowSkipped {
		for _, s := range skipped {
			fmt.Fprintf(out, "skipped: %s\n", s)
		}
		return fmt.Errorf("nothing changed: %d secret(s) could not be decrypted (--allow-skipped to proceed without them)", len(skipped))
	}

	uploadVersion := trustNone
	if !fresh {
		uploadVersion = manifestVersion
	}
	for _, r := range todo {
		resp, err := doRequest("POST", "/secrets/"+r.name, bytes.NewReader(r.ciphertext),
			map[string]string{trustHeader: uploadVersion, "If-Match": r.version})
		if err != nil {
			return err
		}
		switch resp.Status {
		case http.StatusNoContent:
		case http.StatusPreconditionFailed:
			return errTrustChurn
		default:
			return fmt.Errorf("upload %s: server returned %d", r.name, resp.Status)
		}
	}
	fmt.Fprintf(out, "re-encrypted %d secret(s)\n", len(todo))

	for _, s := range skipped {
		fmt.Fprintf(out, "skipped: %s\n", s)
	}
	if !manifestChanged {
		return nil
	}
	return writeManifest(next, old.Counter+1, manifestVersion, fresh)
}

func bodiesEqual(a, b trustBody) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return bytes.Equal(ja, jb)
}

// writeManifest seals and stores the new manifest (create-only when fresh,
// compare-and-swap otherwise) and pins its counter locally.
func writeManifest(body trustBody, counter uint64, ifMatch string, fresh bool) error {
	body.Counter = counter
	blob, err := sealManifest(body)
	if err != nil {
		return err
	}
	hdr := map[string]string{"If-Match": ifMatch}
	if fresh {
		hdr = map[string]string{"If-None-Match": "*"}
	}
	resp, err := doRequest("PUT", "/trust", bytes.NewReader(blob), hdr)
	if err != nil {
		return err
	}
	switch resp.Status {
	case http.StatusNoContent:
	case http.StatusPreconditionFailed:
		return errTrustChurn
	default:
		return fmt.Errorf("store trust manifest: server returned %d", resp.Status)
	}
	return writePin(pinKey(), trustPin{SigningPub: body.SigningPub, Counter: counter})
}

// listSecretNames returns the caller's secret names.
func listSecretNames() ([]string, error) {
	resp, err := doRequest("GET", "/secrets", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("list secrets: server returned %d", resp.Status)
	}
	var names []string
	if err := json.Unmarshal(resp.Body, &names); err != nil {
		return nil, fmt.Errorf("parse secret list: %w", err)
	}
	// The server is untrusted: names it returns are interpolated into
	// request paths, so ignore any that could not be a valid secret name.
	return slices.DeleteFunc(names, func(n string) bool { return !validName(n) }), nil
}

// reencryptSecret fetches name, decrypts it, re-encrypts it to keys and
// verifies the result by decrypting it again. Nothing is uploaded.
func reencryptSecret(name string, keys []string, ids []age.Identity) (reencrypted, error) {
	resp, err := doRequest("GET", "/secrets/"+name, nil, nil)
	if err != nil {
		return reencrypted{}, err
	}
	if resp.Status != http.StatusOK {
		return reencrypted{}, fmt.Errorf("server returned %d", resp.Status)
	}
	plain, err := decryptCiphertext(resp.Body, ids)
	if err != nil {
		return reencrypted{}, fmt.Errorf("cannot decrypt: %w", err)
	}
	if _, err := unpackEnvelope(name, plain); err != nil {
		return reencrypted{}, err
	}
	ciphertext, err := encryptToKeys(keys, plain)
	if err != nil {
		return reencrypted{}, err
	}
	check, err := decryptCiphertext(ciphertext, ids)
	if err != nil || !bytes.Equal(check, plain) {
		return reencrypted{}, errors.New("re-encrypted value failed verification")
	}
	return reencrypted{name: name, ciphertext: ciphertext, version: resp.Header.Get("ETag")}, nil
}
