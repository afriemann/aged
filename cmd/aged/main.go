package main

import (
	"fmt"
	"os"
	"strings"
)

const helpText = `aged — age-encrypted secret server and client

Commands:
  serve                       start the HTTP server
  init                        generate a new age identity key (client-side; run on each machine using get/set)
  get <name>                  fetch a secret value (stdout only — suitable for chezmoi)
  set <name> [value]          store a secret value (from argument, or from stdin if omitted; encrypted locally before upload)
  list                        list all secret names
  delete <name>               delete a secret
  rotate-token [<username>]   generate a new token and update the config file in place
                                 (username required if more than one [[users]] entry is configured)
  rotate-identity <file>      re-encrypt every secret from the current identity to a new one
    [--user <name>]             (required if more than one [[users]] entry is configured)
    [--dry-run]                 (add --dry-run to preview without writing anything)

  pubkey                      print your own local identity's age public key (no network call)

Server configuration (config file [[users]] array, or environment variables):
  [[users]]                per-user entries: name = "...", token = "..." (server-side, multi-tenant)
  AGED_USERNAME             combines with AGED_TOKEN to define one server user (no config file needed)
  AGED_TOKEN                bearer token: server user's token (with AGED_USERNAME) or the CLI client's own credential
  AGED_SECRETS_DIR          path to secrets directory   (default: ~/.config/aged/secrets/)
  AGED_ADDR                 listen address              (default: 127.0.0.1:8743)

Client environment variables:
  AGED_SERVER_URL    server URL                  (default: http://localhost:8743)
  AGED_TOKEN         bearer token                (required)
  AGED_IDENTITY      path to your own age identity file (default: ~/.config/aged/identity.age)
`

// noArgs exits with an error if unexpected arguments follow a no-argument subcommand.
func noArgs(cmd string) {
	if len(os.Args) > 2 {
		fmt.Fprintf(os.Stderr, "%s takes no arguments\nusage: aged %s\n", cmd, cmd)
		os.Exit(1)
	}
}

// stdinIsPiped reports whether stdin is connected to a pipe or redirected
// file, as opposed to an interactive terminal.
func stdinIsPiped() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice == 0
}

// parseSetArgs validates the "set" command's positional arguments (i.e.
// os.Args[2:]) and extracts the secret name and, if present, the explicit
// value argument. Exactly one or two arguments are accepted: <name> alone
// (value comes from stdin) or <name> <value>.
func parseSetArgs(args []string) (name string, argValue string, hasArg bool, err error) {
	if len(args) < 1 || len(args) > 2 {
		return "", "", false, fmt.Errorf("usage: aged set <name> [value]")
	}
	name = args[0]
	if len(args) == 2 {
		argValue = args[1]
		hasArg = true
	}
	return name, argValue, hasArg, nil
}

// parseRotateIdentityArgs extracts the required new-identity-file path, the
// optional --dry-run flag, and the optional --user <name> flag from
// rotate-identity's arguments, in any order. --user as the final argument
// with no following value, or immediately followed by another flag, is an
// error rather than silently treating a missing value or the next flag
// itself as the username.
func parseRotateIdentityArgs(args []string) (newIdentityFile string, dryRun bool, username string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--dry-run":
			dryRun = true
		case "--user":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return "", false, "", fmt.Errorf("--user requires a value")
			}
			i++
			username = args[i]
		default:
			newIdentityFile = a
		}
	}
	return newIdentityFile, dryRun, username, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, helpText)
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "serve":
		noArgs("serve")
		err = serve()
	case "init":
		noArgs("init")
		err = initIdentity()
	case "get":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: aged get <name>")
			os.Exit(1)
		}
		err = get(os.Args[2])
	case "set":
		name, argValue, hasArg, parseErr := parseSetArgs(os.Args[2:])
		if parseErr != nil {
			fmt.Fprintln(os.Stderr, parseErr)
			os.Exit(1)
		}
		value, resolveErr := resolveSetValue(argValue, hasArg, stdinIsPiped(), os.Stdin)
		if resolveErr != nil {
			fmt.Fprintln(os.Stderr, "error:", resolveErr)
			os.Exit(1)
		}
		err = set(name, value)
	case "list":
		noArgs("list")
		err = list()
	case "delete":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: aged delete <name>")
			os.Exit(1)
		}
		err = del(os.Args[2])
	case "pubkey":
		noArgs("pubkey")
		err = pubkey()
	case "rotate-token":
		username := ""
		if len(os.Args) > 2 {
			username = os.Args[2]
		}
		if len(os.Args) > 3 {
			fmt.Fprintln(os.Stderr, "usage: aged rotate-token [<username>]")
			os.Exit(1)
		}
		err = rotateToken(os.Stdout, username)
	case "rotate-identity":
		newIdentityFile, dryRun, username, parseErr := parseRotateIdentityArgs(os.Args[2:])
		if parseErr != nil {
			fmt.Fprintln(os.Stderr, parseErr)
			os.Exit(1)
		}
		if newIdentityFile == "" {
			fmt.Fprintln(os.Stderr, "usage: aged rotate-identity <new-identity-file> [--user <name>] [--dry-run]")
			os.Exit(1)
		}
		err = rotateIdentity(newIdentityFile, username, dryRun, os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", os.Args[1], helpText)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
