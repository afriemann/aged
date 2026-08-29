package main

import (
	"fmt"
	"os"
)

const helpText = `aged — age-encrypted secret server and client

Commands:
  serve              start the HTTP server
  init               generate a new age identity key
  get <name>         fetch a secret value (stdout only — suitable for chezmoi)
  set <name>         store a secret value (reads from stdin)
  list               list all secret names
  delete <name>      delete a secret
  rotate-token       generate a new token and update the config file in place

  pubkey             print the server's age public key

Server environment variables:
  AGED_TOKEN         bearer token for authentication (required)
  AGED_IDENTITY      path to age identity file (default: ~/.config/aged/identity.age)
  AGED_SECRETS_DIR   path to secrets directory   (default: ~/.config/aged/secrets/)
  AGED_ADDR          listen address              (default: 127.0.0.1:8743)

Client environment variables:
  AGED_SERVER_URL    server URL    (default: http://localhost:8743)
  AGED_TOKEN         bearer token  (required)
`

// noArgs exits with an error if unexpected arguments follow a no-argument subcommand.
func noArgs(cmd string) {
	if len(os.Args) > 2 {
		fmt.Fprintf(os.Stderr, "%s takes no arguments\nusage: aged %s\n", cmd, cmd)
		os.Exit(1)
	}
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
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: aged set <name>")
			os.Exit(1)
		}
		err = set(os.Args[2])
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
		noArgs("rotate-token")
		err = rotateToken(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", os.Args[1], helpText)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
