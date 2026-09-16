package main

// spec: openspec/changes/multi-user-support/specs/aged/spec.md

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// maxScanOffendersListed caps how many offending entries are individually
// named in the aggregated error from scanSecretsDir, so the message stays
// bounded when an operator has many unmigrated secrets.
const maxScanOffendersListed = 20

// scanSecretsDir runs the one-level, pre-multi-user-support migration check
// (see design.md D2.2 / Per-User Storage Isolation): every entry directly
// under secretsDir must be a directory, following symlinks (so a legitimately
// symlinked tenant root is permitted, consistent with the root
// canonicalisation newStore performs). Any non-directory entry is an
// offender — a ".age" file gets a migration-specific message, anything else
// an "unexpected entry" message — and every offender is aggregated into a
// single returned error, never failing fast on the first one.
//
// A directory whose name does not match any configured user is NOT an
// offender: it produces a one-line warning to warnDst and does not block
// startup. This deliberately tolerates an orphaned former user's directory
// (see the accepted "removed user's directory is orphaned indefinitely"
// limitation) and a rotate-identity backup/staging sibling, both of which
// are expected to accumulate inside secrets_dir over the life of a
// deployment.
//
// An absent secretsDir is not an error: it is the normal shape of a fresh
// install, before any user's directory has been created.
func scanSecretsDir(secretsDir string, userNames []string, warnDst io.Writer) error {
	entries, err := os.ReadDir(secretsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("scan secrets directory: %w", err)
	}

	known := make(map[string]bool, len(userNames))
	for _, n := range userNames {
		known[n] = true
	}

	type offender struct {
		name    string
		message string
	}
	var offenders []offender

	for _, entry := range entries {
		path := filepath.Join(secretsDir, entry.Name())
		info, statErr := os.Stat(path) // follows symlinks
		if statErr != nil {
			offenders = append(offenders, offender{
				name:    entry.Name(),
				message: fmt.Sprintf("%s is unreadable or a dangling symlink (%v)", entry.Name(), statErr),
			})
			continue
		}
		if info.IsDir() {
			if !known[entry.Name()] {
				fmt.Fprintf(warnDst, "warning: %s does not match any configured user; "+
					"it will not be served and may be an orphaned directory (safe to remove once verified)\n",
					filepath.Join(secretsDir, entry.Name()))
			}
			continue
		}
		if strings.HasSuffix(entry.Name(), ".age") {
			offenders = append(offenders, offender{
				name:    entry.Name(),
				message: fmt.Sprintf("%s is an unmigrated secret; move it into a user directory", entry.Name()),
			})
		} else {
			offenders = append(offenders, offender{
				name:    entry.Name(),
				message: fmt.Sprintf("%s is an unexpected entry; secrets_dir may contain only per-user directories", entry.Name()),
			})
		}
	}

	if len(offenders) == 0 {
		return nil
	}

	sort.Slice(offenders, func(i, j int) bool { return offenders[i].name < offenders[j].name })

	sortedUsers := append([]string{}, userNames...)
	sort.Strings(sortedUsers)

	var b strings.Builder
	fmt.Fprintf(&b, "refusing to start: %s contains %d entr%s that predate multi-user support:\n",
		secretsDir, len(offenders), pluralY(len(offenders)))
	shown := offenders
	extra := 0
	if len(shown) > maxScanOffendersListed {
		shown = offenders[:maxScanOffendersListed]
		extra = len(offenders) - maxScanOffendersListed
	}
	for _, o := range shown {
		fmt.Fprintf(&b, "  - %s\n", o.message)
	}
	if extra > 0 {
		fmt.Fprintf(&b, "  … and %d more\n", extra)
	}
	fmt.Fprintf(&b, "configured users: %s", strings.Join(sortedUsers, ", "))

	return fmt.Errorf("%s", b.String())
}

// pluralY returns "y" for n == 1 and "ies" otherwise, so callers can render
// "entry"/"entries" without a branch at the call site.
func pluralY(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
