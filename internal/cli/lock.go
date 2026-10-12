package cli

import (
	"fmt"
	"strings"

	"github.com/arthurmartelli/git-age/internal/repository"
	"github.com/spf13/cobra"
)

// knownFiles selects protected files, failing if any has an unknown state.
func knownFiles(directory string, paths []string) ([]repository.ProtectedFile, error) {
	files, err := repository.ProtectedFiles(directory, paths)
	if err == nil {
		err = repository.CheckKnown(files)
	}
	return files, err
}

// reportFiles summarizes an operation, with per-file details when verbose.
func reportFiles(cmd *cobra.Command, options *globalOptions, files []repository.ProtectedFile, done repository.State, verb string, skipped map[string]string) error {
	changed, already, noAccess, notRekeyed := 0, 0, 0, 0
	for _, file := range files {
		var message string
		switch {
		case skipped[file.Path] != "":
			reason := skipped[file.Path]
			if reason == "not re-encrypted to you yet" {
				notRekeyed++
			} else {
				noAccess++
			}
			message = "skipped, " + reason
		case file.State == done:
			already++
			message = "already " + verb + "ed"
		default:
			changed++
			message = verb + "ing"
			if options.dryRun {
				message = "would " + verb
			}
		}
		if options.verbose {
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", message, quoteStatusPath(file.Path)); err != nil {
				return err
			}
		}
	}
	action := map[string]string{"lock": "Locked", "unlock": "Unlocked", "rekey": "Re-encrypted"}[verb]
	if options.dryRun {
		action = "Would " + verb
		if verb == "rekey" {
			action = "Would re-encrypt"
		}
	}
	var summary strings.Builder
	fmt.Fprintf(&summary, "git-age: %s %s", action, fileCount(changed))
	if already != 0 {
		fmt.Fprintf(&summary, "; %d already %sed", already, verb)
	}
	if noAccess != 0 {
		fmt.Fprintf(&summary, "; skipped %d without access", noAccess)
	}
	if notRekeyed != 0 {
		fmt.Fprintf(&summary, "; skipped %d awaiting rekey", notRekeyed)
	}
	summary.WriteString(".\n")
	_, err := fmt.Fprint(cmd.OutOrStdout(), summary.String())
	return err
}

func fileCount(count int) string {
	if count == 1 {
		return "1 file"
	}
	return fmt.Sprintf("%d files", count)
}

func newLockCommand(options *globalOptions) *cobra.Command {
	var recipients, identities []string
	var noReuse bool

	lock := &cobra.Command{
		Use:   "lock [PATH ...]",
		Short: "encrypt protected working-tree files",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			files, err := knownFiles(options.directory, args)
			if err != nil {
				return err
			}
			noAccess, err := repository.Lock(options.directory, files, recipients, identities, noReuse, options.dryRun)
			if err != nil {
				return err
			}
			for _, file := range noAccess {
				if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "warning: your identity is not among the recipients for %s; the configured identities cannot unlock this file\n", quoteStatusPath(file.Path)); err != nil {
					return err
				}
			}
			if !options.dryRun {
				if err := refreshGitAttributes(cmd, options.directory); err != nil {
					return err
				}
			}
			return reportFiles(cmd, options, files, repository.Locked, "lock", nil)
		},
	}
	recipientFlags(lock.Flags(), &recipients)
	identityFlags(lock.Flags(), &identities)
	lock.Flags().BoolVar(&noReuse, "no-reuse", false, "always encrypt freshly instead of reusing unchanged ciphertext")
	return lock
}
