package cli

import (
	"fmt"

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

// reportFiles prints what verb did, or would do, to each file not yet in state done.
func reportFiles(cmd *cobra.Command, options *globalOptions, files []repository.ProtectedFile, done repository.State, verb string) error {
	for _, file := range files {
		var message string
		switch {
		case file.State == done && options.verbose:
			message = "already " + verb + "ed"
		case file.State == done:
			continue
		case options.dryRun:
			message = "would " + verb
		case options.verbose:
			message = verb + "ing"
		default:
			continue
		}
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", message, file.Path); err != nil {
			return err
		}
	}
	return nil
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
			if !options.dryRun {
				noAccess, err := repository.Lock(options.directory, files, recipients, identities, noReuse)
				if err != nil {
					return err
				}
				for _, file := range noAccess {
					if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "warning: your identity is not among the recipients for %s; the configured identities cannot unlock this file\n", quoteStatusPath(file.Path)); err != nil {
						return err
					}
				}
				if err := refreshGitAttributes(cmd, options.directory); err != nil {
					return err
				}
			}
			return reportFiles(cmd, options, files, repository.Locked, "lock")
		},
	}
	recipientFlags(lock.Flags(), &recipients)
	identityFlags(lock.Flags(), &identities)
	lock.Flags().BoolVar(&noReuse, "no-reuse", false, "always encrypt freshly instead of reusing unchanged ciphertext")
	return lock
}
