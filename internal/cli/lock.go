package cli

import (
	"fmt"

	"github.com/arthurmartelli/git-age/internal/repository"
	"github.com/spf13/cobra"
)

func newLockCommand(options *globalOptions) *cobra.Command {
	var recipients, identities []string
	var noReuse bool

	lock := &cobra.Command{
		Use:   "lock [PATH ...]",
		Short: "encrypt protected working-tree files",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			files, err := repository.ProtectedFiles(options.directory, args)
			if err != nil {
				return err
			}
			for _, file := range files {
				if file.State == "UNKNOWN" {
					return fmt.Errorf("cannot determine file state: %s", file.Path)
				}
			}
			if !options.dryRun {
				if err := repository.Lock(options.directory, files, recipients, identities, noReuse); err != nil {
					return err
				}
			}
			for _, file := range files {
				var message string
				switch {
				case file.State == "LOCKED" && options.verbose:
					message = "already locked"
				case file.State == "LOCKED":
					continue
				case options.dryRun:
					message = "would lock"
				case options.verbose:
					message = "locking"
				default:
					continue
				}
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", message, file.Path); err != nil {
					return err
				}
			}
			return nil
		},
	}
	recipientFlags(lock.Flags(), &recipients)
	identityFlags(lock.Flags(), &identities)
	lock.Flags().BoolVar(&noReuse, "no-reuse", false, "always encrypt freshly instead of reusing unchanged ciphertext")
	return lock
}
