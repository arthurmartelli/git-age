package cli

import (
	"fmt"

	"github.com/arthurmartelli/git-age/internal/repository"
	"github.com/spf13/cobra"
)

func newUnlockCommand(options *globalOptions) *cobra.Command {
	var identities []string

	unlock := &cobra.Command{
		Use:   "unlock [PATH ...]",
		Short: "decrypt protected working-tree files",
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
				if err := repository.Unlock(options.directory, files, identities); err != nil {
					return err
				}
			}
			for _, file := range files {
				var message string
				switch {
				case file.State == "UNLOCKED" && options.verbose:
					message = "already unlocked"
				case file.State == "UNLOCKED":
					continue
				case options.dryRun:
					message = "would unlock"
				case options.verbose:
					message = "unlocking"
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
	identityFlags(unlock.Flags(), &identities)
	return unlock
}
