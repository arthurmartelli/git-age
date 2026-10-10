package cli

import (
	"fmt"

	"github.com/arthurmartelli/git-age/internal/repository"
	"github.com/spf13/cobra"
)

func newUnlockCommand() *cobra.Command {
	var identities []string

	unlock := &cobra.Command{
		Use:   "unlock [PATH ...]",
		Short: "decrypt protected working-tree files",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			directory, err := cmd.Flags().GetString("directory")
			if err != nil {
				return err
			}
			dryRun, err := cmd.Flags().GetBool("dry-run")
			if err != nil {
				return err
			}
			verbose, err := cmd.Flags().GetBool("verbose")
			if err != nil {
				return err
			}
			files, err := repository.ProtectedFiles(directory, args)
			if err != nil {
				return err
			}
			for _, file := range files {
				if file.State == "UNKNOWN" {
					return fmt.Errorf("cannot determine file state: %s", file.Path)
				}
			}
			if !dryRun {
				if err := repository.Unlock(directory, files, identities); err != nil {
					return err
				}
			}
			for _, file := range files {
				var message string
				switch {
				case file.State == "UNLOCKED" && verbose:
					message = "already unlocked"
				case file.State == "UNLOCKED":
					continue
				case dryRun:
					message = "would unlock"
				case verbose:
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
