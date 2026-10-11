package cli

import (
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
			files, err := knownFiles(options.directory, args)
			if err != nil {
				return err
			}
			if !options.dryRun {
				if err := repository.Unlock(options.directory, files, identities); err != nil {
					return err
				}
			}
			return reportFiles(cmd, options, files, repository.Unlocked, "unlock")
		},
	}
	identityFlags(unlock.Flags(), &identities)
	return unlock
}
