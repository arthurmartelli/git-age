package cli

import (
	"github.com/arthurmartelli/git-age/internal/repository"
	"github.com/spf13/cobra"
)

func newUninstallCommand(global *globalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "remove the hooks, git config and attributes that install set up",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return repository.Uninstall(global.directory, global.dryRun, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
}
