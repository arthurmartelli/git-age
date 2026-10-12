package cli

import (
	"strings"

	"github.com/arthurmartelli/git-age/internal/repository"
	"github.com/spf13/cobra"
)

func newInstallCommand(global *globalOptions) *cobra.Command {
	var options repository.InstallOptions

	install := &cobra.Command{
		Use:   "install",
		Short: "install/update the git-age hooks and plaintext diff driver",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			options.DryRun = global.dryRun
			return repository.Install(global.directory, options, cmd.OutOrStdout())
		},
	}

	install.Flags().Func("hook-mode", "pre-commit policy: "+strings.Join(repository.HookModes, ", "), func(value string) error {
		options.Mode = value
		return repository.ValidateHookMode(value)
	})
	install.RegisterFlagCompletionFunc("hook-mode", cobra.FixedCompletions(repository.HookModes, cobra.ShellCompDirectiveNoFileComp))

	unlockAfterCommit := func(enabled bool) { options.UnlockAfterCommit = &enabled }
	boolFlag(install.Flags(), "unlock-after-commit", "unlock protected files after a successful commit", unlockAfterCommit, false)
	boolFlag(install.Flags(), "no-unlock-after-commit", "keep protected files locked after a successful commit", unlockAfterCommit, true)

	booleanFlags(install.Flags(), "diff", &options.Diff, "show protected files as plaintext in Git diffs")
	booleanFlags(install.Flags(), "merge", &options.Merge, "merge protected files decrypted and re-encrypt the result")
	booleanFlags(install.Flags(), "filter", &options.Filter, "hide unchanged unlocked files from git status")

	return install
}
