package cli

import (
	"strconv"

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

	install.Flags().Func("mode", "pre-commit policy: interactive, always-lock, abort", func(value string) error {
		if err := choice(value, "interactive", "always-lock", "abort"); err != nil {
			return err
		}
		options.Mode = value

		return nil
	})
	install.RegisterFlagCompletionFunc("mode", cobra.FixedCompletions([]string{"interactive", "always-lock", "abort"}, cobra.ShellCompDirectiveNoFileComp))

	install.Flags().BoolFunc("unlock-after-commit", "unlock protected files after a successful commit", func(value string) error {
		b, err := strconv.ParseBool(value)
		options.UnlockAfterCommit = &b

		return err
	})

	install.Flags().BoolFunc("no-unlock-after-commit", "keep protected files locked after a successful commit", func(value string) error {
		b, err := strconv.ParseBool(value)
		b = !b
		options.UnlockAfterCommit = &b

		return err
	})

	booleanFlags(install.Flags(), "diff", &options.Diff, "show protected files as plaintext in Git diffs")
	booleanFlags(install.Flags(), "merge", &options.Merge, "merge protected files decrypted and re-encrypt the result")
	booleanFlags(install.Flags(), "filter", &options.Filter, "hide unchanged unlocked files from git status")

	return install
}
