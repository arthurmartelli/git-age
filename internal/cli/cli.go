package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

var ErrNotImplemented = errors.New("not implemented")

type globalOptions struct {
	directory string
	dryRun    bool
	verbose   bool
}

func Run(args []string, stdout, stderr io.Writer) int {
	root := newRootCommand()
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs(args)

	if err := root.Execute(); err != nil {
		if errors.Is(err, errCheckFailed) {
			return 1
		}
		if errors.Is(err, ErrNotImplemented) {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}

		fmt.Fprintf(stderr, "git-age: %v\n", err)
		return 2
	}

	return 0
}

func newRootCommand() *cobra.Command {
	var options globalOptions

	root := &cobra.Command{
		Use:           "git-age",
		Short:         "Lock and unlock files selected by .gitage rules using age.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("a command is required (see git-age --help)")
		},
	}

	flags := root.PersistentFlags()
	flags.StringVarP(&options.directory, "directory", "C", ".", "directory to operate on")
	flags.BoolVarP(&options.dryRun, "dry-run", "n", false, "show what would happen without modifying files")
	flags.BoolVarP(&options.verbose, "verbose", "v", false, "show detailed operation information")

	root.CompletionOptions.DisableDefaultCmd = true
	root.SetHelpCommand(newHelpCommand())
	root.AddCommand(
		newKeygenCommand(&options),
		newLockCommand(&options),
		newRekeyCommand(&options),
		newUnlockCommand(&options),
		newEditCommand(&options),
		newStatusCommand(&options),
		newCheckCommand(&options),
		newInstallCommand(),
		newUninstallCommand(),
		newTrustCommand(),
		newAuditCommand(),
		newCompletionCommand(),
		newTextconvCommand(&options),
		newCleanCommand(),
		newMergeCommand(),
		newHookCommand(),
	)

	return root
}

func notImplemented(cmd *cobra.Command, args []string) error {
	name := strings.TrimPrefix(cmd.CommandPath(), cmd.Root().Name()+" ")

	return fmt.Errorf("%s: %w", name, ErrNotImplemented)
}
