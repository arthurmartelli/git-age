package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

var ErrNotImplemented = errors.New("not implemented")

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
	flags.StringP("directory", "C", ".", "directory to operate on")
	flags.BoolP("dry-run", "n", false, "show what would happen without modifying files")
	flags.BoolP("verbose", "v", false, "show detailed operation information")

	root.CompletionOptions.DisableDefaultCmd = true
	root.SetHelpCommand(newHelpCommand())
	root.AddCommand(
		newKeygenCommand(),
		newLockCommand(),
		newRekeyCommand(),
		newUnlockCommand(),
		newEditCommand(),
		newStatusCommand(),
		newCheckCommand(),
		newInstallCommand(),
		newUninstallCommand(),
		newTrustCommand(),
		newAuditCommand(),
		newCompletionCommand(),
		newTextconvCommand(),
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
