package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/spf13/cobra"
)

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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	// Editing a locked file creates a plaintext copy that must be wiped before
	// main exits. Other commands retain the immediate exit behavior of SIGINT.
	command, _, _ := root.Find(args)
	waitForCleanup := command != nil && command.Name() == "edit"
	result := make(chan error, 1)
	go func() { result <- root.ExecuteContext(ctx) }()
	var err error
	select {
	case err = <-result:
	case <-ctx.Done():
		// A second Ctrl-C can force an exit while the editor cleans up.
		stop()
		if waitForCleanup {
			<-result
		}
	}
	if ctx.Err() != nil {
		fmt.Fprintln(stderr, "git-age: interrupted")
		return 130
	}
	if err != nil {
		if errors.Is(err, errCheckFailed) || errors.Is(err, errMergeConflict) {
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
		Version:       buildVersion(),
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	flags := root.PersistentFlags()
	flags.StringVarP(&options.directory, "directory", "C", ".", "directory to operate on")
	flags.BoolVarP(&options.dryRun, "dry-run", "n", false, "show what would happen without modifying files")
	flags.BoolVarP(&options.verbose, "verbose", "v", false, "show detailed operation information")

	root.SetVersionTemplate("git-age {{.Version}}\n")
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
		newInstallCommand(&options),
		newUninstallCommand(&options),
		newTrustCommand(&options),
		newHistoryCommand(&options),
		newCompletionCommand(),
		newTextconvCommand(&options),
		newCleanCommand(&options),
		newMergeCommand(&options),
		newHookCommand(&options),
	)

	return root
}
