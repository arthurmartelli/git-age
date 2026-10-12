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

	editors := &editorSignals{}
	ctx, cancel := context.WithCancelCause(context.WithValue(context.Background(), editorSignalKey{}, editors))
	defer cancel(nil)
	received := make(chan os.Signal, 1)
	signal.Notify(received, commandSignals()...)
	defer signal.Stop(received)
	go func() {
		for {
			select {
			case interrupt := <-received:
				if interrupt == os.Interrupt && editors.forwardInterrupt() {
					continue
				}
				cancel(&commandSignalError{interrupt})
				return
			case <-ctx.Done():
				return
			}
		}
	}()
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
		signal.Stop(received)
		if waitForCleanup {
			err = <-result
		}
	}
	var interruption *commandSignalError
	if errors.As(context.Cause(ctx), &interruption) {
		fmt.Fprintf(stderr, "git-age: %s\n", interruption)
		return interruption.exitCode()
	}
	if err != nil {
		if errors.Is(err, errCheckFailed) || errors.Is(err, errMergeConflict) {
			return 1
		}

		fmt.Fprintf(stderr, "git-age: %v\n", err)
		var editor *editorExitError
		if errors.As(err, &editor) {
			return editor.code
		}
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
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return validateSafetyOverrides()
		},
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
