package cli

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/arthurmartelli/git-age/internal/repository"
	"github.com/spf13/cobra"
)

func newEditCommand(options *globalOptions) *cobra.Command {
	var recipients, identities []string
	edit := &cobra.Command{
		Use:   "edit FILE",
		Short: "edit a protected file decrypted, then encrypt it again",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			if !filepath.IsAbs(path) {
				path = filepath.Join(options.directory, path)
			}
			info, err := os.Stat(path)
			if err != nil {
				return err
			}
			if info.IsDir() {
				return fmt.Errorf("%s: is a directory", args[0])
			}
			files, err := repository.ProtectedFiles(options.directory, args)
			if err != nil {
				return err
			}
			file := files[0]
			if file.State == "UNKNOWN" {
				return fmt.Errorf("cannot determine file state: %s", file.Path)
			}
			if options.dryRun {
				_, err := fmt.Fprintf(cmd.OutOrStdout(), "would edit: %s\n", file.Path)
				return err
			}
			if file.State == "UNLOCKED" {
				if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s is unlocked; editing in place\n", file.Path); err != nil {
					return err
				}
			}
			editor, err := exec.Command("git", "-C", options.directory, "var", "GIT_EDITOR").Output()
			if err != nil {
				return fmt.Errorf("find editor: %w", err)
			}
			shell, err := exec.LookPath("sh")
			if err != nil && runtime.GOOS == "windows" {
				// Git for Windows includes sh even when only git.exe is on PATH.
				gitPath, gitErr := exec.Command("git", "--exec-path").Output()
				if gitErr != nil {
					return gitErr
				}
				shell = filepath.Join(strings.TrimSpace(string(gitPath)), "..", "..", "..", "usr", "bin", "sh.exe")
			} else if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			err = repository.Edit(options.directory, file, recipients, identities, func(path string) error {
				command := exec.CommandContext(ctx, shell, "-c", strings.TrimSpace(string(editor))+` "$@"`, "git-age-edit", path)
				command.Dir = options.directory
				command.Stdin = cmd.InOrStdin()
				command.Stdout = cmd.OutOrStdout()
				command.Stderr = cmd.ErrOrStderr()
				if err := command.Run(); err != nil {
					return err
				}
				return ctx.Err()
			})
			if err != nil {
				return err
			}
			if options.verbose {
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "edited: %s\n", file.Path)
			}
			return err
		},
	}
	recipientFlags(edit.Flags(), &recipients)
	identityFlags(edit.Flags(), &identities)
	return edit
}
