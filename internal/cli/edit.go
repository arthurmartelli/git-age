package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/arthurmartelli/git-age/internal/repository"
	"github.com/spf13/cobra"
)

func newEditCommand(options *globalOptions) *cobra.Command {
	var recipients, identities []string
	edit := &cobra.Command{
		Use:               "edit FILE",
		Short:             "edit a protected file decrypted, then encrypt it again",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: protectedPathCompletion(options),
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
			files, err := knownFiles(options.directory, args)
			if err != nil {
				return err
			}
			file := files[0]
			if file.State == repository.Unlocked && !options.dryRun {
				if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s is unlocked; editing in place\n", file.Path); err != nil {
					return err
				}
			}
			err = repository.Edit(options.directory, file, recipients, identities, options.dryRun, func(path string) error {
				if err := cmd.Context().Err(); err != nil {
					return err
				}
				editor, err := exec.Command("git", "-C", options.directory, "var", "GIT_EDITOR").Output()
				if err != nil {
					return fmt.Errorf("find editor: %w", err)
				}
				ctx := cmd.Context()
				command, err := editorCommand(ctx, strings.TrimSpace(string(editor)), path)
				if err != nil {
					return err
				}
				command.Dir = options.directory
				command.Stdin = cmd.InOrStdin()
				command.Stdout = cmd.OutOrStdout()
				command.Stderr = cmd.ErrOrStderr()
				state, _ := ctx.Value(editorSignalKey{}).(*editorSignals)
				if state == nil {
					state = &editorSignals{}
				}
				if err := runEditor(ctx, command, state); err != nil {
					var exit *exec.ExitError
					if errors.As(err, &exit) {
						return &editorExitError{err: err, code: processExitCode(exit)}
					}
					return err
				}
				return ctx.Err()
			})
			if err != nil {
				return err
			}
			if options.dryRun {
				_, err := fmt.Fprintf(cmd.OutOrStdout(), "would edit: %s\n", file.Path)
				return err
			}
			if err := refreshGitAttributes(cmd, options.directory); err != nil {
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

// editorCommand runs a plain editor command directly, as Git does, and only
// uses a shell for shell syntax. A shell such as dash that waits in front of
// the editor would otherwise be killed by the Ctrl-C meant for the editor.
func editorCommand(ctx context.Context, editor, path string) (*exec.Cmd, error) {
	if fields := strings.Fields(editor); len(fields) != 0 && !strings.ContainsAny(editor, "|&;<>()$`\\\"'*?[#~=%") {
		return exec.CommandContext(ctx, fields[0], append(fields[1:], path)...), nil
	}
	shell, err := gitShell()
	if err != nil {
		return nil, err
	}
	return exec.CommandContext(ctx, shell, "-c", editor+` "$@"`, "git-age-edit", path), nil
}
