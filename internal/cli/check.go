package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/arthurmartelli/git-age/internal/repository"
	"github.com/spf13/cobra"
)

var errCheckFailed = errors.New("check failed")

func newCheckCommand() *cobra.Command {
	var cached bool

	check := &cobra.Command{
		Use:   "check",
		Short: "fail if protected files are plaintext",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			directory, err := cmd.Flags().GetString("directory")
			if err != nil {
				return err
			}
			verbose, err := cmd.Flags().GetBool("verbose")
			if err != nil {
				return err
			}

			var files []repository.ProtectedFile
			if cached {
				result, err := repository.CheckIndex(directory)
				if len(result.RemovedRules) != 0 && !allowCheck("GIT_AGE_ALLOW_REMOVE") {
					return reportCheckFailure(cmd, "refusing to commit the removal of .gitage files", result.RemovedRules,
						"Restore them with:\n\n  git restore --staged --worktree -- "+shellPaths(result.RemovedRules)+"\n\nTo allow removal, set GIT_AGE_ALLOW_REMOVE=1.")
				}
				if err != nil {
					return err
				}
				if len(result.PrivateKeys) != 0 && !allowCheck("GIT_AGE_ALLOW_PRIVATE_KEYS") {
					return reportCheckFailure(cmd, "refusing to commit private age keys", result.PrivateKeys,
						"Unstage them with:\n\n  git restore --staged -- "+shellPaths(result.PrivateKeys)+"\n\nTo allow them, set GIT_AGE_ALLOW_PRIVATE_KEYS=1.")
				}
				files = result.Files
			} else {
				files, err = repository.ProtectedFiles(directory, nil)
				if err != nil {
					return err
				}
			}

			var unknown, unlocked []string
			for _, file := range files {
				switch file.State {
				case "UNKNOWN":
					unknown = append(unknown, file.Path)
				case "UNLOCKED":
					unlocked = append(unlocked, file.Path)
				}
			}
			if len(unknown) != 0 {
				return reportCheckFailure(cmd, "could not determine state of protected files", unknown, "")
			}
			if len(unlocked) != 0 {
				message := "protected files are currently unlocked"
				if cached {
					message = "protected files are staged as plaintext"
				}
				return reportCheckFailure(cmd, message, unlocked, "")
			}
			if verbose {
				message := "protected working-tree files are locked"
				if cached {
					message = "staged protected files are locked"
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "git-age: "+message)
			}
			return err
		},
	}
	check.Flags().BoolVar(&cached, "cached", false, "check staged files using the staged .gitage rules")
	return check
}

func reportCheckFailure(cmd *cobra.Command, message string, paths []string, advice string) error {
	var output strings.Builder
	fmt.Fprintf(&output, "git-age: %s:\n\n", message)
	for _, path := range paths {
		fmt.Fprintf(&output, "  %s\n", quoteStatusPath(path))
	}
	if advice != "" {
		fmt.Fprintf(&output, "\n%s\n", advice)
	}
	if _, err := fmt.Fprint(cmd.ErrOrStderr(), output.String()); err != nil {
		return err
	}
	return errCheckFailed
}

func allowCheck(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func shellPaths(paths []string) string {
	quoted := make([]string, len(paths))
	for i, path := range paths {
		if !strings.ContainsAny(path, " \t\n\r'\"\\$`;&|<>()*?[]{}!#~") {
			quoted[i] = path
		} else {
			quoted[i] = "'" + strings.ReplaceAll(path, "'", "'\\''") + "'"
		}
	}
	return strings.Join(quoted, " ")
}
