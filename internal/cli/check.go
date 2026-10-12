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

func newCheckCommand(options *globalOptions) *cobra.Command {
	var staged bool

	check := &cobra.Command{
		Use:               "check [PATH ...]",
		Short:             "fail if protected files are plaintext",
		Args:              cobra.ArbitraryArgs,
		ValidArgsFunction: protectedPathCompletion(options),
		RunE: func(cmd *cobra.Command, args []string) error {
			var files []repository.ProtectedFile
			var err error
			if staged {
				result, err := repository.CheckIndex(options.directory, args)
				if err := refuseRemovedRules(cmd, result.RemovedRules, "To allow removal, set GIT_AGE_ALLOW_REMOVE=1."); err != nil {
					return err
				}
				if err != nil {
					return err
				}
				if err := refuseUnless(cmd, "GIT_AGE_ALLOW_PRIVATE_KEYS", result.PrivateKeys, "refusing to commit private age keys",
					"Unstage them with:\n\n  git restore --staged -- "+shellPaths(result.PrivateKeys)+"\n\nTo allow them, set GIT_AGE_ALLOW_PRIVATE_KEYS=1."); err != nil {
					return err
				}
				files = result.Files
			} else {
				files, err = repository.ProtectedFiles(options.directory, args)
				if err != nil {
					return err
				}
			}

			var unknown, unlocked []string
			for _, file := range files {
				switch file.State {
				case repository.Unknown:
					unknown = append(unknown, file.Path)
				case repository.Unlocked:
					unlocked = append(unlocked, file.Path)
				}
			}
			if len(unknown) != 0 {
				return reportCheckFailure(cmd, "could not determine state of protected files", unknown, "")
			}
			if len(unlocked) != 0 {
				message := "protected files are currently unlocked"
				if staged {
					message = "protected files are staged as plaintext"
				}
				return reportCheckFailure(cmd, message, unlocked, "")
			}
			if options.verbose {
				message := "protected working-tree files are locked"
				if staged {
					message = "staged protected files are locked"
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "git-age: "+message)
			}
			return err
		},
	}
	check.Flags().BoolVar(&staged, "staged", false, "check the index contents using the staged .gitage rules")
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

// refuseUnless reports paths as a failure unless the environment variable allows them.
func refuseUnless(cmd *cobra.Command, environment string, paths []string, message, advice string) error {
	allowed, err := allowCheck(environment)
	if err != nil {
		return err
	}
	if len(paths) == 0 || allowed {
		return nil
	}
	return reportCheckFailure(cmd, message, paths, advice)
}

func refuseRemovedRules(cmd *cobra.Command, paths []string, advice string) error {
	return refuseUnless(cmd, "GIT_AGE_ALLOW_REMOVE", paths, "refusing to commit the removal of .gitage files",
		"Restore them with:\n\n  git restore --staged --worktree -- "+shellPaths(paths)+"\n\n"+advice)
}

func allowCheck(name string) (bool, error) {
	value := os.Getenv(name)
	if strings.TrimSpace(value) == "" {
		return false, nil
	}
	allowed, err := repository.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s: %w", name, err)
	}
	return allowed, nil
}

func validateSafetyOverrides() error {
	for _, name := range []string{"GIT_AGE_ALLOW_EMPTY", "GIT_AGE_ALLOW_PRIVATE_KEYS", "GIT_AGE_ALLOW_STALE_RECIPIENTS", "GIT_AGE_ALLOW_REMOVE", "GIT_AGE_ALLOW_PLAINTEXT_PUSH"} {
		if _, err := allowCheck(name); err != nil {
			return err
		}
	}
	return nil
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
