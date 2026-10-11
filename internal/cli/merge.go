package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/arthurmartelli/git-age/internal/repository"
	"github.com/spf13/cobra"
)

var errMergeConflict = errors.New("merge conflict")

func newMergeCommand(options *globalOptions) *cobra.Command {
	var path string
	var markerSize int
	merge := &cobra.Command{
		Use:    "merge BASE OURS THEIRS",
		Short:  "merge decrypted versions; Git merge driver entrypoint",
		Hidden: true,
		Args:   cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			if path == "" {
				return fmt.Errorf("--path must not be empty")
			}
			if markerSize < 1 {
				return fmt.Errorf("--marker-size must be positive")
			}
			if options.dryRun {
				_, err := fmt.Fprintf(cmd.OutOrStdout(), "would merge: %s\n", quoteStatusPath(path))
				return err
			}
			conflicted, err := repository.Merge(options.directory, path, args[0], args[1], args[2], markerSize)
			if err != nil {
				if _, writeErr := fmt.Fprintf(cmd.ErrOrStderr(), "git-age: cannot merge %s: %s; keeping our version\n", quoteStatusPath(path), strings.SplitN(err.Error(), "\n", 2)[0]); writeErr != nil {
					return writeErr
				}
				return errMergeConflict
			}
			if conflicted {
				if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "git-age: %s is now UNLOCKED with conflict markers; resolve it, then run `git add`\n", quoteStatusPath(path)); err != nil {
					return err
				}
				return errMergeConflict
			}
			return nil
		},
	}
	merge.Flags().StringVar(&path, "path", "", "protected file path (required)")
	merge.Flags().IntVar(&markerSize, "marker-size", 7, "conflict marker size")
	merge.MarkFlagRequired("path")
	return merge
}
