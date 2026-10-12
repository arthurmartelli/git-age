package cli

import (
	"fmt"
	"strings"

	"github.com/arthurmartelli/git-age/internal/repository"
	"github.com/spf13/cobra"
)

func newUnlockCommand(options *globalOptions) *cobra.Command {
	var identities []string

	unlock := &cobra.Command{
		Use:   "unlock [PATH ...]",
		Short: "decrypt protected working-tree files",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			files, err := knownFiles(options.directory, args)
			if err != nil {
				return err
			}
			skips, err := repository.Unlock(options.directory, files, identities, options.dryRun)
			if err != nil {
				return err
			}
			skipped := map[string]string{}
			for _, file := range skips.NoAccess {
				skipped[file.Path] = "not encrypted to you"
			}
			for _, file := range skips.NotRekeyed {
				skipped[file.Path] = "not re-encrypted to you yet"
			}
			if err := reportFiles(cmd, options, files, repository.Unlocked, "unlock", skipped); err != nil {
				return err
			}
			return reportUnlockAdvice(cmd, skips.NotRekeyed)
		},
	}
	identityFlags(unlock.Flags(), &identities)
	return unlock
}

// reportUnlockSkips tells the user which files unlock left locked, and why.
func reportUnlockSkips(cmd *cobra.Command, options *globalOptions, skips repository.UnlockSkips) error {
	stdout, stderr := cmd.OutOrStdout(), cmd.ErrOrStderr()
	if options.verbose {
		for _, group := range []struct {
			reason string
			files  []repository.ProtectedFile
		}{{"not encrypted to you", skips.NoAccess}, {"not re-encrypted to you yet", skips.NotRekeyed}} {
			for _, file := range group.files {
				if _, err := fmt.Fprintf(stdout, "skipped, %s: %s\n", group.reason, file.Path); err != nil {
					return err
				}
			}
		}
	} else if len(skips.NoAccess) != 0 {
		if _, err := fmt.Fprintf(stderr, "git-age: left %d file(s) locked that are not encrypted to you (`git-age status` marks them)\n", len(skips.NoAccess)); err != nil {
			return err
		}
	}
	return reportUnlockAdvice(cmd, skips.NotRekeyed)
}

func reportUnlockAdvice(cmd *cobra.Command, notRekeyed []repository.ProtectedFile) error {
	if len(notRekeyed) == 0 {
		return nil
	}
	var output strings.Builder
	output.WriteString("git-age: these files are not re-encrypted to you yet; someone who can decrypt them must run `git-age rekey`:\n")
	for _, file := range notRekeyed {
		fmt.Fprintf(&output, "  %s\n", quoteStatusPath(file.Path))
	}
	_, err := fmt.Fprint(cmd.ErrOrStderr(), output.String())
	return err
}
