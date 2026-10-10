package cli

import (
	"fmt"

	"github.com/arthurmartelli/git-age/internal/repository"
	"github.com/spf13/cobra"
)

func newRekeyCommand(options *globalOptions) *cobra.Command {
	var recipients, identities []string

	rekey := &cobra.Command{
		Use:   "rekey [PATH ...]",
		Short: "re-encrypt every protected file to the current recipients",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			files, err := repository.ProtectedFiles(options.directory, args)
			if err != nil {
				return err
			}
			for _, file := range files {
				if file.State == "UNKNOWN" {
					return fmt.Errorf("cannot determine file state: %s", file.Path)
				}
			}
			skipped := map[string]bool{}
			if !options.dryRun {
				inaccessible, err := repository.Rekey(options.directory, files, recipients, identities)
				if err != nil {
					return err
				}
				for _, file := range inaccessible {
					skipped[file.Path] = true
					if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "warning: skipping %s: not encrypted to you\n", file.Path); err != nil {
						return err
					}
				}
			}
			for _, file := range files {
				if skipped[file.Path] || !options.dryRun && !options.verbose {
					continue
				}
				message := "rekeying"
				if options.dryRun {
					message = "would rekey"
				}
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", message, file.Path); err != nil {
					return err
				}
			}
			return nil
		},
	}
	recipientFlags(rekey.Flags(), &recipients)
	identityFlags(rekey.Flags(), &identities)
	return rekey
}
