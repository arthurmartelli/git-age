package cli

import (
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
			files, err := knownFiles(options.directory, args)
			if err != nil {
				return err
			}
			inaccessible, err := repository.Rekey(options.directory, files, recipients, identities, options.dryRun)
			if err != nil {
				return err
			}
			skipped := map[string]string{}
			for _, file := range inaccessible {
				skipped[file.Path] = "not encrypted to you"
			}
			return reportFiles(cmd, options, files, "", "rekey", skipped)
		},
	}
	recipientFlags(rekey.Flags(), &recipients)
	identityFlags(rekey.Flags(), &identities)
	return rekey
}
