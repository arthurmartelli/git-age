package cli

import (
	"fmt"

	"github.com/arthurmartelli/git-age/internal/repository"
	"github.com/spf13/cobra"
)

func newKeygenCommand(options *globalOptions) *cobra.Command {
	var output string
	var noExclude bool

	keygen := &cobra.Command{
		Use:   "keygen",
		Short: "generate a new age identity",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := repository.KeyPath(options.directory, output)
			if err != nil {
				return err
			}
			if options.dryRun {
				_, err := fmt.Fprintf(cmd.OutOrStdout(), "would generate identity: %s\n", path)
				return err
			}

			recipient, err := repository.GenerateKey(path, !noExclude)
			if err != nil {
				return err
			}

			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Identity:  %s\nRecipient: %s\n\nKeep this private key safe. Do not commit it to Git.\n", path, recipient)
			return err
		},
	}
	keygen.Flags().StringVarP(&output, "output", "o", "", "identity output path (default: .gitage.key at the repository root)")
	keygen.Flags().BoolVar(&noExclude, "no-exclude", false, "do not add the new key to .git/info/exclude")

	return keygen
}
