package cli

import (
	"io"

	"github.com/arthurmartelli/git-age/internal/repository"
	"github.com/spf13/cobra"
)

func newCleanCommand(options *globalOptions) *cobra.Command {
	return &cobra.Command{
		Use:    "clean FILE",
		Short:  "reuse unchanged ciphertext; Git clean filter entrypoint",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			content, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				return err
			}
			content, err = repository.Clean(options.directory, args[0], content)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(content)
			return err
		},
	}
}
