package cli

import (
	"github.com/arthurmartelli/git-age/internal/repository"
	"github.com/spf13/cobra"
)

func newTextconvCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "textconv FILE",
		Short: "print a file decrypted; Git diff driver entrypoint",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			directory, err := cmd.Flags().GetString("directory")
			if err != nil {
				return err
			}
			content, err := repository.Textconv(directory, args[0])
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(content)
			return err
		},
	}
}
