package cli

import (
	_ "embed"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

//go:embed manual.txt
var manual string

func newHelpCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "help [COMMAND]",
		Short: "show the manual or a command's options",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				_, err := io.WriteString(cmd.OutOrStdout(), manual)
				return err
			}

			root := cmd.Root()
			topic, rest, err := root.Find(args)
			if err != nil || topic == root || len(rest) != 0 {
				return fmt.Errorf("unknown help command %q (see git-age --help)", args[0])
			}

			topic.InitDefaultHelpFlag()
			return topic.Help()
		},
	}
}
