package cli

import "github.com/spf13/cobra"

func newHistoryCommand(options *globalOptions) *cobra.Command {
	history := &cobra.Command{
		Use:   "history",
		Short: "inspect and rewrite protected files in Git history",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	history.AddCommand(newHistoryAuditCommand(options), newHistoryRekeyCommand(options))
	return history
}
