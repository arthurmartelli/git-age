package cli

import "github.com/spf13/cobra"

func newTrustCommand() *cobra.Command {
	var options struct {
		Show bool
	}

	trust := &cobra.Command{
		Use:   "trust",
		Short: "pin the current [recipients] lists as trusted",
		Args:  cobra.NoArgs,
		RunE:  notImplemented,
	}

	trust.Flags().BoolVar(&options.Show, "show", false, "print the hash of the current lists, pin nothing")

	return trust
}

func newAuditCommand() *cobra.Command {
	var options struct {
		Recipients        []string
		Identities        []string
		Reflog            bool
		Rekey             bool
		PlaintextOnly     bool
		KeepUndecryptable bool
		Yes               bool
	}

	audit := &cobra.Command{
		Use:   "audit [REV ...]",
		Short: "find protected files committed as plaintext; --rekey rewrites history",
		Args:  cobra.ArbitraryArgs,
		RunE:  notImplemented,
	}

	recipientFlags(audit.Flags(), &options.Recipients)
	identityFlags(audit.Flags(), &options.Identities)
	audit.Flags().BoolVar(&options.Reflog, "reflog", false, "also search commits only the reflogs keep")
	audit.Flags().BoolVar(&options.Rekey, "rekey", false, "rewrite every local branch and tag to the current recipients")
	audit.Flags().BoolVar(&options.PlaintextOnly, "plaintext-only", false, "with --rekey: only encrypt plaintext")
	audit.Flags().BoolVar(&options.KeepUndecryptable, "keep-undecryptable", false, "with --rekey: keep ciphertext you cannot decrypt")
	audit.Flags().BoolVar(&options.Yes, "yes", false, "with --rekey: rewrite without asking")

	return audit
}
