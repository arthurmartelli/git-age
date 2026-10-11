package cli

import (
	"fmt"
	"strings"

	"github.com/arthurmartelli/git-age/internal/repository"
	"github.com/spf13/cobra"
)

func newTrustCommand(options *globalOptions) *cobra.Command {
	var show bool

	trust := &cobra.Command{
		Use:   "trust",
		Short: "pin the current [recipients] lists as trusted",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			trust, err := repository.RecipientTrust(options.directory)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if show {
				_, err := fmt.Fprintln(out, trust.Hash)
				return err
			}
			if trust.Pinned == trust.Hash {
				_, err := fmt.Fprintln(out, "git-age: the current [recipients] lists are already trusted")
				return err
			}

			heading := "git-age: trusting [recipients] lists changed since you trusted them:"
			if trust.Pinned == "" {
				heading = "git-age: trusting these [recipients] lists:"
			}
			if _, err := fmt.Fprintf(out, "%s\n\n%s\n\n", heading, strings.Join(trust.Details, "\n")); err != nil {
				return err
			}
			if options.dryRun {
				_, err := fmt.Fprintf(out, "would set git config age.trustedRecipients %s\n", trust.Hash)
				return err
			}
			if err := trust.Pin(); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(out, "git-age: pinned %s in repo git config age.trustedRecipients\n", trust.Hash[:12]); err != nil {
				return err
			}
			if repository.PinOverridden() {
				_, err = fmt.Fprintln(cmd.ErrOrStderr(), "git-age: warning: GIT_AGE_TRUSTED_RECIPIENTS is set and takes precedence")
			}
			return err
		},
	}
	trust.Flags().BoolVar(&show, "show", false, "print the hash of the current lists, pin nothing")

	return trust
}
