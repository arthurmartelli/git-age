package cli

import (
	"fmt"
	"strings"

	"github.com/arthurmartelli/git-age/internal/repository"
	"github.com/spf13/cobra"
)

func newTrustCommand(options *globalOptions) *cobra.Command {
	var show, hash bool

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
			if hash {
				_, err := fmt.Fprintln(out, trust.Hash)
				return err
			}
			if show {
				var text strings.Builder
				state := "trusted"
				if trust.Pinned == "" {
					state = "unpinned"
				} else if trust.Pinned != trust.Hash {
					state = "changed since approval"
				}
				fmt.Fprintf(&text, "Recipient trust: %s\n", state)
				if trust.Pinned != "" {
					fmt.Fprintf(&text, "Approval source: %s\n", trust.Source)
				}
				text.WriteString("\nCurrent [recipients] lists:\n")
				text.WriteString(strings.Join(trust.Lists, "\n") + "\n")
				if trust.Pinned != "" && trust.Pinned != trust.Hash {
					text.WriteString("\nChanges since approval:\n" + strings.Join(trust.Details, "\n") + "\n")
				}
				_, err := fmt.Fprint(out, text.String())
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
	trust.Flags().BoolVar(&show, "show", false, "show current recipients, trust status and changes without approving")
	trust.Flags().BoolVar(&hash, "hash", false, "print the hash of the current recipient lists without approving")
	trust.MarkFlagsMutuallyExclusive("show", "hash")

	return trust
}
