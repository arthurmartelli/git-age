package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/arthurmartelli/git-age/internal/repository"
	"github.com/spf13/cobra"
)

func newHistoryRekeyCommand(options *globalOptions) *cobra.Command {
	var rekey repository.HistoryRekeyOptions
	var keepUndecryptable, yes bool
	command := &cobra.Command{
		Use:   "rekey",
		Short: "rewrite local branches, tags and the stash to the current recipients",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return errors.New("history rekey rewrites all local branches, tags and the stash; it takes no revisions")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			rekey.DryRun = options.dryRun
			return rekeyHistory(cmd, options, rekey, keepUndecryptable, yes)
		},
	}
	recipientFlags(command.Flags(), &rekey.Recipients)
	identityFlags(command.Flags(), &rekey.Identities)
	command.Flags().BoolVar(&rekey.PlaintextOnly, "plaintext-only", false, "only encrypt plaintext; keep existing ciphertext")
	command.Flags().BoolVar(&keepUndecryptable, "keep-undecryptable", false, "keep ciphertext you cannot decrypt")
	command.Flags().BoolVar(&yes, "yes", false, "rewrite without asking")
	return command
}

func rekeyHistory(cmd *cobra.Command, options *globalOptions, rekey repository.HistoryRekeyOptions, keepUndecryptable, yes bool) error {
	if err := repository.CheckRewritable(options.directory); err != nil {
		return err
	}
	tty, err := historyConfirmationTerminal(yes, options.dryRun)
	if err != nil {
		return err
	}
	if tty != nil {
		defer tty.Close()
	}

	rewrite, err := repository.PrepareHistoryRekey(options.directory, rekey)
	if err != nil {
		return err
	}
	stdout, stderr := cmd.OutOrStdout(), cmd.ErrOrStderr()
	if err := printWarnings(stderr, rewrite.Warnings); err != nil {
		return err
	}
	if len(rewrite.Undecryptable) != 0 && !keepUndecryptable {
		var text strings.Builder
		fmt.Fprintf(&text, "git-age: cannot decrypt %d protected file version(s):\n", len(rewrite.Undecryptable))
		for _, version := range rewrite.Undecryptable {
			text.WriteString("  " + version + "\n")
		}
		if _, err := fmt.Fprint(stderr, text.String()); err != nil {
			return err
		}
		return errors.New("nothing was changed; pass --keep-undecryptable to keep what you cannot decrypt as it is, or --plaintext-only to only encrypt plaintext")
	}

	var text strings.Builder
	verb := "rewriting"
	if options.dryRun {
		verb = "would rewrite"
	}
	fmt.Fprintf(&text, "git-age: %s %d of %d commit(s) and %d ref(s): %d plaintext version(s) encrypted, %d re-encrypted\n",
		verb, rewrite.Changed, rewrite.Commits, len(rewrite.Moves), rewrite.Encrypted, rewrite.Reencrypted)
	if len(rewrite.Undecryptable) != 0 {
		fmt.Fprintf(&text, "  kept %d version(s) you cannot decrypt as they are\n", len(rewrite.Undecryptable))
	}
	if rewrite.Signatures != 0 {
		fmt.Fprintf(&text, "  %d commit or tag signature(s) will be dropped\n", rewrite.Signatures)
	}
	if options.verbose || options.dryRun {
		for _, move := range rewrite.Moves {
			updated := move.New[:12]
			if options.dryRun {
				updated = "(new)"
			}
			fmt.Fprintf(&text, "  %s: %s -> %s\n", move.Ref, move.Old[:12], updated)
		}
	}
	if _, err := fmt.Fprint(stdout, text.String()); err != nil {
		return err
	}
	if rewrite.PrivateKeys != 0 {
		if _, err := fmt.Fprintf(stderr, "git-age: warning: %d private key file(s) are in Git history, and stay there; `git-age history audit` lists them.\n%s", rewrite.PrivateKeys, keyLeakAdvice); err != nil {
			return err
		}
	}
	if len(rewrite.Moves) == 0 {
		_, err := fmt.Fprintln(stdout, "git-age: history is already encrypted; nothing to do")
		return err
	}
	if options.dryRun {
		return nil
	}

	if err := confirmHistoryRewrite(tty, rewrite.Moves); err != nil {
		return err
	}
	if err := rewrite.Apply(); err != nil {
		return err
	}

	return printHistoryRewriteAdvice(stderr, rewrite.Moves)
}
