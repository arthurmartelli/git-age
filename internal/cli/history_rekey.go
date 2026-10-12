package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/arthurmartelli/git-age/internal/repository"
	"github.com/spf13/cobra"
	"golang.org/x/term"
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
	var tty *os.File
	if !yes && !options.dryRun {
		// Input from anything but a terminal means a script, which must pass --yes.
		var err error
		if term.IsTerminal(int(os.Stdin.Fd())) {
			tty, err = os.OpenFile("/dev/tty", os.O_RDWR, 0)
		}
		if tty == nil || err != nil {
			return errors.New("cannot ask for confirmation without a terminal; pass --yes")
		}
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

	if tty != nil {
		var refs []string
		for _, move := range rewrite.Moves {
			refs = append(refs, move.Ref)
		}
		if _, err := fmt.Fprintf(tty, "\nThis rewrites %s.\nEveryone who has a copy must re-clone or reset onto the new history.\nType \"rewrite\" to continue: ", strings.Join(refs, ", ")); err != nil {
			return err
		}
		answer, err := bufio.NewReader(tty).ReadString('\n')
		if err != nil && err != io.EOF {
			return err
		}
		if strings.TrimSpace(answer) != "rewrite" {
			return errors.New("rewrite not confirmed; nothing was changed")
		}
	}
	if err := rewrite.Apply(); err != nil {
		return err
	}

	var pushes []string
	for _, move := range rewrite.Moves {
		if name, ok := strings.CutPrefix(move.Ref, "refs/heads/"); ok {
			pushes = append(pushes, name)
		} else if name, ok := strings.CutPrefix(move.Ref, "refs/tags/"); ok {
			pushes = append(pushes, name)
		}
	}
	_, err = fmt.Fprintf(stderr, `git-age: history rewritten; the old refs are under refs/git-age/original.

Next:
  * Check the result, e.g. `+"`git log -p` and `git-age history audit -- --branches --tags`"+`;
    a plain `+"`git-age history audit`"+` also searches the remote-tracking refs, which keep
    the old history until you push.
  * Publish it: `+"`git push --force-with-lease origin %s`"+`.
  * Others must re-clone; a pull would merge the old history back in.
  * Once you are sure, delete the old history here:
      %s
      git reflog expire --expire=now --all && git gc --prune=now
  * Change the secrets anyway: old clones, forks and the server's caches keep
    the old history.
`, strings.Join(pushes, " "), repository.DeleteOriginalRefs)
	return err
}
