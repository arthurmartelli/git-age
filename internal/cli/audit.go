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

func newAuditCommand(options *globalOptions) *cobra.Command {
	var rekey repository.HistoryRekeyOptions
	var reflog, rewrite, keepUndecryptable, yes bool

	audit := &cobra.Command{
		Use:   "audit [REV ...]",
		Short: "find protected files committed as plaintext; --rekey rewrites history",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !rewrite && (rekey.PlaintextOnly || keepUndecryptable || yes) {
				return errors.New("--plaintext-only, --keep-undecryptable and --yes need --rekey")
			}
			if rewrite {
				if len(args) != 0 || reflog {
					return errors.New("--rekey rewrites all local branches and tags; it takes no revisions")
				}
				rekey.DryRun = options.dryRun
				return rekeyHistory(cmd, options, rekey, keepUndecryptable, yes)
			}
			leaks, err := repository.Audit(options.directory, args, reflog)
			if err != nil {
				return err
			}
			if err := printWarnings(cmd.ErrOrStderr(), leaks.Warnings); err != nil {
				return err
			}
			if len(leaks.Plaintext) == 0 && len(leaks.PrivateKeys) == 0 {
				_, err := fmt.Fprintf(cmd.OutOrStdout(), "git-age: no protected file was committed as plaintext and no private key was committed in %d commit(s)\n", leaks.Commits)
				return err
			}
			if err := printLeaks(cmd, options, leaks); err != nil {
				return err
			}
			return errCheckFailed
		},
	}

	recipientFlags(audit.Flags(), &rekey.Recipients)
	identityFlags(audit.Flags(), &rekey.Identities)
	audit.Flags().BoolVar(&reflog, "reflog", false, "also search commits only the reflogs keep")
	audit.Flags().BoolVar(&rewrite, "rekey", false, "rewrite every local branch and tag to the current recipients")
	audit.Flags().BoolVar(&rekey.PlaintextOnly, "plaintext-only", false, "with --rekey: only encrypt plaintext")
	audit.Flags().BoolVar(&keepUndecryptable, "keep-undecryptable", false, "with --rekey: keep ciphertext you cannot decrypt")
	audit.Flags().BoolVar(&yes, "yes", false, "with --rekey: rewrite without asking")

	return audit
}

func printWarnings(output io.Writer, warnings []string) error {
	for _, warning := range warnings {
		if _, err := fmt.Fprintf(output, "git-age: warning: %s\n", warning); err != nil {
			return err
		}
	}
	return nil
}

// printLeaks lists the leaks by path, on stdout, with advice on stderr.
func printLeaks(cmd *cobra.Command, options *globalOptions, leaks repository.Leaks) error {
	stdout, stderr := cmd.OutOrStdout(), cmd.ErrOrStderr()
	if len(leaks.PrivateKeys) != 0 {
		paths, err := printLeakGroup(stdout, options, "Private age keys committed to Git history:", leaks.PrivateKeys)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(stderr, "\ngit-age: %d version(s) of %d private key file(s) are in Git history.\n%s", len(leaks.PrivateKeys), paths, keyLeakAdvice); err != nil {
			return err
		}
	}
	if len(leaks.PrivateKeys) != 0 && len(leaks.Plaintext) != 0 {
		if _, err := fmt.Fprintln(stdout); err != nil {
			return err
		}
	}
	if len(leaks.Plaintext) != 0 {
		paths, err := printLeakGroup(stdout, options, "Protected files committed as plaintext:", leaks.Plaintext)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(stderr, "\ngit-age: %d plaintext version(s) of %d protected file(s) are in Git history.\n"+
			"Anyone with a copy of the repository can read them, so change those secrets.\n"+
			"Then encrypt them in history; this rewrites every commit:\n\n  git-age audit --rekey\n", len(leaks.Plaintext), paths); err != nil {
			return err
		}
	}
	return nil
}

// printLeakGroup prints the first commit of the first version of each path
// unless verbose, and returns the number of paths.
func printLeakGroup(output io.Writer, options *globalOptions, title string, leaks []repository.Leak) (int, error) {
	var text strings.Builder
	text.WriteString(title + "\n")
	paths := 0
	for start := 0; start < len(leaks); {
		end := start + 1
		for end < len(leaks) && leaks[end].Path == leaks[start].Path {
			end++
		}
		paths++
		fmt.Fprintf(&text, "\n  %s\n", quoteStatusPath(leaks[start].Path))
		shown := leaks[start:end]
		if !options.verbose {
			shown = shown[:1]
		}
		for _, leak := range shown {
			commits := leak.Commits
			if !options.verbose {
				commits = commits[:1]
			}
			for _, commit := range commits {
				fmt.Fprintf(&text, "    %s in %s\n", leak.OID[:12], commit)
			}
			if more := len(leak.Commits) - len(commits); more != 0 {
				fmt.Fprintf(&text, "    %12s    and %d more commit(s)\n", "", more)
			}
		}
		if more := end - start - len(shown); more != 0 {
			fmt.Fprintf(&text, "    and %d more version(s); -v lists them\n", more)
		}
		start = end
	}
	_, err := fmt.Fprint(output, text.String())
	return paths, err
}

const keyLeakAdvice = `Anyone with a copy of the repository has those keys, and can decrypt whatever
was encrypted to them, in any copy of the history. Treat them as compromised:

  1. generate a new key: git-age keygen -o /path/to/new.key
  2. replace the old key's recipient in [recipients] with the new one
  3. re-encrypt the files: git-age rekey; and history: git-age audit --rekey
  4. change the secrets those files hold anyway

` + "`audit --rekey`" + ` does not remove the key files from history; purge them with
a history rewriting tool such as git filter-repo.
`

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
		if _, err := fmt.Fprintf(stderr, "git-age: warning: %d private key file(s) are in Git history, and stay there; `git-age audit` lists them.\n%s", rewrite.PrivateKeys, keyLeakAdvice); err != nil {
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
  * Check the result, e.g. `+"`git log -p` and `git-age audit -- --branches --tags`"+`;
    a plain `+"`git-age audit`"+` also searches the remote-tracking refs, which keep
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
