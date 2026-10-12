package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/arthurmartelli/git-age/internal/repository"
	"github.com/spf13/cobra"
)

func newHistoryAuditCommand(options *globalOptions) *cobra.Command {
	var reflog bool
	audit := &cobra.Command{
		Use:   "audit [REV ...]",
		Short: "find protected plaintext files and private age keys in history",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
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
	audit.Flags().BoolVar(&reflog, "reflog", false, "also search commits only the reflogs keep")
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
			"Then encrypt them in history; this rewrites every commit:\n\n  git-age history rekey\n", len(leaks.Plaintext), paths); err != nil {
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
  3. re-encrypt the files: git-age rekey; and history: git-age history rekey
  4. change the secrets those files hold anyway

` + "`history rekey`" + ` does not remove the key files from history; purge them with
a history rewriting tool such as git filter-repo.
`
