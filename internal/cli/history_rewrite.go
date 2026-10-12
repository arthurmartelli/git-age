package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/arthurmartelli/git-age/internal/repository"
	"golang.org/x/term"
)

func historyConfirmationTerminal(yes, dryRun bool) (*os.File, error) {
	var tty *os.File
	if !yes && !dryRun {
		// Input from anything but a terminal means a script, which must pass --yes.
		var err error
		if term.IsTerminal(int(os.Stdin.Fd())) {
			tty, err = os.OpenFile("/dev/tty", os.O_RDWR, 0)
		}
		if tty == nil || err != nil {
			return nil, errors.New("cannot ask for confirmation without a terminal; pass --yes")
		}
	}
	return tty, nil
}

func confirmHistoryRewrite(tty *os.File, moves []repository.RefMove) error {
	if tty != nil {
		var refs []string
		for _, move := range moves {
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
	return nil
}

func printHistoryRewriteAdvice(stderr io.Writer, moves []repository.RefMove) error {
	var pushes []string
	for _, move := range moves {
		if name, ok := strings.CutPrefix(move.Ref, "refs/heads/"); ok {
			pushes = append(pushes, name)
		} else if name, ok := strings.CutPrefix(move.Ref, "refs/tags/"); ok {
			pushes = append(pushes, name)
		}
	}
	_, err := fmt.Fprintf(stderr, `git-age: history rewritten; the old refs are under refs/git-age/original.

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
