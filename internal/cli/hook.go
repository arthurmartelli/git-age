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
)

func newHookCommand(options *globalOptions) *cobra.Command {
	hook := &cobra.Command{
		Use: "hook EVENT [arguments]", Short: "internal Git hook entrypoint", Hidden: true,
		// Args rejects a missing or unknown event before PersistentPreRunE
		// runs; RunE only makes the command runnable so that Args is checked.
		Args: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("hook: an event is required (see git-age hook --help)")
		},
		RunE: notImplemented,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if !options.dryRun && cmd.Name() != "pre-push" {
				return refreshGitAttributes(cmd, options.directory)
			}
			return nil
		},
	}
	hook.AddCommand(&cobra.Command{
		Use: "pre-commit", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { return preCommit(cmd, options) },
	})
	hook.AddCommand(&cobra.Command{
		Use: "post-commit", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			enabled, err := repository.UnlockAfterCommit(options.directory)
			if err != nil {
				return err
			}
			if !enabled || options.dryRun {
				return nil
			}
			root, err := repository.Root(options.directory)
			if err != nil {
				return err
			}
			files, err := repository.ProtectedFiles(root, nil)
			if errors.Is(err, repository.ErrNoRules) {
				return nil
			}
			if err == nil {
				err = repository.Unlock(root, files, nil)
			}
			if err != nil {
				return fmt.Errorf("commit succeeded, but automatic unlock failed: %w", err)
			}
			return nil
		},
	})
	hook.AddCommand(&cobra.Command{
		Use: "pre-push REMOTE URL", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return prePush(cmd, options, args[0])
		},
	})
	hook.AddCommand(&cobra.Command{
		Use: "post-merge", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			changed, err := repository.MergedRecipientChanges(options.directory)
			if err != nil {
				_, err = fmt.Fprintf(cmd.ErrOrStderr(), "git-age: warning: could not check merged recipients: %v\n", err)
				return err
			}
			if len(changed) != 0 {
				_, err = fmt.Fprintln(cmd.ErrOrStderr(), "git-age: warning: this merge changes [recipients] in "+shellPaths(changed)+"; review the changes before encrypting.")
			}
			return err
		},
	})
	// These hooks only refresh the attributes, in PersistentPreRunE.
	for _, event := range []string{"post-checkout", "post-rewrite"} {
		hook.AddCommand(&cobra.Command{
			Use: event, Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error { return nil },
		})
	}
	return hook
}

func prePush(cmd *cobra.Command, options *globalOptions, remote string) error {
	check, err := repository.CheckPush(options.directory, remote, cmd.InOrStdin())
	if err != nil {
		return err
	}
	if len(check.Plaintext) == 0 && len(check.PrivateKeys) == 0 {
		return nil
	}
	var output strings.Builder
	for _, group := range []struct {
		title string
		paths []string
	}{
		{"Private age keys in the commits being pushed:", check.PrivateKeys},
		{"Protected files committed as plaintext:", check.Plaintext},
	} {
		if len(group.paths) == 0 {
			continue
		}
		fmt.Fprintln(&output, group.title)
		for _, path := range group.paths {
			fmt.Fprintln(&output, "  "+quoteStatusPath(path))
		}
		output.WriteByte('\n')
	}
	output.WriteString("Fix the affected commits before pushing, using `git commit --amend` or `git rebase -i`.\nTo push them explicitly: GIT_AGE_ALLOW_PLAINTEXT_PUSH=1 git push\n")
	allowed := allowCheck("GIT_AGE_ALLOW_PLAINTEXT_PUSH")
	if allowed {
		output.WriteString("git-age: pushing them by explicit choice (GIT_AGE_ALLOW_PLAINTEXT_PUSH).\n")
	} else {
		output.WriteString("git-age: push aborted.\n")
	}
	if _, err := fmt.Fprint(cmd.ErrOrStderr(), output.String()); err != nil {
		return err
	}
	if !allowed {
		return errCheckFailed
	}
	return nil
}

func preCommit(cmd *cobra.Command, options *globalOptions) error {
	check, err := repository.CheckCommit(options.directory)
	if err := refuseRemovedRules(cmd, check.RemovedRules, "Use `git-age uninstall` to remove the integration, or set GIT_AGE_ALLOW_REMOVE=1 to allow this removal."); err != nil {
		return err
	}
	if err != nil {
		return err
	}
	if len(check.RemovedRules) != 0 {
		if _, err := fmt.Fprintln(cmd.ErrOrStderr(), "git-age: removing .gitage files by explicit choice (GIT_AGE_ALLOW_REMOVE)."); err != nil {
			return err
		}
	}
	if err := refuseUnless(cmd, "GIT_AGE_ALLOW_PRIVATE_KEYS", check.PrivateKeys, "refusing to commit private age keys", "Unstage these files or set GIT_AGE_ALLOW_PRIVATE_KEYS=1."); err != nil {
		return err
	}
	if !check.HasRules {
		return nil
	}
	mode, err := repository.HookMode(options.directory)
	if err != nil {
		return err
	}
	if err := refuseUnless(cmd, "GIT_AGE_ALLOW_STALE_RECIPIENTS", check.StaleFiles, "files are still encrypted to the previous list of [recipients]", "Run `git-age rekey` and stage the encrypted files before committing the recipient changes."); err != nil {
		return err
	}
	var plaintext []string
	for _, file := range check.Files {
		if file.State == repository.Unlocked {
			plaintext = append(plaintext, file.Path)
		}
	}
	if len(plaintext) == 0 {
		return nil
	}
	if options.dryRun {
		for _, path := range plaintext {
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "would encrypt staged: %s\n", quoteStatusPath(path)); err != nil {
				return err
			}
		}
		return nil
	}
	if mode == "abort" {
		return reportCheckFailure(cmd, "hook policy is abort; commit aborted", plaintext, "")
	}
	if mode == "interactive" {
		reader, err := os.Open("/dev/tty")
		if err != nil {
			return reportCheckFailure(cmd, "interactive confirmation is unavailable; commit aborted", plaintext, "Use GIT_AGE_HOOK_MODE=always-lock to encrypt automatically.")
		}
		defer reader.Close()
		writer, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
		if err != nil {
			return reportCheckFailure(cmd, "interactive confirmation is unavailable; commit aborted", plaintext, "")
		}
		defer writer.Close()
		choice, err := promptHookChoice(reader, writer)
		if err != nil {
			return err
		}
		if choice == "abort" {
			return reportCheckFailure(cmd, "commit aborted", plaintext, "")
		}
		if choice == "commit" {
			_, err := fmt.Fprintln(cmd.ErrOrStderr(), "git-age: committing protected files as plaintext by explicit choice.")
			return err
		}
	}
	result, err := repository.EncryptStaged(check)
	if err != nil {
		return reportCheckFailure(cmd, "could not encrypt staged files; commit aborted", plaintext, err.Error())
	}
	if len(result.LeftUnchanged) != 0 {
		if _, err := fmt.Fprintln(cmd.ErrOrStderr(), "git-age: working-tree copies were left unlocked because they contain unstaged changes or could not be safely replaced: "+shellPaths(result.LeftUnchanged)); err != nil {
			return err
		}
	}
	if result.MadeEmpty && !allowCheck("GIT_AGE_ALLOW_EMPTY") {
		return reportCheckFailure(cmd, "nothing to commit; staged files encrypt to the ciphertext already in HEAD", plaintext, "Set GIT_AGE_ALLOW_EMPTY=1 to amend or commit anyway. Commit aborted.")
	}
	return nil
}

func refreshGitAttributes(cmd *cobra.Command, directory string) error {
	if err := repository.RefreshAttributes(directory); err != nil {
		_, err = fmt.Fprintf(cmd.ErrOrStderr(), "git-age: warning: could not refresh Git attributes: %v\n", err)
		return err
	}
	return nil
}

func promptHookChoice(input io.Reader, output io.Writer) (string, error) {
	reader := bufio.NewReader(input)
	for {
		if _, err := fmt.Fprint(output, "What would you like to do?\n\n  [e] Encrypt staged protected files and continue\n  [a] Abort the commit\n  [c] Commit them as plaintext anyway\n\nChoice [a]: "); err != nil {
			return "", err
		}
		answer, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}
		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "", "a", "abort":
			return "abort", nil
		case "e", "encrypt":
			return "encrypt", nil
		case "c", "commit":
			if _, err := fmt.Fprint(output, "\nProtected plaintext will enter Git history. Type \"commit\" to continue: "); err != nil {
				return "", err
			}
			answer, err := reader.ReadString('\n')
			if err != nil && err != io.EOF {
				return "", err
			}
			if strings.TrimSpace(answer) == "commit" {
				return "commit", nil
			}
			_, err = fmt.Fprintln(output, "Plaintext commit not confirmed; aborting.")
			return "abort", err
		}
		if err == io.EOF {
			return "abort", nil
		}
	}
}
