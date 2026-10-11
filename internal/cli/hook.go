package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/arthurmartelli/git-age/internal/repository"
	"github.com/spf13/cobra"
)

func newHookCommand(options *globalOptions) *cobra.Command {
	hook := &cobra.Command{
		Use: "hook EVENT [arguments]", Short: "internal Git hook entrypoint", Hidden: true,
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
			enabled, err := hookBoolean(options.directory, "GIT_AGE_UNLOCK_AFTER_COMMIT", "age.unlockAfterCommit")
			if err != nil {
				return err
			}
			if !enabled || options.dryRun {
				return nil
			}
			root, err := hookRoot(options.directory)
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
	for _, event := range []string{"post-checkout", "post-merge", "post-rewrite"} {
		hook.AddCommand(&cobra.Command{
			Use: event, Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				if event == "post-merge" {
					changed, err := repository.MergedRecipientChanges(options.directory)
					if err != nil {
						_, err = fmt.Fprintf(cmd.ErrOrStderr(), "git-age: warning: could not check merged recipients: %v\n", err)
						return err
					}
					if len(changed) != 0 {
						_, err = fmt.Fprintln(cmd.ErrOrStderr(), "git-age: warning: this merge changes [recipients] in "+shellPaths(changed)+"; review the changes before encrypting.")
						return err
					}
				}
				return nil
			},
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
	if len(check.RemovedRules) != 0 && !allowCheck("GIT_AGE_ALLOW_REMOVE") {
		return reportCheckFailure(cmd, "refusing to commit the removal of .gitage files", check.RemovedRules,
			"Restore them with:\n\n  git restore --staged --worktree -- "+shellPaths(check.RemovedRules)+"\n\nUse `git-age uninstall` to remove the integration, or set GIT_AGE_ALLOW_REMOVE=1 to allow this removal.")
	}
	if err != nil {
		return err
	}
	if len(check.RemovedRules) != 0 {
		if _, err := fmt.Fprintln(cmd.ErrOrStderr(), "git-age: removing .gitage files by explicit choice (GIT_AGE_ALLOW_REMOVE)."); err != nil {
			return err
		}
	}
	if len(check.PrivateKeys) != 0 && !allowCheck("GIT_AGE_ALLOW_PRIVATE_KEYS") {
		return reportCheckFailure(cmd, "refusing to commit private age keys", check.PrivateKeys, "Unstage these files or set GIT_AGE_ALLOW_PRIVATE_KEYS=1.")
	}
	if !check.HasRules {
		return nil
	}
	mode, err := hookMode(options.directory)
	if err != nil {
		return err
	}
	if len(check.StaleFiles) != 0 && !allowCheck("GIT_AGE_ALLOW_STALE_RECIPIENTS") {
		return reportCheckFailure(cmd, "files are still encrypted to the previous list of [recipients]", check.StaleFiles, "Run `git-age rekey` and stage the encrypted files before committing the recipient changes.")
	}
	var plaintext []string
	for _, file := range check.Files {
		if file.State == "UNLOCKED" {
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

func hookMode(directory string) (string, error) {
	value := os.Getenv("GIT_AGE_HOOK_MODE")
	if value == "" {
		output, err := exec.Command("git", "-C", directory, "config", "--get", "age.hookMode").Output()
		var exit *exec.ExitError
		if err != nil && !(errors.As(err, &exit) && exit.ExitCode() == 1) {
			return "", err
		}
		value = strings.TrimSpace(string(output))
	}
	if value == "" {
		value = "interactive"
	}
	return value, choice(value, "interactive", "always-lock", "abort")
}

func hookBoolean(directory, environment, key string) (bool, error) {
	value, configured := os.LookupEnv(environment)
	if !configured {
		output, err := exec.Command("git", "-C", directory, "config", "--bool", "--get", key).Output()
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		value = strings.TrimSpace(string(output))
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value %q for %s", value, environment)
	}
}

func hookRoot(directory string) (string, error) {
	output, err := exec.Command("git", "-C", directory, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", err
	}
	return filepath.FromSlash(strings.TrimSpace(string(output))), nil
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
