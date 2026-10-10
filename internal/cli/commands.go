package cli

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
)

func newRekeyCommand() *cobra.Command {
	var options struct {
		Recipients []string
		Identities []string
	}

	rekey := &cobra.Command{
		Use:   "rekey [PATH ...]",
		Short: "re-encrypt every protected file to the current recipients",
		Args:  cobra.ArbitraryArgs,
		RunE:  notImplemented,
	}

	recipientFlags(rekey.Flags(), &options.Recipients)
	identityFlags(rekey.Flags(), &options.Identities)

	return rekey
}

func newEditCommand() *cobra.Command {
	var options struct {
		Recipients []string
		Identities []string
	}

	edit := &cobra.Command{
		Use:   "edit FILE",
		Short: "edit a protected file decrypted, then encrypt it again",
		Args:  cobra.ExactArgs(1),
		RunE:  notImplemented,
	}

	recipientFlags(edit.Flags(), &options.Recipients)
	identityFlags(edit.Flags(), &options.Identities)

	return edit
}

func newCheckCommand() *cobra.Command {
	var options struct {
		Cached bool
	}

	check := &cobra.Command{
		Use:   "check",
		Short: "fail if protected files are plaintext",
		Args:  cobra.NoArgs,
		RunE:  notImplemented,
	}

	check.Flags().BoolVar(&options.Cached, "cached", false, "check staged files using the staged .gitage rules")

	return check
}

func newInstallCommand() *cobra.Command {
	var options struct {
		Mode              string
		UnlockAfterCommit *bool
		Diff              bool
		Merge             bool
		Filter            bool
	}

	install := &cobra.Command{
		Use:   "install",
		Short: "install/update the git-age hooks and plaintext diff driver",
		Args:  cobra.NoArgs,
		RunE:  notImplemented,
	}

	install.Flags().Func("mode", "pre-commit policy: interactive, always-lock, abort", func(value string) error {
		if err := choice(value, "interactive", "always-lock", "abort"); err != nil {
			return err
		}
		options.Mode = value

		return nil
	})

	install.Flags().BoolFunc("unlock-after-commit", "unlock protected files after a successful commit", func(value string) error {
		b, err := strconv.ParseBool(value)
		options.UnlockAfterCommit = &b

		return err
	})

	install.Flags().BoolFunc("no-unlock-after-commit", "keep protected files locked after a successful commit", func(value string) error {
		b, err := strconv.ParseBool(value)
		b = !b
		options.UnlockAfterCommit = &b

		return err
	})

	booleanFlags(install.Flags(), "diff", &options.Diff, "show protected files as plaintext in Git diffs")
	booleanFlags(install.Flags(), "merge", &options.Merge, "merge protected files decrypted and re-encrypt the result")
	booleanFlags(install.Flags(), "filter", &options.Filter, "hide unchanged unlocked files from git status")

	return install
}

func newUninstallCommand() *cobra.Command {
	uninstall := &cobra.Command{
		Use:   "uninstall",
		Short: "remove the hooks, git config and attributes that install set up",
		Args:  cobra.NoArgs,
		RunE:  notImplemented,
	}

	return uninstall
}

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

func newCompletionCommand() *cobra.Command {
	completion := &cobra.Command{
		Use:       "completion SHELL",
		ValidArgs: []string{"bash", "zsh", "fish"},
		Short:     "print the shell completion script for bash, zsh or fish",
		Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE:      notImplemented,
	}

	return completion
}

func newCleanCommand() *cobra.Command {
	clean := &cobra.Command{
		Use:   "clean FILE",
		Short: "reuse unchanged ciphertext; Git clean filter entrypoint",
		Args:  cobra.ExactArgs(1),
		RunE:  notImplemented,
	}

	return clean
}

func newMergeCommand() *cobra.Command {
	var options struct {
		Path       string
		MarkerSize int
	}

	merge := &cobra.Command{
		Use:   "merge BASE OURS THEIRS",
		Short: "merge decrypted versions; Git merge driver entrypoint",
		Args:  cobra.ExactArgs(3),
		RunE:  notImplemented,
	}

	merge.Flags().StringVar(&options.Path, "path", "", "protected file path (required)")
	merge.Flags().IntVar(&options.MarkerSize, "marker-size", 7, "conflict marker size")
	merge.MarkFlagRequired("path")

	return merge
}

func newHookCommand() *cobra.Command {
	hook := &cobra.Command{
		Use:   "hook EVENT [arguments]",
		Short: "internal Git hook entrypoint",
		RunE:  notImplemented,
	}

	hook.Args = func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("hook: an event is required (see git-age hook --help)")
	}

	hook.AddCommand(&cobra.Command{
		Use:  "pre-commit",
		Args: cobra.NoArgs,
		RunE: notImplemented,
	})
	hook.AddCommand(&cobra.Command{
		Use:  "post-commit",
		Args: cobra.NoArgs,
		RunE: notImplemented,
	})
	hook.AddCommand(&cobra.Command{
		Use:  "pre-push REMOTE URL",
		Args: cobra.ExactArgs(2),
		RunE: notImplemented,
	})
	hook.AddCommand(&cobra.Command{
		Use:  "post-checkout",
		Args: cobra.NoArgs,
		RunE: notImplemented,
	})
	hook.AddCommand(&cobra.Command{
		Use:  "post-merge",
		Args: cobra.NoArgs,
		RunE: notImplemented,
	})
	hook.AddCommand(&cobra.Command{
		Use:  "post-rewrite",
		Args: cobra.NoArgs,
		RunE: notImplemented,
	})

	return hook
}
