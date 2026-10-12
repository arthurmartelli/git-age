package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/arthurmartelli/git-age/internal/repository"
	"github.com/spf13/cobra"
)

func newHistoryPurgeCommand(options *globalOptions) *cobra.Command {
	var all, yes bool
	command := &cobra.Command{
		Use:   "purge PATH ... | --all",
		Short: "remove selected paths throughout local branches, tags and the stash",
		Args: func(cmd *cobra.Command, args []string) error {
			if all == (len(args) != 0) {
				return errors.New("history purge requires PATH ... or --all, but not both")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return purgeHistory(cmd, options, repository.HistoryPurgeOptions{Paths: args, All: all, DryRun: options.dryRun}, yes)
		},
	}
	command.Flags().BoolVar(&all, "all", false, "remove every version of paths protected by current or historical .gitage rules")
	command.Flags().BoolVar(&yes, "yes", false, "rewrite without asking")
	return command
}

func purgeHistory(cmd *cobra.Command, options *globalOptions, purge repository.HistoryPurgeOptions, yes bool) error {
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
	rewrite, err := repository.PrepareHistoryPurge(options.directory, purge)
	if err != nil {
		return err
	}
	stdout, stderr := cmd.OutOrStdout(), cmd.ErrOrStderr()
	if err := printWarnings(stderr, rewrite.Warnings); err != nil {
		return err
	}
	var text strings.Builder
	verb, rewriteVerb := "removing", "rewriting"
	if options.dryRun {
		verb, rewriteVerb = "would remove", "would rewrite"
	}
	fmt.Fprintf(&text, "git-age: %s %d path(s); %s %d of %d commit(s) and %d ref(s)\n", verb, len(rewrite.Paths), rewriteVerb, rewrite.Changed, rewrite.Commits, len(rewrite.Moves))
	for _, name := range rewrite.Paths {
		fmt.Fprintf(&text, "  %s\n", quoteStatusPath(name))
	}
	if rewrite.Signatures != 0 {
		fmt.Fprintf(&text, "  %d commit or tag signature(s) will be dropped\n", rewrite.Signatures)
	}
	if options.verbose || options.dryRun {
		for _, move := range rewrite.Moves {
			fmt.Fprintf(&text, "  %s: %s -> %s\n", move.Ref, move.Old[:12], move.New[:12])
		}
	}
	if _, err := fmt.Fprint(stdout, text.String()); err != nil {
		return err
	}
	if len(rewrite.Moves) == 0 {
		_, err := fmt.Fprintln(stdout, "git-age: no paths to purge; nothing to do")
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
