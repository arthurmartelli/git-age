package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func writeHelp(cmd *cobra.Command, content string) error {
	output := cmd.OutOrStdout()
	direct := func() error {
		_, err := io.WriteString(output, content)
		return err
	}
	terminal, ok := output.(*os.File)
	if !ok || !term.IsTerminal(int(terminal.Fd())) {
		return direct()
	}
	pager, configured := os.LookupEnv("GIT_PAGER")
	if !configured {
		pager, configured = os.LookupEnv("PAGER")
	}
	var command *exec.Cmd
	if configured {
		pager = strings.TrimSpace(pager)
		if pager == "" || pager == "cat" {
			return direct()
		}
		shell, err := gitShell()
		if err != nil {
			return fmt.Errorf("find pager shell: %w", err)
		}
		command = exec.CommandContext(cmd.Context(), shell, "-c", pager)
	} else {
		less, err := exec.LookPath("less")
		if err != nil {
			return direct()
		}
		command = exec.CommandContext(cmd.Context(), less, "-FRX")
	}
	command.Stdin = strings.NewReader(content)
	command.Stdout = output
	command.Stderr = cmd.ErrOrStderr()
	if err := command.Run(); err != nil {
		return fmt.Errorf("pager: %w", err)
	}
	return nil
}
