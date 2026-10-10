package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestHelpManual(t *testing.T) {
	var output bytes.Buffer
	cmd := newHelpCommand()
	cmd.SetOut(&output)

	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatal(err)
	}

	for _, heading := range []string{"QUICK START", "SHELL COMPLETION"} {
		if !strings.Contains(output.String(), "\n"+heading+"\n") {
			t.Errorf("manual is missing %q", heading)
		}
	}
}

func TestHelpCommand(t *testing.T) {
	var output bytes.Buffer
	root := &cobra.Command{Use: "git-age"}
	root.SetOut(&output)

	help := newHelpCommand()
	lock := newLockCommand(&globalOptions{})
	root.AddCommand(help, lock)

	if err := help.RunE(help, []string{"lock"}); err != nil {
		t.Fatal(err)
	}

	text := output.String()
	for _, expected := range []string{"git-age lock [PATH ...]", "--recipient"} {
		if !strings.Contains(text, expected) {
			t.Errorf("command help is missing %q", expected)
		}
	}

	output.Reset()
	if err := lock.Help(); err != nil {
		t.Fatal(err)
	}
	if text != output.String() {
		t.Error("help lock differs from lock's own help")
	}
}

func TestHelpUnknownCommand(t *testing.T) {
	var output bytes.Buffer
	root := &cobra.Command{Use: "git-age"}
	root.SetOut(&output)

	help := newHelpCommand()
	root.AddCommand(help, newLockCommand(&globalOptions{}))

	err := help.RunE(help, []string{"lockd"})
	if err == nil || err.Error() != `unknown help command "lockd" (see git-age --help)` {
		t.Errorf("unexpected error: %v", err)
	}
	if output.Len() != 0 {
		t.Errorf("unexpected output: %s", &output)
	}
}
