package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestHelpDoesNotPageRedirectedOutput(t *testing.T) {
	t.Setenv("GIT_PAGER", "exit 99")
	t.Setenv("PAGER", "exit 98")
	output, err := os.CreateTemp(t.TempDir(), "help")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	var stderr bytes.Buffer
	if code := Run([]string{"help"}, output, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("redirected help: exit %d, stderr %q", code, &stderr)
	}
	content, err := os.ReadFile(output.Name())
	if err != nil || string(content) != manual {
		t.Fatalf("redirected help differs from manual: %v", err)
	}
}

func TestBareCommandHelp(t *testing.T) {
	for _, command := range [][]string{nil, {"history"}} {
		var output, help, stderr bytes.Buffer
		if code := Run(command, &output, &stderr); code != 0 || stderr.Len() != 0 {
			t.Fatalf("%v: exit %d, stderr %q", command, code, &stderr)
		}
		if code := Run(append(command, "--help"), &help, &stderr); code != 0 || output.String() != help.String() || !strings.Contains(output.String(), "Usage:") {
			t.Fatalf("%v: bare command differs from --help: %q", command, &output)
		}
	}
	var output, stderr bytes.Buffer
	if code := Run([]string{"unknown-command"}, &output, &stderr); code != 2 || output.Len() != 0 || !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("unknown command: exit %d, stdout %q, stderr %q", code, &output, &stderr)
	}
}

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

func TestHelpHistorySubcommands(t *testing.T) {
	for _, test := range []struct {
		command string
		option  string
	}{
		{"audit", "--reflog"},
		{"rekey", "--keep-undecryptable"},
		{"purge", "--all"},
	} {
		t.Run(test.command, func(t *testing.T) {
			var help, direct, stderr bytes.Buffer
			if code := Run([]string{"help", "history", test.command}, &help, &stderr); code != 0 {
				t.Fatalf("help: exit %d, %s", code, &stderr)
			}
			if code := Run([]string{"history", test.command, "--help"}, &direct, &stderr); code != 0 {
				t.Fatalf("direct help: exit %d, %s", code, &stderr)
			}
			if help.String() != direct.String() || !strings.Contains(help.String(), "git-age history "+test.command) || !strings.Contains(help.String(), test.option) {
				t.Fatalf("nested help differs or is missing options: %s", &help)
			}
		})
	}
	for _, args := range [][]string{{"help", "history", "unknown"}, {"help", "history", "audit", "extra"}, {"help", "commands", "extra"}} {
		var stdout, stderr bytes.Buffer
		if code := Run(args, &stdout, &stderr); code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "unknown help command") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", args, code, &stdout, &stderr)
		}
	}
}

func TestHelpTopic(t *testing.T) {
	for _, topic := range []string{"commands", "git-hooks", "gitage", "shell-completion"} {
		t.Run(topic, func(t *testing.T) {
			var output, stderr bytes.Buffer
			if code := Run([]string{"help", topic}, &output, &stderr); code != 0 {
				t.Fatalf("help: exit %d, %s", code, &stderr)
			}
			heading := strings.ToUpper(strings.ReplaceAll(topic, "-", " "))
			if topic == "gitage" {
				heading = ".GITAGE"
			}
			if !strings.HasPrefix(output.String(), heading+"\n") || strings.Contains(output.String(), "\nDEPENDENCIES\n") {
				t.Fatalf("wrong manual section: %s", &output)
			}
		})
	}
}
