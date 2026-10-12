//go:build !windows

package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestHelpPagerOnTerminal(t *testing.T) {
	script, err := exec.LookPath("script")
	if err != nil {
		t.Fatal("terminal pager tests require script")
	}
	binary := buildGitAge(t)
	for _, scenario := range []struct {
		name, gitPager, pager, prefix string
		args                          []string
		setGitPager, setPager, piped  bool
		missingLess, quit, fail       bool
	}{
		{name: "GIT_PAGER takes precedence", gitPager: "printf '%s\\n' 'git pager'; cat", pager: "exit 99", setGitPager: true, setPager: true, prefix: "git pager\n"},
		{name: "PAGER topic", pager: "printf '%s\\n' 'topic pager'; cat", setPager: true, args: []string{"commands"}, prefix: "topic pager\n"},
		{name: "command options", gitPager: "printf '%s\\n' 'command pager'; cat", setGitPager: true, args: []string{"history", "audit"}, prefix: "command pager\n"},
		{name: "default less flags", prefix: "default pager -FRX\n"},
		{name: "empty GIT_PAGER", setGitPager: true, setPager: true, pager: "exit 99"},
		{name: "GIT_PAGER cat", setGitPager: true, gitPager: "cat", setPager: true, pager: "exit 99"},
		{name: "empty PAGER", setPager: true},
		{name: "PAGER cat", setPager: true, pager: "cat"},
		{name: "piped output", setGitPager: true, gitPager: "exit 99", piped: true},
		{name: "missing less", missingLess: true},
		{name: "pager quits early", setGitPager: true, gitPager: "exit 0", quit: true},
		{name: "pager fails", setGitPager: true, gitPager: "exit 7", fail: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			for _, name := range []string{"GIT_PAGER", "PAGER"} {
				t.Setenv(name, "")
				if err := os.Unsetenv(name); err != nil {
					t.Fatal(err)
				}
			}
			if scenario.setGitPager {
				t.Setenv("GIT_PAGER", scenario.gitPager)
			}
			if scenario.setPager {
				t.Setenv("PAGER", scenario.pager)
			}
			bin := t.TempDir()
			writeFile(t, bin, "less", "#!/bin/sh\nprintf 'default pager %s\\n' \"$*\"\ncat\n")
			if err := os.Chmod(filepath.Join(bin, "less"), 0755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			if scenario.missingLess {
				t.Setenv("PATH", t.TempDir())
			}
			directory := t.TempDir() // Help must work outside Git without an identity.
			args := append([]string{"-C", directory, "help"}, scenario.args...)
			var expected, stderr bytes.Buffer
			if code := Run(args, &expected, &stderr); code != 0 {
				t.Fatalf("direct help: exit %d, stderr %q", code, &stderr)
			}
			quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'" }
			program := quote(binary)
			for _, arg := range args {
				program += " " + quote(arg)
			}
			if scenario.piped {
				program += " | cat"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			scriptArgs := []string{"-q", "-e", "-c", program, "/dev/null"}
			if runtime.GOOS == "darwin" {
				scriptArgs = []string{"-q", "/dev/null", "/bin/sh", "-c", program}
			}
			command := exec.CommandContext(ctx, script, scriptArgs...)
			command.Env = append(os.Environ(), "SHELL=/bin/sh", "TERM=xterm")
			command.WaitDelay = time.Second
			// Keep stdin open so script does not send EOF before help finishes.
			input, keepOpen, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			defer keepOpen.Close()
			command.Stdin = input
			output, err := command.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("terminal help timed out: %s", output)
			}
			text := strings.ReplaceAll(string(output), "\r", "")
			if scenario.fail {
				if err == nil || !strings.Contains(text, "git-age: pager: exit status 7") {
					t.Fatalf("pager failure: %v, %q", err, text)
				}
				return
			}
			want := scenario.prefix + expected.String()
			if scenario.quit {
				want = ""
			}
			if err != nil || text != want {
				t.Fatalf("terminal help: %v, got %q, want %q", err, text, want)
			}
		})
	}
}
