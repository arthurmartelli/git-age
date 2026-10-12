//go:build !windows

package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func detachTerminal(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

func TestInteractiveCommit(t *testing.T) {
	if _, err := exec.LookPath("script"); err != nil {
		t.Fatal("interactive integration tests require script")
	}
	buildGitAge(t)
	for _, test := range []struct {
		name, input, diagnostic string
		commits, encrypted      bool
	}{
		{"abort", "a\n", "commit aborted", false, false},
		{"encrypt", "e\n", "", true, true},
		{"unconfirmed plaintext", "c\nno\n", "not confirmed", false, false},
		{"confirmed plaintext", "c\ncommit\n", "", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			isolateHookEnvironment(t)
			directory, identity, _ := cleanFixture(t, []byte("original\n"), false)
			mustCommand(t, directory, "install", "--hook-mode=interactive")
			writeFile(t, directory, "secret.env", "changed\n")
			runGit(t, directory, "add", "secret.env")
			head := gitRevision(t, directory, "HEAD")
			index := runGit(t, directory, "ls-files", "--stage", "-z")
			// Keep a writer open until the commit exits. macOS script otherwise sends
			// EOF before it has flushed queued answers to the pseudo-terminal.
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			if _, err := writer.WriteString(test.input); err != nil {
				t.Fatal(err)
			}
			program := "git -C '" + strings.ReplaceAll(directory, "'", `'"'"'`) + "' commit -q -m interactive"
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			args := []string{"-q", "-e", "-c", program, "/dev/null"}
			if runtime.GOOS == "darwin" {
				args = []string{"-q", "/dev/null", "sh", "-c", program}
			}
			command := exec.CommandContext(ctx, "script", args...)
			command.Stdin = reader
			command.WaitDelay = time.Second
			command.Env = append(os.Environ(), "SHELL=/bin/sh")
			output, err := command.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("terminal commit timed out:\n%s", output)
			}
			if (err == nil) != test.commits || !bytes.Contains(output, []byte(test.diagnostic)) {
				t.Fatalf("terminal commit: %v\n%s", err, output)
			}
			if !test.commits {
				if gitRevision(t, directory, "HEAD") != head || !bytes.Equal(index, runGit(t, directory, "ls-files", "--stage", "-z")) || string(readFile(t, directory, "secret.env")) != "changed\n" {
					t.Fatal("aborted interactive commit changed files, index or HEAD")
				}
				return
			}
			if gitRevision(t, directory, "HEAD") == head {
				t.Fatal("confirmed commit did not move HEAD")
			}
			staged := runGit(t, directory, "show", "HEAD:secret.env")
			if test.encrypted {
				assertDecrypts(t, staged, identity, []byte("changed\n"))
			} else if string(staged) != "changed\n" {
				t.Fatalf("confirmed plaintext commit: %q", staged)
			}
		})
	}
}
