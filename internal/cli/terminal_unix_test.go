//go:build !windows

package cli

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func detachTerminal(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

func TestEditTerminalInterrupt(t *testing.T) {
	script, err := exec.LookPath("script")
	if err != nil {
		t.Fatal("terminal editor tests require script")
	}
	binary := buildGitAge(t)
	isolateHookEnvironment(t)
	directory, identity, _ := cleanFixture(t, []byte("original\n"), false)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'" }
	// A plain editor command runs without a shell. Under dash, a shell waiting
	// in front of the editor would be killed by the editor's Ctrl-C.
	editor := filepath.Join(t.TempDir(), "editor")
	if err := os.WriteFile(editor, []byte("#!/bin/sh\nexec "+quote(executable)+" -test.run=^TestInterruptEditor$ -- \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_EDITOR", editor)
	t.Setenv("GIT_AGE_TEST_INTERRUPT_EDITOR", "save")
	program := quote(binary) + " -C " + quote(directory) + " edit secret.env"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	args := []string{"-q", "-e", "-c", program, "/dev/null"}
	if runtime.GOOS == "darwin" {
		args = []string{"-q", "/dev/null", "/bin/sh", "-c", program}
	}
	command := exec.CommandContext(ctx, script, args...)
	command.Env = append(os.Environ(), "SHELL=/bin/sh")
	command.WaitDelay = time.Second
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer writer.Close()
	command.Stdin = input
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(output)
	waitFor := func(message string) {
		t.Helper()
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("waiting for %q: %v, %q, stderr %q", message, err, line, &stderr)
			}
			if strings.Contains(line, message) {
				return
			}
		}
	}
	waitFor("editor ready")
	for range 2 {
		if _, err := writer.Write([]byte{3}); err != nil {
			t.Fatal(err)
		}
		waitFor("editor handled interrupt")
	}
	if _, err := writer.WriteString("save\n"); err != nil {
		t.Fatal(err)
	}
	remaining, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil || ctx.Err() != nil || stderr.Len() != 0 {
		t.Fatalf("terminal editor: %v, timeout %v, output %q, stderr %q", err, ctx.Err(), remaining, &stderr)
	}
	assertDecrypts(t, readFile(t, directory, "secret.env"), identity, []byte("saved\n"))
	assertNoEditCopies(t, directory)
}

func TestEditTerminationRestoresTerminal(t *testing.T) {
	script, err := exec.LookPath("script")
	if err != nil {
		t.Fatal("terminal editor tests require script")
	}
	binary := buildGitAge(t)
	isolateHookEnvironment(t)
	directory, _, ciphertext := cleanFixture(t, []byte("original\n"), false)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'" }
	t.Setenv("GIT_EDITOR", "exec "+quote(executable)+" -test.run=^TestInterruptEditor$ --")
	t.Setenv("GIT_AGE_TEST_INTERRUPT_EDITOR", "save")
	t.Setenv("GIT_AGE_TEST_RAW_EDITOR", "1")
	program := quote(binary) + " -C " + quote(directory) + ` edit secret.env; editor_status=$?; stty -a; exit "$editor_status"`
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	args := []string{"-q", "-e", "-c", program, "/dev/null"}
	if runtime.GOOS == "darwin" {
		args = []string{"-q", "/dev/null", "/bin/sh", "-c", program}
	}
	command := exec.CommandContext(ctx, script, args...)
	command.Env = append(os.Environ(), "SHELL=/bin/sh")
	command.WaitDelay = time.Second
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer writer.Close()
	command.Stdin = input
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(output)
	ready, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(ready, "editor ready ") {
		t.Fatalf("raw editor did not start: %q, %v", ready, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(ready, "editor ready ")))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	remaining, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil || ctx.Err() != nil || !bytes.Contains(remaining, []byte("git-age: terminated")) || bytes.Contains(remaining, []byte("-icanon")) || bytes.Contains(remaining, []byte("-echo ")) {
		t.Fatalf("terminal was not restored: %v, timeout %v, output %q", err, ctx.Err(), remaining)
	}
	if !bytes.Equal(ciphertext, readFile(t, directory, "secret.env")) {
		t.Fatal("termination changed ciphertext")
	}
	assertNoEditCopies(t, directory)
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
