//go:build !windows

package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestInterrupt(t *testing.T) {
	binary := buildGitAge(t)
	t.Run("blocked input", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, binary, "clean", "secret.env")
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		input, err := command.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		defer input.Close()
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		// More than a pipe can buffer, so completion proves clean has started
		// reading input. Keep the pipe open to block it waiting for EOF.
		if _, err := input.Write(bytes.Repeat([]byte("x"), 2<<20)); err != nil {
			t.Fatal(err)
		}
		if err := command.Process.Signal(os.Interrupt); err != nil {
			t.Fatal(err)
		}
		checkInterruptExit(t, command.Wait(), &stderr)
		if stdout.Len() != 0 {
			t.Fatalf("interruption wrote to stdout: %q", &stdout)
		}
	})
	for _, test := range []struct {
		name, editor, diagnostic string
		signal                   os.Signal
		code                     int
	}{
		{"editor interrupt", "exec ", "editor: exit status 7; secret.env was not changed", os.Interrupt, 7},
		{"editor hangup", "", "git-age: hangup\n", syscall.SIGHUP, 129},
		{"editor termination", "", "git-age: terminated\n", syscall.SIGTERM, 143},
	} {
		t.Run(test.name, func(t *testing.T) {
			isolateHookEnvironment(t)
			directory, _, ciphertext := cleanFixture(t, []byte("original\n"), false)
			scratch := t.TempDir()
			t.Setenv("TMPDIR", scratch)
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("GIT_EDITOR", test.editor+"'"+strings.ReplaceAll(executable, "'", `'"'"'`)+"' -test.run=^TestInterruptEditor$ --")
			t.Setenv("GIT_AGE_TEST_INTERRUPT_EDITOR", "exit7")
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, binary, "-C", directory, "edit", "secret.env")
			var stderr bytes.Buffer
			command.Stderr = &stderr
			input, err := command.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			output, err := command.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(output)
			if ready, err := reader.ReadString('\n'); err != nil || ready != "editor ready\n" {
				t.Fatalf("editor did not start: %q, %v", ready, err)
			}
			if err := command.Process.Signal(test.signal); err != nil {
				t.Fatal(err)
			}
			remaining, err := io.ReadAll(reader)
			if err != nil || test.signal != os.Interrupt && len(remaining) != 0 || test.signal == os.Interrupt && !bytes.Contains(remaining, []byte("editor handled interrupt")) {
				t.Fatalf("interruption wrote to stdout: %q, %v", remaining, err)
			}
			var exit *exec.ExitError
			if err := command.Wait(); !errors.As(err, &exit) || exit.ExitCode() != test.code || !strings.Contains(stderr.String(), test.diagnostic) {
				t.Fatalf("editor signal: %v, stderr %q", err, &stderr)
			}
			if !bytes.Equal(ciphertext, readFile(t, directory, "secret.env")) {
				t.Fatal("interrupted edit changed ciphertext")
			}
			if entries, err := os.ReadDir(scratch); err != nil || len(entries) != 0 {
				t.Fatalf("plaintext copies left behind: %v, %v", entries, err)
			}
			assertNoEditCopies(t, directory)
		})
	}
}

func checkInterruptExit(t *testing.T, err error, stderr *bytes.Buffer) {
	t.Helper()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 130 {
		t.Fatalf("interrupt: %v, stderr: %q", err, stderr)
	}
	if stderr.String() != "git-age: interrupted\n" {
		t.Fatalf("interrupt message: %q", stderr)
	}
}

func TestInterruptEditor(t *testing.T) {
	action := os.Getenv("GIT_AGE_TEST_INTERRUPT_EDITOR")
	if action == "" {
		return
	}
	path := os.Args[len(os.Args)-1]
	if filepath.Base(path) != "secret.env" {
		t.Fatalf("unexpected editor path: %s", path)
	}
	if err := os.WriteFile(path, []byte("edited\n"), 0600); err != nil {
		t.Fatal(err)
	}
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	defer signal.Stop(interrupts)
	fmt.Fprintln(os.Stdout, "editor ready")
	input := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		input <- line
	}()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case <-interrupts:
			fmt.Fprintln(os.Stdout, "editor handled interrupt")
			if action == "exit7" {
				os.Exit(7)
			}
		case line := <-input:
			if action != "save" || line != "save\n" {
				os.Exit(99)
			}
			if err := os.WriteFile(path, []byte("saved\n"), 0600); err != nil {
				t.Fatal(err)
			}
			os.Exit(0)
		case <-timeout:
			os.Exit(99)
		}
	}
}
