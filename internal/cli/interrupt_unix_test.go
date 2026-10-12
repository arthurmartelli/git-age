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
	"path/filepath"
	"strings"
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
	t.Run("editor cleanup", func(t *testing.T) {
		isolateHookEnvironment(t)
		directory, _, ciphertext := cleanFixture(t, []byte("original\n"), false)
		scratch := t.TempDir()
		t.Setenv("TMPDIR", scratch)
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("GIT_EDITOR", "exec '"+strings.ReplaceAll(executable, "'", `'"'"'`)+"' -test.run=^TestInterruptEditor$ --")
		t.Setenv("GIT_AGE_TEST_INTERRUPT_EDITOR", "1")
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
		if err := command.Process.Signal(os.Interrupt); err != nil {
			t.Fatal(err)
		}
		remaining, err := io.ReadAll(reader)
		if err != nil || len(remaining) != 0 {
			t.Fatalf("interruption wrote to stdout: %q, %v", remaining, err)
		}
		checkInterruptExit(t, command.Wait(), &stderr)
		if !bytes.Equal(ciphertext, readFile(t, directory, "secret.env")) {
			t.Fatal("interrupted edit changed ciphertext")
		}
		if entries, err := os.ReadDir(scratch); err != nil || len(entries) != 0 {
			t.Fatalf("plaintext copies left behind: %v, %v", entries, err)
		}
	})
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
	if os.Getenv("GIT_AGE_TEST_INTERRUPT_EDITOR") == "" {
		return
	}
	path := os.Args[len(os.Args)-1]
	if filepath.Base(path) != "secret.env" {
		t.Fatalf("unexpected editor path: %s", path)
	}
	if err := os.WriteFile(path, []byte("edited\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(os.Stdout, "editor ready")
	var input [1]byte
	os.Stdin.Read(input[:])
	os.Exit(0)
}
