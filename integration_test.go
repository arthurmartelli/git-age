package gitage_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func buildLauncher(t *testing.T) string {
	t.Helper()
	name := "git-age"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binary := filepath.Join(t.TempDir(), "bin", name)
	command := exec.Command("go", "build", "-trimpath", "-o", binary, "./cmd/git-age")
	command.Env = withEnv("CGO_ENABLED=0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build launcher: %v\n%s", err, output)
	}
	return binary
}

func withEnv(replacements ...string) []string {
	environment := os.Environ()
	for _, replacement := range replacements {
		key, _, _ := strings.Cut(replacement, "=")
		filtered := make([]string, 0, len(environment)+1)
		for _, entry := range environment {
			name, _, _ := strings.Cut(entry, "=")
			if !strings.EqualFold(name, key) {
				filtered = append(filtered, entry)
			}
		}
		environment = append(filtered, replacement)
	}
	return environment
}

func TestLauncher(t *testing.T) {
	binary := buildLauncher(t)
	reference := filepath.Join(filepath.Dir(filepath.Dir(binary)), "git-age")
	// This fixture tests transport, independently of git-age's implementation.
	script := `import json, os, sys
print(json.dumps({"args": sys.argv[1:], "cwd": os.getcwd(), "env": os.getenv("GIT_AGE_WRAPPER_TEST"), "stdin": sys.stdin.buffer.read().hex()}))
sys.stderr.buffer.write(b"stderr\x00\xff")
sys.exit(23)
`
	if err := os.WriteFile(reference, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	cwd := t.TempDir()
	arguments := []string{"-C", "directory with spaces", "lock", "-r", "ssh-ed25519 abc comment", "semi;colon", "$literal"}
	input := []byte{0, 1, 10, 13, 255}
	for _, override := range []bool{false, true} {
		name := "relative-to-executable"
		if override {
			name = "explicit-reference"
		}
		t.Run(name, func(t *testing.T) {
			command := exec.Command(binary, arguments...)
			command.Dir = cwd
			command.Env = withEnv("GIT_AGE_PYTHON_SCRIPT=", "GIT_AGE_WRAPPER_TEST=forwarded")
			if override {
				// Prove the override is used, even with spaces in the filename.
				path := filepath.Join(t.TempDir(), "reference script.py")
				if err := os.WriteFile(path, []byte(script), 0600); err != nil {
					t.Fatal(err)
				}
				command.Env = withEnv("GIT_AGE_PYTHON_SCRIPT="+path, "GIT_AGE_WRAPPER_TEST=forwarded")
			}
			command.Stdin = bytes.NewReader(input)
			var stdout, stderr bytes.Buffer
			command.Stdout, command.Stderr = &stdout, &stderr
			err := command.Run()
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 23 {
				t.Fatalf("expected exit 23, got %v; stderr: %s", err, &stderr)
			}
			var got struct {
				Args            []string
				Cwd, Env, Stdin string
			}
			if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
				t.Fatalf("stdout: %q: %v", &stdout, err)
			}
			wantArgs, _ := json.Marshal(arguments)
			gotArgs, _ := json.Marshal(got.Args)
			if !bytes.Equal(gotArgs, wantArgs) || got.Env != "forwarded" || got.Stdin != "00010a0dff" {
				t.Fatalf("transport changed: %+v", got)
			}
			wantDir, err := os.Stat(cwd)
			if err != nil {
				t.Fatal(err)
			}
			gotDir, err := os.Stat(got.Cwd)
			if err != nil || !os.SameFile(wantDir, gotDir) {
				t.Fatalf("working directory changed: %q", got.Cwd)
			}
			if !bytes.Equal(stderr.Bytes(), []byte{'s', 't', 'd', 'e', 'r', 'r', 0, 255}) {
				t.Fatalf("stderr changed: %q", &stderr)
			}
		})
	}
	if runtime.GOOS != "windows" {
		t.Run("symlink-from-another-directory", func(t *testing.T) {
			link := filepath.Join(t.TempDir(), "git-age")
			if err := os.Symlink(binary, link); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(link)
			command.Dir = cwd
			command.Env = withEnv("GIT_AGE_PYTHON_SCRIPT=")
			if output, err := command.CombinedOutput(); err == nil || command.ProcessState.ExitCode() != 23 {
				t.Fatalf("symlink launch: %v\n%s", err, output)
			}
		})
		t.Run("interrupt", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "interrupt.py")
			if err := os.WriteFile(path, []byte("import time\nprint('ready', flush=True)\ntry:\n    time.sleep(60)\nexcept KeyboardInterrupt:\n    raise SystemExit(130)\n"), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, binary)
			command.Env = withEnv("GIT_AGE_PYTHON_SCRIPT=" + path)
			stdout, err := command.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			ready, err := bufio.NewReader(stdout).ReadString('\n')
			if err != nil || ready != "ready\n" {
				_ = command.Wait()
				t.Fatalf("waiting for Python: %q, %v", ready, err)
			}
			if err := command.Process.Signal(os.Interrupt); err != nil {
				t.Fatal(err)
			}
			if err := command.Wait(); err == nil || command.ProcessState.ExitCode() != 130 {
				t.Fatalf("interrupt exit: %v", err)
			}
		})
	}
	t.Run("missing-reference", func(t *testing.T) {
		command := exec.Command(binary)
		command.Env = withEnv("GIT_AGE_PYTHON_SCRIPT=" + filepath.Join(t.TempDir(), "missing.py"))
		if output, err := command.CombinedOutput(); err == nil || !bytes.Contains(output, []byte("Python reference not found")) {
			t.Fatalf("missing reference: %v\n%s", err, output)
		}
	})
}

func TestAcceptance(t *testing.T) {
	binary := buildLauncher(t)
	reference, err := filepath.Abs("git-age")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "bash", "./git-age-test.sh")
	command.Env = withEnv("GIT_AGE="+filepath.ToSlash(binary), "GIT_AGE_PYTHON_SCRIPT="+reference)
	command.WaitDelay = 5 * time.Second
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("acceptance suite: %v\n%s", err, output)
	}
	t.Logf("%s", output)
}
