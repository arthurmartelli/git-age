package cli

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// buildGitAge puts the real executable on PATH so installed Git hooks and
// drivers exercise the same entrypoint users run.
func buildGitAge(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	name := "git-age"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(bin, name)
	build := exec.Command("go", "build", "-o", path, "./cmd/git-age")
	build.Dir = "../.."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return path
}

func mustCommand(t *testing.T, directory, command string, args ...string) string {
	t.Helper()
	output, err := runCommand(directory, command, args...)
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", command, args, err, output)
	}
	return output
}

func refuseGit(t *testing.T, directory, diagnostic string, args ...string) []byte {
	t.Helper()
	output, err := exec.Command("git", append([]string{"-C", directory}, args...)...).CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte(diagnostic)) {
		t.Fatalf("git %v: %v, %s; want refusal containing %q", args, err, output, diagnostic)
	}
	return output
}

func gitRevision(t *testing.T, directory, revision string) string {
	t.Helper()
	return strings.TrimSpace(string(runGit(t, directory, "rev-parse", revision)))
}

func assertCannotDecrypt(t *testing.T, ciphertext []byte, identity age.Identity) {
	t.Helper()
	if _, err := age.Decrypt(bytes.NewReader(ciphertext), identity); err == nil {
		t.Fatal("excluded recipient can decrypt")
	}
}

func assertSnapshotUnchanged(t *testing.T, directory string, before map[string]string) {
	t.Helper()
	after := installSnapshot(t, directory)
	changed := false
	for path, old := range before {
		name, err := filepath.Rel(directory, path)
		if err != nil {
			t.Fatal(err)
		}
		current, exists := after[path]
		if !exists {
			t.Errorf("removed %s", name)
			changed = true
			continue
		}
		if current != old {
			oldMode, oldContent, _ := strings.Cut(old, "\n")
			newMode, newContent, _ := strings.Cut(current, "\n")
			t.Errorf("changed %s: mode %s -> %s, content changed: %t", name, oldMode, newMode, oldContent != newContent)
			changed = true
		}
	}
	for path, current := range after {
		if _, exists := before[path]; !exists {
			name, err := filepath.Rel(directory, path)
			if err != nil {
				t.Fatal(err)
			}
			mode, _, _ := strings.Cut(current, "\n")
			t.Errorf("added %s: mode %s", name, mode)
			changed = true
		}
	}
	if changed {
		t.FailNow()
	}
}

// runCommand runs a git-age command in directory, combining its output.
func runCommand(directory, command string, args ...string) (string, error) {
	var output bytes.Buffer
	root := newRootCommand()
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs(append([]string{"-C", directory, command}, args...))
	err := root.Execute()
	return output.String(), err
}

func runGit(t *testing.T, directory string, args ...string) []byte {
	t.Helper()
	output, err := exec.Command("git", append([]string{"-C", directory}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
	return output
}

func newIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func readFile(t *testing.T, directory, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(directory, path))
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func assertDecrypts(t *testing.T, ciphertext []byte, identity age.Identity, want []byte) {
	t.Helper()
	var input io.Reader = bytes.NewReader(ciphertext)
	if bytes.HasPrefix(ciphertext, []byte("-----BEGIN")) {
		input = armor.NewReader(input)
	}
	reader, err := age.Decrypt(input, identity)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(plaintext, want) {
		t.Fatalf("decrypted content: %q, %v; want %q", plaintext, err, want)
	}
}

func writeFile(t *testing.T, directory, name, content string) {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func encryptFixture(t *testing.T, recipient age.Recipient, plaintext string, armored bool) []byte {
	t.Helper()
	var output bytes.Buffer
	var destination io.Writer = &output
	var outer io.WriteCloser
	if armored {
		outer = armor.NewWriter(&output)
		destination = outer
	}
	writer, err := age.Encrypt(destination, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(plaintext)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if outer != nil {
		if err := outer.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return output.Bytes()
}
