package cli

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
)

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
