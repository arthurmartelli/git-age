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
)

func TestLock(t *testing.T) {
	for _, source := range []string{"rules", "flag", "environment", "Git config", "own key"} {
		t.Run(source, func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			t.Setenv("GIT_AGE_RECIPIENT", "")
			t.Setenv("GIT_AGE_KEY_FILE", "")
			identity, err := age.GenerateX25519Identity()
			if err != nil {
				t.Fatal(err)
			}
			recipient := identity.Recipient().String()
			rules := "[files]\n*.env\n"
			var args []string
			switch source {
			case "rules":
				rules += "[recipients]\n" + recipient + "\n"
			case "flag":
				args = []string{"-r", recipient}
			case "environment":
				t.Setenv("GIT_AGE_RECIPIENT", recipient)
			case "Git config":
				if err := exec.Command("git", "-C", directory, "config", "age.recipient", recipient).Run(); err != nil {
					t.Fatal(err)
				}
			case "own key":
				writeStatusFile(t, directory, ".gitage.key", identity.String()+"\n")
			}
			writeStatusFile(t, directory, ".gitage", rules)
			writeStatusFile(t, directory, "a.env", "secret\x00bytes\n")
			writeStatusFile(t, directory, "b.env", "untouched")
			args = append(args, "a.env")
			if _, err := runLock(directory, args...); err != nil {
				t.Fatal(err)
			}
			ciphertext, err := os.ReadFile(filepath.Join(directory, "a.env"))
			if err != nil {
				t.Fatal(err)
			}
			reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
			if err != nil {
				t.Fatal(err)
			}
			plaintext, err := io.ReadAll(reader)
			if err != nil || string(plaintext) != "secret\x00bytes\n" {
				t.Fatalf("plaintext: %q, %v", plaintext, err)
			}
			if content, _ := os.ReadFile(filepath.Join(directory, "b.env")); string(content) != "untouched" {
				t.Fatal("unselected file changed")
			}
			if info, err := os.Stat(filepath.Join(directory, "a.env")); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
				t.Fatalf("permissions: %v, %v", info, err)
			}
			if output, err := runLock(directory, append([]string{"-v"}, args...)...); err != nil || !strings.Contains(output, "already locked: a.env") {
				t.Fatalf("second lock: %q, %v", output, err)
			}
			if after, _ := os.ReadFile(filepath.Join(directory, "a.env")); !bytes.Equal(after, ciphertext) {
				t.Fatal("already locked file changed")
			}
		})
	}
}

func TestLockDryRun(t *testing.T) {
	directory := t.TempDir()
	writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n")
	writeStatusFile(t, directory, "a.env", "secret")
	output, err := runLock(directory, "-n")
	if err != nil || output != "would lock: a.env\n" {
		t.Fatalf("dry run: %q, %v", output, err)
	}
	if content, _ := os.ReadFile(filepath.Join(directory, "a.env")); string(content) != "secret" {
		t.Fatal("dry run changed file")
	}
}

func TestLockInvalidRecipientsChangeNothing(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "invalid nested recipient"}[invalid], func(t *testing.T) {
			directory := t.TempDir()
			t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
			t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
			t.Setenv("GIT_AGE_RECIPIENT", "")
			t.Setenv("GIT_AGE_KEY_FILE", "")
			rules := "[files]\n*.env\n"
			if invalid {
				identity, err := age.GenerateX25519Identity()
				if err != nil {
					t.Fatal(err)
				}
				rules += "[recipients]\n" + identity.Recipient().String() + "\n"
				writeStatusFile(t, directory, "sub/.gitage", "[recipients]\nage1invalid\n")
			}
			writeStatusFile(t, directory, ".gitage", rules)
			for _, path := range []string{"a.env", "sub/b.env"} {
				writeStatusFile(t, directory, path, "secret")
			}
			if _, err := runLock(directory); err == nil {
				t.Fatal("expected recipient error")
			}
			for _, path := range []string{"a.env", "sub/b.env"} {
				if content, _ := os.ReadFile(filepath.Join(directory, path)); string(content) != "secret" {
					t.Fatalf("%s changed after failure", path)
				}
			}
		})
	}
}

func runLock(directory string, args ...string) (string, error) {
	var output bytes.Buffer
	root := newRootCommand()
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs(append([]string{"-C", directory, "lock"}, args...))
	err := root.Execute()
	return output.String(), err
}

func TestLockNestedRecipients(t *testing.T) {
	for _, aliased := range []bool{false, true} {
		name := "direct"
		if aliased {
			name = "directory alias"
		}
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			if aliased {
				alias := filepath.Join(t.TempDir(), "repository")
				if err := os.Symlink(directory, alias); err != nil {
					t.Skipf("directory symlinks unavailable: %v", err)
				}
				directory = alias
			}

			first, err := age.GenerateX25519Identity()
			if err != nil {
				t.Fatal(err)
			}
			second, err := age.GenerateX25519Identity()
			if err != nil {
				t.Fatal(err)
			}
			writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+first.Recipient().String()+"\n")
			writeStatusFile(t, directory, "sub/.gitage", "[recipients]\n"+second.Recipient().String()+"\n")
			writeStatusFile(t, directory, "sub/a.env", "shared secret")
			if _, err := runLock(filepath.Join(directory, "sub")); err != nil {
				t.Fatal(err)
			}
			content, err := os.ReadFile(filepath.Join(directory, "sub/a.env"))
			if err != nil {
				t.Fatal(err)
			}
			for _, identity := range []age.Identity{first, second} {
				reader, err := age.Decrypt(bytes.NewReader(content), identity)
				if err != nil {
					t.Fatal(err)
				}
				plaintext, err := io.ReadAll(reader)
				if err != nil || string(plaintext) != "shared secret" {
					t.Fatalf("decrypted: %q, %v", plaintext, err)
				}
			}
		})
	}
}

func TestLockReusesCiphertext(t *testing.T) {
	for _, aliased := range []bool{false, true} {
		name := "direct"
		if aliased {
			name = "directory alias"
		}
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			if aliased {
				alias := filepath.Join(t.TempDir(), "repository")
				if err := os.Symlink(directory, alias); err != nil {
					t.Skipf("directory symlinks unavailable: %v", err)
				}
				directory = alias
			}

			identity, err := age.GenerateX25519Identity()
			if err != nil {
				t.Fatal(err)
			}
			writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+identity.Recipient().String()+"\n")
			writeStatusFile(t, directory, ".gitage.key", identity.String()+"\n")
			writeStatusFile(t, directory, "a.env", "secret")
			if _, err := runLock(directory); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Join(directory, "a.env"))
			if err != nil {
				t.Fatal(err)
			}
			for _, args := range [][]string{{"add", ".gitage", "a.env"}, {"-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", "commit", "-qm", "encrypted"}} {
				if output, err := exec.Command("git", append([]string{"-C", directory}, args...)...).CombinedOutput(); err != nil {
					t.Fatalf("git: %v: %s", err, output)
				}
			}
			writeStatusFile(t, directory, "a.env", "secret")
			if _, err := runLock(directory); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(filepath.Join(directory, "a.env"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("unchanged plaintext did not reuse ciphertext")
			}
			writeStatusFile(t, directory, "a.env", "secret")
			if _, err := runLock(directory, "--no-reuse"); err != nil {
				t.Fatal(err)
			}
			after, err = os.ReadFile(filepath.Join(directory, "a.env"))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(before, after) {
				t.Fatal("--no-reuse reused ciphertext")
			}
			second, err := age.GenerateX25519Identity()
			if err != nil {
				t.Fatal(err)
			}
			writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+identity.Recipient().String()+"\n"+second.Recipient().String()+"\n")
			if err := exec.Command("git", "-C", directory, "add", ".gitage").Run(); err != nil {
				t.Fatal(err)
			}
			for _, committed := range []bool{false, true} {
				if committed {
					cmd := exec.Command("git", "-C", directory, "-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", "commit", "-qm", "add recipient")
					if output, err := cmd.CombinedOutput(); err != nil {
						t.Fatalf("commit: %v: %s", err, output)
					}
				}
				writeStatusFile(t, directory, "a.env", "secret")
				if _, err := runLock(directory); err != nil {
					t.Fatal(err)
				}
				content, err := os.ReadFile(filepath.Join(directory, "a.env"))
				if err != nil {
					t.Fatal(err)
				}
				reader, err := age.Decrypt(bytes.NewReader(content), second)
				if err != nil {
					t.Fatalf("recipient change, committed=%v: %v", committed, err)
				}
				plaintext, err := io.ReadAll(reader)
				if err != nil || string(plaintext) != "secret" {
					t.Fatalf("new recipient: %q, %v", plaintext, err)
				}
			}
		})
	}
}
