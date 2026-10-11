package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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
			identity := newIdentity(t)
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
				writeFile(t, directory, ".gitage.key", identity.String()+"\n")
			}
			writeFile(t, directory, ".gitage", rules)
			writeFile(t, directory, "a.env", "secret\x00bytes\n")
			writeFile(t, directory, "b.env", "untouched")
			args = append(args, "a.env")
			if _, err := runCommand(directory, "lock", args...); err != nil {
				t.Fatal(err)
			}
			ciphertext := readFile(t, directory, "a.env")
			assertDecrypts(t, ciphertext, identity, []byte("secret\x00bytes\n"))
			if content, _ := os.ReadFile(filepath.Join(directory, "b.env")); string(content) != "untouched" {
				t.Fatal("unselected file changed")
			}
			if info, err := os.Stat(filepath.Join(directory, "a.env")); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
				t.Fatalf("permissions: %v, %v", info, err)
			}
			if output, err := runCommand(directory, "lock", append([]string{"-v"}, args...)...); err != nil || !strings.Contains(output, "already locked: a.env") {
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
	writeFile(t, directory, ".gitage", "[files]\n*.env\n")
	writeFile(t, directory, "a.env", "secret")
	output, err := runCommand(directory, "lock", "-n")
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
				identity := newIdentity(t)
				rules += "[recipients]\n" + identity.Recipient().String() + "\n"
				writeFile(t, directory, "sub/.gitage", "[recipients]\nage1invalid\n")
			}
			writeFile(t, directory, ".gitage", rules)
			for _, path := range []string{"a.env", "sub/b.env"} {
				writeFile(t, directory, path, "secret")
			}
			if _, err := runCommand(directory, "lock"); err == nil {
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

func TestLockIgnoresSymlinkedRules(t *testing.T) {
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	t.Setenv("GIT_AGE_KEY_FILE", "")
	t.Setenv("GIT_AGE_RECIPIENT", "")
	identity, linkedRecipient := newIdentity(t), newIdentity(t)
	external := t.TempDir()
	writeFile(t, external, "identity.key", identity.String()+"\n")
	writeFile(t, external, "linked.gitage", "[files]\npublic.env\n[recipients]\n"+linkedRecipient.Recipient().String()+"\n")
	if err := os.Symlink(filepath.Join(external, "linked.gitage"), filepath.Join(directory, ".gitage")); err != nil {
		t.Skipf("file symlinks unavailable: %v", err)
	}
	writeFile(t, directory, "sub/.gitage", "[files]\nx.env\n")
	writeFile(t, directory, "sub/x.env", "secret\n")
	writeFile(t, directory, "public.env", "public\n")
	runGit(t, directory, "config", "age.keyFile", filepath.Join(external, "identity.key"))
	// Reproduce `git -c age.keyFile= age lock`, clearing the configured key.
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "age.keyFile")
	t.Setenv("GIT_CONFIG_VALUE_0", "")
	before := installSnapshot(t, directory)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-C", directory, "lock"}, &stdout, &stderr)
	if code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "no encryption key configured") {
		t.Fatalf("missing key: exit %d, stdout %q, stderr %q", code, &stdout, &stderr)
	}
	if !reflect.DeepEqual(before, installSnapshot(t, directory)) {
		t.Fatal("failed lock changed files")
	}
	// An explicit identity encrypts the nested file to itself, without granting
	// access to the recipient or matching the pattern in the symlinked rules.
	if _, err := runCommand(directory, "lock", "-i", filepath.Join(external, "identity.key")); err != nil {
		t.Fatal(err)
	}
	ciphertext := readFile(t, directory, "sub/x.env")
	assertDecrypts(t, ciphertext, identity, []byte("secret\n"))
	if _, err := age.Decrypt(bytes.NewReader(ciphertext), linkedRecipient); err == nil {
		t.Fatal("used a recipient from symlinked rules")
	}
	if content, err := os.ReadFile(filepath.Join(directory, "public.env")); err != nil || string(content) != "public\n" {
		t.Fatal("used a pattern from symlinked rules")
	}
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

			first := newIdentity(t)
			second := newIdentity(t)
			writeFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+first.Recipient().String()+"\n")
			writeFile(t, directory, "sub/.gitage", "[recipients]\n"+second.Recipient().String()+"\n")
			writeFile(t, directory, "sub/a.env", "shared secret")
			if _, err := runCommand(filepath.Join(directory, "sub"), "lock"); err != nil {
				t.Fatal(err)
			}
			content := readFile(t, directory, "sub/a.env")
			for _, identity := range []age.Identity{first, second} {
				assertDecrypts(t, content, identity, []byte("shared secret"))
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

			identity := newIdentity(t)
			writeFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+identity.Recipient().String()+"\n")
			writeFile(t, directory, ".gitage.key", identity.String()+"\n")
			writeFile(t, directory, "a.env", "secret")
			if _, err := runCommand(directory, "lock"); err != nil {
				t.Fatal(err)
			}
			before := readFile(t, directory, "a.env")
			for _, args := range [][]string{{"add", ".gitage", "a.env"}, {"-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", "commit", "-qm", "encrypted"}} {
				if output, err := exec.Command("git", append([]string{"-C", directory}, args...)...).CombinedOutput(); err != nil {
					t.Fatalf("git: %v: %s", err, output)
				}
			}
			writeFile(t, directory, "a.env", "secret")
			if _, err := runCommand(directory, "lock"); err != nil {
				t.Fatal(err)
			}
			after := readFile(t, directory, "a.env")
			if !bytes.Equal(before, after) {
				t.Fatal("unchanged plaintext did not reuse ciphertext")
			}
			writeFile(t, directory, "a.env", "secret")
			if _, err := runCommand(directory, "lock", "--no-reuse"); err != nil {
				t.Fatal(err)
			}
			after = readFile(t, directory, "a.env")
			if bytes.Equal(before, after) {
				t.Fatal("--no-reuse reused ciphertext")
			}
			second := newIdentity(t)
			writeFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+identity.Recipient().String()+"\n"+second.Recipient().String()+"\n")
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
				writeFile(t, directory, "a.env", "secret")
				if _, err := runCommand(directory, "lock"); err != nil {
					t.Fatal(err)
				}
				content := readFile(t, directory, "a.env")
				assertDecrypts(t, content, second, []byte("secret"))
			}
		})
	}
}
