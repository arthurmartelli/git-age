package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
)

func TestUnlock(t *testing.T) {
	for _, source := range []string{"local key", "flag", "environment", "Git config"} {
		t.Run(source, func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			t.Setenv("GIT_AGE_KEY_FILE", "")
			identity, err := age.GenerateX25519Identity()
			if err != nil {
				t.Fatal(err)
			}
			writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n")
			key := ".gitage.key"
			var args []string
			if source != "local key" {
				key = "identity.txt"
			}
			writeStatusFile(t, directory, key, identity.String()+"\n")
			switch source {
			case "flag":
				args = []string{"-i", key}
			case "environment":
				t.Setenv("GIT_AGE_KEY_FILE", filepath.Join(directory, key))
			case "Git config":
				if err := exec.Command("git", "-C", directory, "config", "age.keyFile", key).Run(); err != nil {
					t.Fatal(err)
				}
			}
			for _, armored := range []bool{false, true} {
				content := encryptUnlockFixture(t, identity, "secret\x00bytes\n", armored)
				writeStatusFile(t, directory, "a.env", string(content))
				writeStatusFile(t, directory, "sub/b.env", string(content))
				if _, err := runUnlock(directory, append(args, "a.env")...); err != nil {
					t.Fatal(err)
				}
				after, err := os.ReadFile(filepath.Join(directory, "a.env"))
				if err != nil || string(after) != "secret\x00bytes\n" {
					t.Fatalf("plaintext: %q, %v", after, err)
				}
				if unselected, _ := os.ReadFile(filepath.Join(directory, "sub/b.env")); !bytes.Equal(unselected, content) {
					t.Fatal("unselected file changed")
				}
				if output, err := runUnlock(directory, append([]string{"-v"}, append(args, "a.env")...)...); err != nil || output != "already unlocked: a.env\n" {
					t.Fatalf("second unlock: %q, %v", output, err)
				}
				info, err := os.Stat(filepath.Join(directory, "a.env"))
				if err != nil {
					t.Fatal(err)
				}
				if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
					t.Errorf("permissions: %o", info.Mode().Perm())
				}
			}
		})
	}
}

func TestUnlockFailureChangesNothing(t *testing.T) {
	for _, failure := range []string{"wrong key", "corrupt ciphertext", "missing key"} {
		t.Run(failure, func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			t.Setenv("GIT_AGE_KEY_FILE", "")
			identity, err := age.GenerateX25519Identity()
			if err != nil {
				t.Fatal(err)
			}
			writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+identity.Recipient().String()+"\n")
			if failure != "missing key" {
				writeStatusFile(t, directory, ".gitage.key", identity.String()+"\n")
			}
			first := encryptUnlockFixture(t, identity, "first", false)
			second := encryptUnlockFixture(t, identity, "second", false)
			if failure == "wrong key" {
				other, err := age.GenerateX25519Identity()
				if err != nil {
					t.Fatal(err)
				}
				second = encryptUnlockFixture(t, other, "second", false)
			}
			if failure == "corrupt ciphertext" {
				second[len(second)-1] ^= 1
			}
			writeStatusFile(t, directory, "a.env", string(first))
			writeStatusFile(t, directory, "b.env", string(second))
			_, err = runUnlock(directory)
			if err == nil {
				t.Fatal("expected decryption error")
			}
			if failure != "missing key" && !strings.Contains(err.Error(), "b.env") {
				t.Errorf("error does not name failing file: %v", err)
			}
			for name, before := range map[string][]byte{"a.env": first, "b.env": second} {
				if after, _ := os.ReadFile(filepath.Join(directory, name)); !bytes.Equal(before, after) {
					t.Errorf("%s changed on failure", name)
				}
			}
			entries, err := os.ReadDir(directory)
			if err != nil {
				t.Fatal(err)
			}
			want := 5
			if failure == "missing key" {
				want = 4
			}
			if len(entries) != want {
				t.Fatalf("unexpected files after failure: %v", entries)
			}
		})
	}
}

func TestUnlockDryRun(t *testing.T) {
	directory := t.TempDir()
	writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n")
	writeStatusFile(t, directory, "a.env", "age-encryption.org/v1\n")
	output, err := runUnlock(directory, "-n")
	if err != nil || output != "would unlock: a.env\n" {
		t.Fatalf("dry run: %q, %v", output, err)
	}
	if after, _ := os.ReadFile(filepath.Join(directory, "a.env")); string(after) != "age-encryption.org/v1\n" {
		t.Fatal("dry run changed file")
	}
}

func TestUnlockFromSubdirectory(t *testing.T) {
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n")
	writeStatusFile(t, directory, ".gitage.key", identity.String()+"\n")
	writeStatusFile(t, directory, "sub/a.env", string(encryptUnlockFixture(t, identity, "secret", false)))
	if _, err := runUnlock(filepath.Join(directory, "sub"), "a.env"); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(filepath.Join(directory, "sub/a.env")); string(after) != "secret" {
		t.Fatal("subdirectory key discovery failed")
	}
}

func TestUnlockAlreadyPlaintextNeedsNoKey(t *testing.T) {
	directory := t.TempDir()
	writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n")
	writeStatusFile(t, directory, "a.env", "plaintext")
	output, err := runUnlock(directory, "-v", "-i", "missing.key")
	if err != nil || output != "already unlocked: a.env\n" {
		t.Fatalf("already unlocked: %q, %v", output, err)
	}
}

func TestLockUnlockRoundTrip(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_AGE_KEY_FILE", "")
	t.Setenv("GIT_AGE_RECIPIENT", "")
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n")
	writeStatusFile(t, directory, ".gitage.key", identity.String()+"\n")
	writeStatusFile(t, directory, "a.env", "secret")
	if _, err := runLock(directory); err != nil {
		t.Fatal(err)
	}
	if _, err := runUnlock(directory); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(directory, "a.env"))
	if err != nil || string(content) != "secret" {
		t.Fatalf("round trip: %q, %v", content, err)
	}
}

func encryptUnlockFixture(t *testing.T, identity *age.X25519Identity, plaintext string, armored bool) []byte {
	t.Helper()
	var output bytes.Buffer
	if armored {
		outer := armor.NewWriter(&output)
		writer, err := age.Encrypt(outer, identity.Recipient())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(plaintext)); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if err := outer.Close(); err != nil {
			t.Fatal(err)
		}
	} else {
		writer, err := age.Encrypt(&output, identity.Recipient())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(plaintext)); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return output.Bytes()
}

func runUnlock(directory string, args ...string) (string, error) {
	var output bytes.Buffer
	root := newRootCommand()
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs(append([]string{"-C", directory, "unlock"}, args...))
	err := root.Execute()
	return output.String(), err
}
