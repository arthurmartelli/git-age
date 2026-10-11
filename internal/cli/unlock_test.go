package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestUnlock(t *testing.T) {
	for _, source := range []string{"local key", "flag", "environment", "Git config"} {
		t.Run(source, func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			t.Setenv("GIT_AGE_KEY_FILE", "")
			identity := newIdentity(t)
			writeFile(t, directory, ".gitage", "[files]\n*.env\n")
			key := ".gitage.key"
			var args []string
			if source != "local key" {
				key = "identity.txt"
			}
			writeFile(t, directory, key, identity.String()+"\n")
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
				content := encryptFixture(t, identity.Recipient(), "secret\x00bytes\n", armored)
				writeFile(t, directory, "a.env", string(content))
				writeFile(t, directory, "sub/b.env", string(content))
				if _, err := runCommand(directory, "unlock", append(args, "a.env")...); err != nil {
					t.Fatal(err)
				}
				after, err := os.ReadFile(filepath.Join(directory, "a.env"))
				if err != nil || string(after) != "secret\x00bytes\n" {
					t.Fatalf("plaintext: %q, %v", after, err)
				}
				if unselected, _ := os.ReadFile(filepath.Join(directory, "sub/b.env")); !bytes.Equal(unselected, content) {
					t.Fatal("unselected file changed")
				}
				if output, err := runCommand(directory, "unlock", append([]string{"-v"}, append(args, "a.env")...)...); err != nil || output != "already unlocked: a.env\n" {
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
			identity := newIdentity(t)
			writeFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+identity.Recipient().String()+"\n")
			if failure != "missing key" {
				writeFile(t, directory, ".gitage.key", identity.String()+"\n")
			}
			first := encryptFixture(t, identity.Recipient(), "first", false)
			second := encryptFixture(t, identity.Recipient(), "second", false)
			if failure == "wrong key" {
				other := newIdentity(t)
				second = encryptFixture(t, other.Recipient(), "second", false)
			}
			if failure == "corrupt ciphertext" {
				second[len(second)-1] ^= 1
			}
			writeFile(t, directory, "a.env", string(first))
			writeFile(t, directory, "b.env", string(second))
			_, err := runCommand(directory, "unlock")
			if err == nil {
				t.Fatal("expected decryption error")
			}
			if failure == "missing key" && err.Error() != "no identity configured; use -i or generate a key with git-age keygen" {
				t.Fatalf("missing identity guidance: %v", err)
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
	writeFile(t, directory, ".gitage", "[files]\n*.env\n")
	writeFile(t, directory, "a.env", "age-encryption.org/v1\n")
	output, err := runCommand(directory, "unlock", "-n")
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
	identity := newIdentity(t)
	writeFile(t, directory, ".gitage", "[files]\n*.env\n")
	writeFile(t, directory, ".gitage.key", identity.String()+"\n")
	writeFile(t, directory, "sub/a.env", string(encryptFixture(t, identity.Recipient(), "secret", false)))
	if _, err := runCommand(filepath.Join(directory, "sub"), "unlock", "a.env"); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(filepath.Join(directory, "sub/a.env")); string(after) != "secret" {
		t.Fatal("subdirectory key discovery failed")
	}
}

func TestUnlockAlreadyPlaintextNeedsNoKey(t *testing.T) {
	directory := t.TempDir()
	writeFile(t, directory, ".gitage", "[files]\n*.env\n")
	writeFile(t, directory, "a.env", "plaintext")
	output, err := runCommand(directory, "unlock", "-v", "-i", "missing.key")
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
	identity := newIdentity(t)
	writeFile(t, directory, ".gitage", "[files]\n*.env\n")
	writeFile(t, directory, ".gitage.key", identity.String()+"\n")
	writeFile(t, directory, "a.env", "secret")
	if _, err := runCommand(directory, "lock"); err != nil {
		t.Fatal(err)
	}
	if _, err := runCommand(directory, "unlock"); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(directory, "a.env"))
	if err != nil || string(content) != "secret" {
		t.Fatalf("round trip: %q, %v", content, err)
	}
}
