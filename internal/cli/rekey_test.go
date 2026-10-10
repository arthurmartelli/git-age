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

func TestRekeyRecipientSources(t *testing.T) {
	for _, source := range []string{"rules", "flag", "environment", "Git config", "own key"} {
		t.Run(source, func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			t.Setenv("GIT_AGE_RECIPIENT", "")
			t.Setenv("GIT_AGE_KEY_FILE", "")
			old := rekeyIdentity(t)
			current := rekeyIdentity(t)
			writeStatusFile(t, directory, ".gitage.key", old.String()+"\n")
			rules := "[files]\n*.env\n"
			var args []string
			switch source {
			case "rules":
				rules += "[recipients]\n" + current.Recipient().String() + "\n"
			case "flag":
				rules += "[recipients]\n" + old.Recipient().String() + "\n"
				args = []string{"-r", current.Recipient().String()}
			case "environment":
				rules += "[recipients]\n" + old.Recipient().String() + "\n"
				t.Setenv("GIT_AGE_RECIPIENT", current.Recipient().String())
			case "Git config":
				if err := exec.Command("git", "-C", directory, "config", "age.recipient", current.Recipient().String()).Run(); err != nil {
					t.Fatal(err)
				}
			case "own key":
				current = old
			}
			writeStatusFile(t, directory, ".gitage", rules)
			for _, armored := range []bool{false, true} {
				before := encryptUnlockFixture(t, old, "secret\x00bytes\n", armored)
				writeStatusFile(t, directory, "a.env", string(before))
				writeStatusFile(t, directory, "b.env", "plaintext")
				writeStatusFile(t, directory, "public.txt", "untouched")
				output, err := runRekey(directory, args...)
				if err != nil || output != "" {
					t.Fatalf("rekey: %q, %v", output, err)
				}
				after := readRekeyFile(t, directory, "a.env")
				if bytes.Equal(before, after) {
					t.Fatal("rekey reused ciphertext")
				}
				assertRekeyPlaintext(t, after, current, "secret\x00bytes\n")
				assertRekeyPlaintext(t, readRekeyFile(t, directory, "b.env"), current, "plaintext")
				if source != "own key" {
					if _, err := age.Decrypt(bytes.NewReader(after), old); err == nil {
						t.Fatal("removed recipient can still decrypt")
					}
				}
				if string(readRekeyFile(t, directory, "public.txt")) != "untouched" {
					t.Fatal("unprotected file changed")
				}
				info, err := os.Stat(filepath.Join(directory, "a.env"))
				if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
					t.Fatalf("permissions: %v, %v", info, err)
				}
			}
		})
	}
}

func TestRekeyIdentitySources(t *testing.T) {
	for _, source := range []string{"flag", "environment", "Git config"} {
		t.Run(source, func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			t.Setenv("GIT_AGE_KEY_FILE", "")
			t.Setenv("GIT_AGE_RECIPIENT", "")
			old, current := rekeyIdentity(t), rekeyIdentity(t)
			writeStatusFile(t, directory, "old.key", old.String()+"\n")
			writeStatusFile(t, directory, ".gitage.key", current.String()+"\n")
			writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+current.Recipient().String()+"\n")
			writeStatusFile(t, directory, "a.env", string(encryptUnlockFixture(t, old, "secret", false)))
			var args []string
			switch source {
			case "flag":
				args = []string{"-i", "old.key"}
			case "environment":
				t.Setenv("GIT_AGE_KEY_FILE", filepath.Join(directory, "old.key"))
			case "Git config":
				if err := exec.Command("git", "-C", directory, "config", "age.keyFile", "old.key").Run(); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := runRekey(directory, args...); err != nil {
				t.Fatal(err)
			}
			assertRekeyPlaintext(t, readRekeyFile(t, directory, "a.env"), current, "secret")
		})
	}
}

func TestRekeyPathsAndNestedRecipients(t *testing.T) {
	for _, aliased := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "directory alias"}[aliased], func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			t.Setenv("GIT_AGE_RECIPIENT", "")
			t.Setenv("GIT_AGE_KEY_FILE", "")
			old, current, nested := rekeyIdentity(t), rekeyIdentity(t), rekeyIdentity(t)
			writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+current.Recipient().String()+"\n")
			writeStatusFile(t, directory, ".gitage.key", old.String()+"\n")
			writeStatusFile(t, directory, "sub/.gitage", "[recipients]\n"+nested.Recipient().String()+"\n")
			before := encryptUnlockFixture(t, old, "secret", false)
			for _, path := range []string{"top.env", "sub/a.env", "sub/deep/b.env"} {
				writeStatusFile(t, directory, path, string(before))
			}
			if aliased {
				alias := filepath.Join(t.TempDir(), "repository")
				if err := os.Symlink(directory, alias); err != nil {
					t.Skipf("directory symlinks unavailable: %v", err)
				}
				directory = alias
			}
			output, err := runRekey(filepath.Join(directory, "sub"), "-v", "deep", "deep/b.env")
			if err != nil || output != "rekeying: deep/b.env\n" {
				t.Fatalf("rekey subdirectory: %q, %v", output, err)
			}
			after := readRekeyFile(t, directory, "sub/deep/b.env")
			for _, identity := range []*age.X25519Identity{current, nested} {
				assertRekeyPlaintext(t, after, identity, "secret")
			}
			for _, path := range []string{"top.env", "sub/a.env"} {
				if !bytes.Equal(before, readRekeyFile(t, directory, path)) {
					t.Fatalf("unselected file changed: %s", path)
				}
			}
			if _, err := runRekey(directory, "sub", "missing.env"); err == nil {
				t.Fatal("expected missing path error")
			}
			if !bytes.Equal(after, readRekeyFile(t, directory, "sub/deep/b.env")) {
				t.Fatal("file changed on path error")
			}
		})
	}
}

func TestRekeyFailureChangesNothing(t *testing.T) {
	for _, failure := range []string{"wrong key", "corrupt ciphertext", "invalid header", "missing key", "invalid recipient", "trusted recipients"} {
		t.Run(failure, func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			t.Setenv("GIT_AGE_KEY_FILE", "")
			t.Setenv("GIT_AGE_RECIPIENT", "")
			identity := rekeyIdentity(t)
			writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+identity.Recipient().String()+"\n")
			if failure != "missing key" {
				writeStatusFile(t, directory, ".gitage.key", identity.String()+"\n")
			}
			second := encryptUnlockFixture(t, identity, "secret", false)
			switch failure {
			case "wrong key":
				second = encryptUnlockFixture(t, rekeyIdentity(t), "secret", false)
			case "corrupt ciphertext":
				second[len(second)-1] ^= 1
			case "invalid header":
				second = []byte("age-encryption.org/v1\ninvalid\n")
			case "invalid recipient":
				writeStatusFile(t, directory, "sub/.gitage", "[recipients]\nage1invalid\n")
			case "trusted recipients":
				if err := exec.Command("git", "-C", directory, "config", "age.trustedRecipients", "pinned").Run(); err != nil {
					t.Fatal(err)
				}
			}
			originals := map[string][]byte{
				"a.env":     []byte("plaintext"),
				"b.env":     second,
				"sub/c.env": encryptUnlockFixture(t, identity, "third", false),
			}
			for path, content := range originals {
				writeStatusFile(t, directory, path, string(content))
			}
			output, err := runRekey(directory, "-v")
			if err == nil || output != "" {
				t.Fatalf("expected failure without success output: %q, %v", output, err)
			}
			for path, before := range originals {
				if !bytes.Equal(before, readRekeyFile(t, directory, path)) {
					t.Errorf("%s changed after failure", path)
				}
			}
		})
	}
}

func TestRekeyLimitedAccess(t *testing.T) {
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	t.Setenv("GIT_AGE_KEY_FILE", "")
	t.Setenv("GIT_AGE_RECIPIENT", "")
	alice, carol, dave := rekeyIdentity(t), rekeyIdentity(t), rekeyIdentity(t)
	writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+alice.Recipient().String()+"\n")
	writeStatusFile(t, directory, "prod/.gitage", "[recipients]\n"+carol.Recipient().String()+"\n"+dave.Recipient().String()+"\n")
	writeStatusFile(t, directory, ".gitage.key", carol.String()+"\n")
	app := encryptUnlockFixture(t, alice, "app", false)
	writeStatusFile(t, directory, "app.env", string(app))
	writeStatusFile(t, directory, "prod/db.env", string(encryptUnlockFixture(t, carol, "db", false)))
	output, err := runRekey(directory, "-v")
	if err != nil || !strings.Contains(output, "skipping app.env: not encrypted to you") || !strings.Contains(output, "rekeying: prod/db.env") || strings.Contains(output, "rekeying: app.env") {
		t.Fatalf("limited access: %q, %v", output, err)
	}
	if !bytes.Equal(app, readRekeyFile(t, directory, "app.env")) {
		t.Fatal("inaccessible file changed")
	}
	for _, identity := range []*age.X25519Identity{alice, carol, dave} {
		assertRekeyPlaintext(t, readRekeyFile(t, directory, "prod/db.env"), identity, "db")
	}
	// Loss of expected access may indicate tampering, so it must stop the batch.
	writeStatusFile(t, directory, "prod/db.env", string(encryptUnlockFixture(t, alice, "tampered", false)))
	writeStatusFile(t, directory, "a.env", "plaintext")
	if _, err := runRekey(directory); err == nil || !strings.Contains(err.Error(), "cannot decrypt prod/db.env") {
		t.Fatalf("expected decryption error: %v", err)
	}
	if string(readRekeyFile(t, directory, "a.env")) != "plaintext" {
		t.Fatal("plaintext changed on decryption failure")
	}
	if _, err := runRekey(directory, "app.env"); err == nil {
		t.Fatal("expected error when no selected file can be decrypted")
	}
}

func TestRekeyDryRun(t *testing.T) {
	directory := t.TempDir()
	writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n")
	originals := map[string]string{"a.env": "plaintext", "b.env": "age-encryption.org/v1\n"}
	for path, content := range originals {
		writeStatusFile(t, directory, path, content)
	}
	output, err := runRekey(directory, "-n", "-i", "missing.key")
	if err != nil || output != "would rekey: a.env\nwould rekey: b.env\n" {
		t.Fatalf("dry run: %q, %v", output, err)
	}
	for path, before := range originals {
		if string(readRekeyFile(t, directory, path)) != before {
			t.Fatalf("dry run changed %s", path)
		}
	}
}

func TestRekeyOutsideGit(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_AGE_KEY_FILE", "")
	t.Setenv("GIT_AGE_RECIPIENT", "")
	identity := rekeyIdentity(t)
	writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n")
	writeStatusFile(t, directory, ".gitage.key", identity.String()+"\n")
	writeStatusFile(t, directory, "a.env", "secret")
	for range 2 {
		if _, err := runRekey(directory); err != nil {
			t.Fatal(err)
		}
		assertRekeyPlaintext(t, readRekeyFile(t, directory, "a.env"), identity, "secret")
	}
}

func TestRekeyNeverReusesGitCiphertext(t *testing.T) {
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	t.Setenv("GIT_AGE_KEY_FILE", "")
	t.Setenv("GIT_AGE_RECIPIENT", "")
	identity := rekeyIdentity(t)
	writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n")
	writeStatusFile(t, directory, ".gitage.key", identity.String()+"\n")
	writeStatusFile(t, directory, "a.env", "secret")
	if _, err := runLock(directory); err != nil {
		t.Fatal(err)
	}
	before := readRekeyFile(t, directory, "a.env")
	for _, args := range [][]string{
		{"add", ".gitage", "a.env"},
		{"-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", "commit", "-qm", "encrypted"},
	} {
		if output, err := exec.Command("git", append([]string{"-C", directory}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git: %v: %s", err, output)
		}
	}
	for _, plaintext := range []bool{false, true} {
		if plaintext {
			writeStatusFile(t, directory, "a.env", "secret")
		}
		if _, err := runRekey(directory); err != nil {
			t.Fatal(err)
		}
		after := readRekeyFile(t, directory, "a.env")
		if bytes.Equal(before, after) {
			t.Fatalf("rekey reused Git ciphertext, plaintext=%v", plaintext)
		}
		assertRekeyPlaintext(t, after, identity, "secret")
		index, err := exec.Command("git", "-C", directory, "show", ":a.env").Output()
		if err != nil || !bytes.Equal(before, index) {
			t.Fatalf("index changed: %v", err)
		}
	}
}

func TestRekeyPlaintextNeedsNoIdentity(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_AGE_KEY_FILE", "")
	t.Setenv("GIT_AGE_RECIPIENT", "")
	identity := rekeyIdentity(t)
	writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n")
	if output, err := runRekey(directory, "-i", "missing.key"); err != nil || output != "" {
		t.Fatalf("no protected files: %q, %v", output, err)
	}
	writeStatusFile(t, directory, "a.env", "plaintext")
	if _, err := runRekey(directory, "-r", identity.Recipient().String()); err != nil {
		t.Fatal(err)
	}
	assertRekeyPlaintext(t, readRekeyFile(t, directory, "a.env"), identity, "plaintext")
}

func runRekey(directory string, args ...string) (string, error) {
	var output bytes.Buffer
	root := newRootCommand()
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs(append([]string{"-C", directory, "rekey"}, args...))
	err := root.Execute()
	return output.String(), err
}

func rekeyIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func readRekeyFile(t *testing.T, directory, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(directory, path))
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func assertRekeyPlaintext(t *testing.T, content []byte, identity age.Identity, want string) {
	t.Helper()
	reader, err := age.Decrypt(bytes.NewReader(content), identity)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := io.ReadAll(reader)
	if err != nil || string(plaintext) != want {
		t.Fatalf("decrypted: %q, %v; want %q", plaintext, err, want)
	}
}
