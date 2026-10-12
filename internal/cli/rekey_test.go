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
)

func TestRekeyRecipientSources(t *testing.T) {
	for _, source := range []string{"rules", "flag", "environment", "Git config", "own key"} {
		t.Run(source, func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			t.Setenv("GIT_AGE_RECIPIENT", "")
			t.Setenv("GIT_AGE_KEY_FILE", "")
			old := newIdentity(t)
			current := newIdentity(t)
			writeFile(t, directory, ".gitage.key", old.String()+"\n")
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
			writeFile(t, directory, ".gitage", rules)
			for _, armored := range []bool{false, true} {
				before := encryptFixture(t, old.Recipient(), "secret\x00bytes\n", armored)
				writeFile(t, directory, "a.env", string(before))
				writeFile(t, directory, "b.env", "plaintext")
				writeFile(t, directory, "public.txt", "untouched")
				output, err := runCommand(directory, "rekey", args...)
				if err != nil || output != "git-age: Re-encrypted 2 files.\n" {
					t.Fatalf("rekey: %q, %v", output, err)
				}
				after := readFile(t, directory, "a.env")
				if bytes.Equal(before, after) {
					t.Fatal("rekey reused ciphertext")
				}
				assertDecrypts(t, after, current, []byte("secret\x00bytes\n"))
				assertDecrypts(t, readFile(t, directory, "b.env"), current, []byte("plaintext"))
				if source != "own key" {
					if _, err := age.Decrypt(bytes.NewReader(after), old); err == nil {
						t.Fatal("removed recipient can still decrypt")
					}
				}
				if string(readFile(t, directory, "public.txt")) != "untouched" {
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
			old, current := newIdentity(t), newIdentity(t)
			writeFile(t, directory, "old.key", old.String()+"\n")
			writeFile(t, directory, ".gitage.key", current.String()+"\n")
			writeFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+current.Recipient().String()+"\n")
			writeFile(t, directory, "a.env", string(encryptFixture(t, old.Recipient(), "secret", false)))
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
			if _, err := runCommand(directory, "rekey", args...); err != nil {
				t.Fatal(err)
			}
			assertDecrypts(t, readFile(t, directory, "a.env"), current, []byte("secret"))
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
			old, current, nested := newIdentity(t), newIdentity(t), newIdentity(t)
			writeFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+current.Recipient().String()+"\n")
			writeFile(t, directory, ".gitage.key", old.String()+"\n")
			writeFile(t, directory, "sub/.gitage", "[recipients]\n"+nested.Recipient().String()+"\n")
			before := encryptFixture(t, old.Recipient(), "secret", false)
			for _, path := range []string{"top.env", "sub/a.env", "sub/deep/b.env"} {
				writeFile(t, directory, path, string(before))
			}
			if aliased {
				alias := filepath.Join(t.TempDir(), "repository")
				if err := os.Symlink(directory, alias); err != nil {
					t.Skipf("directory symlinks unavailable: %v", err)
				}
				directory = alias
			}
			output, err := runCommand(filepath.Join(directory, "sub"), "rekey", "-v", "deep", "deep/b.env")
			if err != nil || output != "rekeying: deep/b.env\ngit-age: Re-encrypted 1 file.\n" {
				t.Fatalf("rekey subdirectory: %q, %v", output, err)
			}
			after := readFile(t, directory, "sub/deep/b.env")
			for _, identity := range []*age.X25519Identity{current, nested} {
				assertDecrypts(t, after, identity, []byte("secret"))
			}
			for _, path := range []string{"top.env", "sub/a.env"} {
				if !bytes.Equal(before, readFile(t, directory, path)) {
					t.Fatalf("unselected file changed: %s", path)
				}
			}
			if _, err := runCommand(directory, "rekey", "sub", "missing.env"); err == nil {
				t.Fatal("expected missing path error")
			}
			if !bytes.Equal(after, readFile(t, directory, "sub/deep/b.env")) {
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
			identity := newIdentity(t)
			writeFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+identity.Recipient().String()+"\n")
			if failure != "missing key" {
				writeFile(t, directory, ".gitage.key", identity.String()+"\n")
			}
			second := encryptFixture(t, identity.Recipient(), "secret", false)
			switch failure {
			case "wrong key":
				second = encryptFixture(t, newIdentity(t).Recipient(), "secret", false)
			case "corrupt ciphertext":
				second[len(second)-1] ^= 1
			case "invalid header":
				second = []byte("age-encryption.org/v1\ninvalid\n")
			case "invalid recipient":
				writeFile(t, directory, "sub/.gitage", "[recipients]\nage1invalid\n")
			case "trusted recipients":
				if err := exec.Command("git", "-C", directory, "config", "age.trustedRecipients", "pinned").Run(); err != nil {
					t.Fatal(err)
				}
			}
			originals := map[string][]byte{
				"a.env":     []byte("plaintext"),
				"b.env":     second,
				"sub/c.env": encryptFixture(t, identity.Recipient(), "third", false),
			}
			for path, content := range originals {
				writeFile(t, directory, path, string(content))
			}
			output, err := runCommand(directory, "rekey", "-v")
			if err == nil || output != "" {
				t.Fatalf("expected failure without success output: %q, %v", output, err)
			}
			if failure == "missing key" && err.Error() != "no identity configured; use -i or generate a key with git-age keygen" {
				t.Fatalf("missing identity guidance: %v", err)
			}
			for path, before := range originals {
				if !bytes.Equal(before, readFile(t, directory, path)) {
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
	alice, carol, dave := newIdentity(t), newIdentity(t), newIdentity(t)
	writeFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+alice.Recipient().String()+"\n")
	writeFile(t, directory, "prod/.gitage", "[recipients]\n"+carol.Recipient().String()+"\n"+dave.Recipient().String()+"\n")
	writeFile(t, directory, ".gitage.key", carol.String()+"\n")
	app := encryptFixture(t, alice.Recipient(), "app", false)
	writeFile(t, directory, "app.env", string(app))
	writeFile(t, directory, "prod/db.env", string(encryptFixture(t, carol.Recipient(), "db", false)))
	before := installSnapshot(t, directory)
	output, err := runCommand(directory, "rekey", "-n")
	if err != nil || output != "git-age: Would re-encrypt 1 file; skipped 1 without access.\n" {
		t.Fatalf("limited-access dry run: %q, %v", output, err)
	}
	assertSnapshotUnchanged(t, directory, before)
	output, err = runCommand(directory, "rekey", "-n", "-v")
	if err != nil || !strings.Contains(output, "skipped, not encrypted to you: app.env\n") || strings.Contains(output, "would rekey: app.env") || !strings.Contains(output, "would rekey: prod/db.env\n") {
		t.Fatalf("verbose limited-access dry run: %q, %v", output, err)
	}
	assertSnapshotUnchanged(t, directory, before)
	output, err = runCommand(directory, "rekey", "-v")
	if err != nil || !strings.Contains(output, "skipped, not encrypted to you: app.env") || !strings.Contains(output, "rekeying: prod/db.env") || strings.Contains(output, "rekeying: app.env") {
		t.Fatalf("limited access: %q, %v", output, err)
	}
	if !bytes.Equal(app, readFile(t, directory, "app.env")) {
		t.Fatal("inaccessible file changed")
	}
	for _, identity := range []*age.X25519Identity{alice, carol, dave} {
		assertDecrypts(t, readFile(t, directory, "prod/db.env"), identity, []byte("db"))
	}
	// Loss of expected access may indicate tampering, so it must stop the batch.
	writeFile(t, directory, "prod/db.env", string(encryptFixture(t, alice.Recipient(), "tampered", false)))
	writeFile(t, directory, "a.env", "plaintext")
	before = installSnapshot(t, directory)
	if output, err := runCommand(directory, "rekey", "-n"); err == nil || !strings.Contains(err.Error(), "cannot decrypt prod/db.env") || output != "" {
		t.Fatalf("dry run missed decryption failure: %q, %v", output, err)
	}
	assertSnapshotUnchanged(t, directory, before)
	if _, err := runCommand(directory, "rekey"); err == nil || !strings.Contains(err.Error(), "cannot decrypt prod/db.env") {
		t.Fatalf("expected decryption error: %v", err)
	}
	if string(readFile(t, directory, "a.env")) != "plaintext" {
		t.Fatal("plaintext changed on decryption failure")
	}
	if _, err := runCommand(directory, "rekey", "app.env"); err == nil {
		t.Fatal("expected error when no selected file can be decrypted")
	}
}

func TestRekeyDryRun(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_AGE_KEY_FILE", "")
	t.Setenv("GIT_AGE_RECIPIENT", "")
	identity := newIdentity(t)
	writeFile(t, directory, ".gitage", "[files]\n*.env\n")
	writeFile(t, directory, ".gitage.key", identity.String()+"\n")
	writeFile(t, directory, "a.env", "plaintext")
	writeFile(t, directory, "b.env", string(encryptFixture(t, identity.Recipient(), "secret", false)))
	before := installSnapshot(t, directory)
	output, err := runCommand(directory, "rekey", "-n")
	if err != nil || output != "git-age: Would re-encrypt 2 files.\n" {
		t.Fatalf("dry run: %q, %v", output, err)
	}
	assertSnapshotUnchanged(t, directory, before)
	if output, err := runCommand(directory, "rekey", "-n", "-i", "missing.key"); err == nil || output != "" {
		t.Fatalf("missing identity: %q, %v", output, err)
	}
	assertSnapshotUnchanged(t, directory, before)
}

func TestRekeyOutsideGit(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_AGE_KEY_FILE", "")
	t.Setenv("GIT_AGE_RECIPIENT", "")
	identity := newIdentity(t)
	writeFile(t, directory, ".gitage", "[files]\n*.env\n")
	writeFile(t, directory, ".gitage.key", identity.String()+"\n")
	writeFile(t, directory, "a.env", "secret")
	for range 2 {
		if _, err := runCommand(directory, "rekey"); err != nil {
			t.Fatal(err)
		}
		assertDecrypts(t, readFile(t, directory, "a.env"), identity, []byte("secret"))
	}
}

func TestRekeyNeverReusesGitCiphertext(t *testing.T) {
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	t.Setenv("GIT_AGE_KEY_FILE", "")
	t.Setenv("GIT_AGE_RECIPIENT", "")
	identity := newIdentity(t)
	writeFile(t, directory, ".gitage", "[files]\n*.env\n")
	writeFile(t, directory, ".gitage.key", identity.String()+"\n")
	writeFile(t, directory, "a.env", "secret")
	if _, err := runCommand(directory, "lock"); err != nil {
		t.Fatal(err)
	}
	before := readFile(t, directory, "a.env")
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
			writeFile(t, directory, "a.env", "secret")
		}
		if _, err := runCommand(directory, "rekey"); err != nil {
			t.Fatal(err)
		}
		after := readFile(t, directory, "a.env")
		if bytes.Equal(before, after) {
			t.Fatalf("rekey reused Git ciphertext, plaintext=%v", plaintext)
		}
		assertDecrypts(t, after, identity, []byte("secret"))
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
	identity := newIdentity(t)
	writeFile(t, directory, ".gitage", "[files]\n*.env\n")
	if output, err := runCommand(directory, "rekey", "-i", "missing.key"); err != nil || output != "git-age: Re-encrypted 0 files.\n" {
		t.Fatalf("no protected files: %q, %v", output, err)
	}
	writeFile(t, directory, "a.env", "plaintext")
	if _, err := runCommand(directory, "rekey", "-r", identity.Recipient().String()); err != nil {
		t.Fatal(err)
	}
	assertDecrypts(t, readFile(t, directory, "a.env"), identity, []byte("plaintext"))
}
