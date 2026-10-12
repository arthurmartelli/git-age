package cli

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func TestLegacyReuseRecordsRecipients(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		name := "explicit recipients"
		if implicit {
			name = "implicit original owner"
		}
		t.Run(name, func(t *testing.T) {
			isolateHookEnvironment(t)
			plaintext := []byte("original\n")
			directory, owner, _ := cleanFixture(t, plaintext, false)
			teammate := newIdentity(t)
			rules := "[files]\n*.env\n"
			if implicit {
				writeFile(t, directory, "sub/.gitage", "[recipients]\n"+teammate.Recipient().String()+"\n")
			} else {
				rules += "[recipients]\n" + owner.Recipient().String() + "\n" + teammate.Recipient().String() + "\n"
			}
			writeFile(t, directory, ".gitage", rules)
			var ciphertext bytes.Buffer
			writer, err := age.Encrypt(&ciphertext, owner.Recipient(), teammate.Recipient())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(plaintext); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			writeFile(t, directory, "sub/shared.env", ciphertext.String())
			runGit(t, directory, "add", ".gitage", "sub")
			runGit(t, directory, "commit", "-qm", "legacy team ciphertext")
			writeFile(t, directory, ".gitage.key", teammate.String()+"\n")
			mustCommand(t, directory, "unlock", "sub/shared.env")
			before := installSnapshot(t, directory)
			mustCommand(t, directory, "lock", "-n", "sub/shared.env")
			assertSnapshotUnchanged(t, directory, before)
			mustCommand(t, directory, "lock", "sub/shared.env")
			if !bytes.Equal(ciphertext.Bytes(), readFile(t, directory, "sub/shared.env")) {
				t.Fatal("legacy ciphertext was not reused")
			}
			path := recipientCachePath(t, directory, ciphertext.Bytes())
			record, err := os.ReadFile(path)
			if err != nil || len(record) == 0 || (record[0] == '\n') != implicit {
				t.Fatalf("unexpected legacy recipient record: %q, %v", record, err)
			}
			mustCommand(t, directory, "unlock", "sub/shared.env")
			mustCommand(t, directory, "lock", "sub/shared.env")
			if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, record) {
				t.Fatalf("reuse changed the original provenance: %q, %v", got, err)
			}
			// The original owner must not survive an explicit narrowing to the teammate.
			mustCommand(t, directory, "unlock", "sub/shared.env")
			mustCommand(t, directory, "lock", "-r", teammate.Recipient().String(), "sub/shared.env")
			fresh := readFile(t, directory, "sub/shared.env")
			assertDecrypts(t, fresh, teammate, plaintext)
			assertCannotDecrypt(t, fresh, owner)
		})
	}
}

func recipientCachePath(t *testing.T, directory string, ciphertext []byte) string {
	t.Helper()
	return filepath.Join(installGitPath(t, directory, "git-age/recipients"), fmt.Sprintf("%x", sha256.Sum256(ciphertext)))
}

func expireRecipientRecord(t *testing.T, path string) {
	t.Helper()
	old := time.Now().Add(-31 * 24 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
}

func TestEncryptionPrunesRecipientCache(t *testing.T) {
	isolateHookEnvironment(t)
	directory, identity, _ := cleanFixture(t, []byte("original\n"), false)
	flags := []string{"-r", identity.Recipient().String()}
	paths := map[string]string{}
	for _, name := range []string{"working", "expired", "recent"} {
		writeFile(t, directory, name+".env", "secret\n")
		mustCommand(t, directory, "lock", append(flags, name+".env")...)
		paths[name] = recipientCachePath(t, directory, readFile(t, directory, name+".env"))
		if name != "working" {
			if err := os.Remove(filepath.Join(directory, name+".env")); err != nil {
				t.Fatal(err)
			}
		}
	}
	expireRecipientRecord(t, paths["working"])
	expireRecipientRecord(t, paths["expired"])
	working := readFile(t, directory, "working.env")
	writeFile(t, directory, "new.env", "new secret\n")
	before := installSnapshot(t, directory)
	mustCommand(t, directory, "lock", append([]string{"-n"}, append(flags, "new.env")...)...)
	assertSnapshotUnchanged(t, directory, before)
	mustCommand(t, directory, "lock", append(flags, "new.env")...)
	for name, path := range paths {
		_, err := os.Stat(path)
		if name == "expired" {
			if !os.IsNotExist(err) {
				t.Fatalf("encryption did not prune expired orphan: %v", err)
			}
		} else if err != nil {
			t.Fatalf("lost %s recipient record: %v", name, err)
		}
	}
	runGit(t, directory, "add", "working.env")
	mustCommand(t, directory, "unlock", "working.env")
	mustCommand(t, directory, "lock", append(flags, "working.env")...)
	if !bytes.Equal(working, readFile(t, directory, "working.env")) {
		t.Fatal("pruning discarded the unstaged ciphertext's reuse record")
	}
}

func TestUninstallRecipientCacheWithoutIntegration(t *testing.T) {
	for _, scenario := range []string{"directory", "symlink"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			cache := installGitPath(t, directory, "git-age/recipients")
			writeFile(t, filepath.Dir(cache), "keep", "other metadata")
			target := t.TempDir()
			writeFile(t, target, "keep", "external data")
			if scenario == "symlink" {
				if err := os.Symlink(target, cache); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			} else {
				writeFile(t, cache, "fingerprint", "cache record")
			}
			before := installSnapshot(t, directory)
			output := mustCommand(t, directory, "uninstall", "-n")
			if !strings.Contains(output, "would remove ciphertext recipient cache: "+cache) {
				t.Fatalf("cache removal missing from dry run: %s", output)
			}
			assertSnapshotUnchanged(t, directory, before)
			mustCommand(t, directory, "uninstall")
			if _, err := os.Lstat(cache); !os.IsNotExist(err) {
				t.Fatalf("cache remains after uninstall: %v", err)
			}
			if string(readFile(t, filepath.Dir(cache), "keep")) != "other metadata" || string(readFile(t, target, "keep")) != "external data" {
				t.Fatal("uninstall removed unrelated files")
			}
		})
	}
}

func TestRecipientCacheGraceAcrossBranchAndStash(t *testing.T) {
	for _, scenario := range []string{"branch", "stash"} {
		t.Run(scenario, func(t *testing.T) {
			isolateHookEnvironment(t)
			directory, identity, _ := cleanFixture(t, []byte("original\n"), false)
			flags := []string{"-r", identity.Recipient().String()}
			name := "secret.env"
			if scenario == "branch" {
				runGit(t, directory, "branch", "before")
				runGit(t, directory, "checkout", "-qb", "secrets")
				name = "branch.env"
				writeFile(t, directory, name, "branch secret\n")
			}
			mustCommand(t, directory, "rekey", append(flags, name)...)
			ciphertext := readFile(t, directory, name)
			record := recipientCachePath(t, directory, ciphertext)
			if scenario == "branch" {
				runGit(t, directory, "add", name)
				runGit(t, directory, "commit", "-qm", "branch secret")
				runGit(t, directory, "checkout", "-q", "before")
			} else {
				runGit(t, directory, "stash", "push", "-qm", "secret", "--", name)
			}
			// An expired orphan forces a retention scan while the record is
			// reachable only on the other branch or in the stash.
			orphan := recipientCachePath(t, directory, []byte("orphan"))
			writeFile(t, filepath.Dir(orphan), filepath.Base(orphan), "fingerprint")
			expireRecipientRecord(t, orphan)
			writeFile(t, directory, "new.env", "new secret\n")
			mustCommand(t, directory, "lock", append(flags, "new.env")...)
			if _, err := os.Stat(record); err != nil {
				t.Fatalf("lost recent %s ciphertext record: %v", scenario, err)
			}
			if scenario == "branch" {
				runGit(t, directory, "checkout", "-q", "secrets")
			} else {
				runGit(t, directory, "stash", "pop", "-q")
			}
			runGit(t, directory, "add", name)
			mustCommand(t, directory, "unlock", name)
			mustCommand(t, directory, "lock", append(flags, name)...)
			if !bytes.Equal(ciphertext, readFile(t, directory, name)) {
				t.Fatalf("%s ciphertext was not reusable after pruning", scenario)
			}
		})
	}
}
