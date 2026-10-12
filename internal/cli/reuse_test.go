package cli

import (
	"bytes"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestExternalRecipientReuse(t *testing.T) {
	buildGitAge(t)
	for _, source := range []string{"flag", "environment", "config"} {
		t.Run(source, func(t *testing.T) {
			isolateHookEnvironment(t)
			plaintext := []byte("original\n")
			directory, identity, _ := cleanFixture(t, plaintext, false)
			setRecipient := func(recipient string) []string {
				switch source {
				case "flag":
					return []string{"-r", recipient}
				case "environment":
					t.Setenv("GIT_AGE_RECIPIENT", recipient)
				case "config":
					runGit(t, directory, "config", "age.recipient", recipient)
					// Configuration is used only when the root list is absent.
					writeFile(t, directory, ".gitage", "[files]\n*.env\n")
				}
				return nil
			}
			args := setRecipient(identity.Recipient().String())
			writeFile(t, directory, "secret.env", string(plaintext))
			before := installSnapshot(t, directory)
			mustCommand(t, directory, "lock", append([]string{"-n"}, args...)...)
			assertSnapshotUnchanged(t, directory, before)
			mustCommand(t, directory, "lock", args...)
			ciphertext := readFile(t, directory, "secret.env")
			runGit(t, directory, "add", ".gitage", "secret.env")
			// An index-only candidate must work before its first commit.
			writeFile(t, directory, "secret.env", string(plaintext))
			mustCommand(t, directory, "lock", args...)
			if !bytes.Equal(ciphertext, readFile(t, directory, "secret.env")) {
				t.Fatal("did not reuse indexed ciphertext for external recipients")
			}
			runGit(t, directory, "commit", "-qm", "external recipients")
			mustCommand(t, directory, "install", "--hook-mode=always-lock")
			mustCommand(t, directory, "unlock")
			if status := string(runGit(t, directory, "status", "--porcelain", "--", "secret.env")); status != "" {
				t.Fatalf("unchanged plaintext appears modified: %q", status)
			}
			writeFile(t, directory, "note.txt", "unrelated\n")
			runGit(t, directory, "add", "note.txt")
			runGit(t, directory, "commit", "-qm", "unrelated change")
			if !bytes.Equal(ciphertext, runGit(t, directory, "show", "HEAD:secret.env")) {
				t.Fatal("unrelated commit re-encrypted ciphertext")
			}
			// Force plaintext into the index to exercise pre-commit encryption.
			oid := strings.TrimSpace(string(runGit(t, directory, "hash-object", "-w", "--no-filters", "secret.env")))
			runGit(t, directory, "update-index", "--cacheinfo", "100644,"+oid+",secret.env")
			writeFile(t, directory, "note.txt", "another unrelated change\n")
			runGit(t, directory, "add", "note.txt")
			runGit(t, directory, "commit", "-qm", "reuse in pre-commit")
			if !bytes.Equal(ciphertext, runGit(t, directory, "show", "HEAD:secret.env")) {
				t.Fatal("pre-commit did not reuse ciphertext")
			}
			writeFile(t, directory, "secret.env", string(plaintext))
			mustCommand(t, directory, "lock", append([]string{"--no-reuse"}, args...)...)
			if bytes.Equal(ciphertext, readFile(t, directory, "secret.env")) {
				t.Fatal("--no-reuse reused ciphertext")
			}
			changed := newIdentity(t)
			args = setRecipient(changed.Recipient().String())
			writeFile(t, directory, "secret.env", string(plaintext))
			if source != "flag" {
				cleaned, _, err := runClean(directory, "secret.env", plaintext)
				if err != nil || !bytes.Equal(cleaned, plaintext) {
					t.Fatalf("clean reused ciphertext after recipient change: %v", err)
				}
			}
			mustCommand(t, directory, "lock", args...)
			fresh := readFile(t, directory, "secret.env")
			assertDecrypts(t, fresh, changed, plaintext)
			assertCannotDecrypt(t, fresh, identity)
		})
	}
}

func TestExternalRecipientsIncludeNestedLists(t *testing.T) {
	for _, source := range []string{"flag", "environment", "config"} {
		t.Run(source, func(t *testing.T) {
			isolateHookEnvironment(t)
			directory, identity, _ := cleanFixture(t, []byte("original\n"), false)
			runGit(t, directory, "mv", "secret.env", "sub/secret.env")
			var args []string
			switch source {
			case "flag":
				args = []string{"-r", identity.Recipient().String()}
			case "environment":
				t.Setenv("GIT_AGE_RECIPIENT", identity.Recipient().String())
			case "config":
				writeFile(t, directory, ".gitage", "[files]\n*.env\n")
				runGit(t, directory, "config", "age.recipient", identity.Recipient().String())
			}
			writeFile(t, directory, "sub/secret.env", "original\n")
			mustCommand(t, directory, "lock", args...)
			ciphertext := readFile(t, directory, "sub/secret.env")
			runGit(t, directory, "add", ".gitage", "sub/secret.env")
			runGit(t, directory, "commit", "-qm", "nested external recipients")
			extra := newIdentity(t)
			writeFile(t, directory, "sub/.gitage", "[recipients]\n"+extra.Recipient().String()+"\n")
			writeFile(t, directory, "sub/secret.env", "original\n")
			mustCommand(t, directory, "lock", args...)
			fresh := readFile(t, directory, "sub/secret.env")
			if bytes.Equal(ciphertext, fresh) {
				t.Fatal("nested recipient addition reused stale ciphertext")
			}
			assertDecrypts(t, fresh, identity, []byte("original\n"))
			assertDecrypts(t, fresh, extra, []byte("original\n"))
		})
	}
}

func TestEffectiveRecipientReuse(t *testing.T) {
	for _, change := range []string{"comment", "patterns", "reorder and duplicates", "empty nested recipients", "move to nested", "addition", "removal"} {
		for _, stage := range []string{"working", "staged", "committed"} {
			t.Run(change+"/"+stage, func(t *testing.T) {
				isolateHookEnvironment(t)
				plaintext := []byte("original\n")
				directory, own, _ := cleanFixture(t, plaintext, false)
				other, added := newIdentity(t), newIdentity(t)
				rules := "[files]\n*.env\n[recipients]\n" + own.Recipient().String() + "\n" + other.Recipient().String() + "\n"
				writeFile(t, directory, ".gitage", rules)
				runGit(t, directory, "mv", "secret.env", "sub/secret.env")
				// Simulate ciphertext from an older version or another clone,
				// without any local recipient fingerprint.
				var ciphertext bytes.Buffer
				writer, err := age.Encrypt(&ciphertext, own.Recipient(), other.Recipient())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := writer.Write(plaintext); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				writeFile(t, directory, "sub/secret.env", ciphertext.String())
				runGit(t, directory, "add", ".gitage", "sub/secret.env")
				runGit(t, directory, "commit", "-qm", "two recipients")
				switch change {
				case "comment":
					rules = "# useful comment\n" + rules
				case "patterns":
					rules = strings.Replace(rules, "*.env\n", "*.env\n*.secret\n", 1)
				case "reorder and duplicates":
					rules = "[files]\n*.env\n[recipients]\n" + other.Recipient().String() + "\n" + own.Recipient().String() + "\n" + own.Recipient().String() + "\n"
				case "empty nested recipients":
					writeFile(t, directory, "sub/.gitage", "# no recipient changes\n[files]\n*.secret\n")
				case "move to nested":
					rules = "[files]\n*.env\n[recipients]\n" + own.Recipient().String() + "\n"
					writeFile(t, directory, "sub/.gitage", "[recipients]\n"+other.Recipient().String()+"\n")
				case "addition":
					rules += added.Recipient().String() + "\n"
				case "removal":
					rules = "[files]\n*.env\n[recipients]\n" + own.Recipient().String() + "\n"
				}
				writeFile(t, directory, ".gitage", rules)
				if stage != "working" {
					runGit(t, directory, "add", ".gitage", "sub")
				}
				if stage == "committed" {
					runGit(t, directory, "commit", "-qm", "change rules")
				}
				changedRecipients := change == "addition" || change == "removal"
				cleaned, _, err := runClean(directory, "sub/secret.env", plaintext)
				want := ciphertext.Bytes()
				if changedRecipients {
					want = plaintext
				}
				if err != nil || !bytes.Equal(cleaned, want) {
					t.Fatalf("clean after %s: %v, output %q", change, err, cleaned)
				}
				writeFile(t, directory, "sub/secret.env", string(plaintext))
				mustCommand(t, directory, "lock")
				locked := readFile(t, directory, "sub/secret.env")
				if bytes.Equal(locked, ciphertext.Bytes()) == changedRecipients {
					t.Fatalf("wrong reuse decision after %s", change)
				}
				assertDecrypts(t, locked, own, plaintext)
				if change == "addition" {
					assertDecrypts(t, locked, added, plaintext)
				}
				if change == "removal" {
					assertCannotDecrypt(t, locked, other)
				}
			})
		}
	}
}

func TestPreCommitReusesAcrossUnstagedRuleComments(t *testing.T) {
	isolateHookEnvironment(t)
	directory, _, ciphertext := cleanFixture(t, []byte("original\n"), false)
	rules := readFile(t, directory, ".gitage")
	writeFile(t, directory, ".gitage", "# unstaged comment\n"+string(rules))
	writeFile(t, directory, "secret.env", "original\n")
	writeFile(t, directory, "note.txt", "unrelated change\n")
	runGit(t, directory, "add", "secret.env", "note.txt")
	t.Setenv("GIT_AGE_HOOK_MODE", "always-lock")
	mustCommand(t, directory, "hook", "pre-commit")
	if !bytes.Equal(ciphertext, runGit(t, directory, "show", ":secret.env")) {
		t.Fatal("unstaged rule comment prevented pre-commit reuse")
	}
}
