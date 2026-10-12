package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"filippo.io/age"
)

// auditFixture is a repository whose first commit holds secret.env as
// plaintext, before .gitage protected it, and whose second encrypts it.
func auditFixture(t *testing.T) (directory string, identity *age.X25519Identity) {
	t.Helper()
	directory = t.TempDir()
	initKeygenRepo(t, directory)
	for _, name := range []string{"GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"} {
		t.Setenv(name, "git-age test")
	}
	for _, name := range []string{"GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"} {
		t.Setenv(name, "test@example.invalid")
	}
	t.Setenv("GIT_AGE_RECIPIENT", "")
	t.Setenv("GIT_AGE_TRUSTED_RECIPIENTS", "")
	identity = newIdentity(t)
	t.Setenv("GIT_AGE_KEY_FILE", writeKey(t, identity))
	writeFile(t, directory, "secret.env", "TOKEN=early\n")
	writeFile(t, directory, "readme", "hello\n")
	runGit(t, directory, "add", ".")
	runGit(t, directory, "commit", "-qm", "before .gitage")
	writeFile(t, directory, ".gitage", "[files]\n*.env\n\n[recipients]\n"+identity.Recipient().String()+"\n")
	if output, err := runCommand(directory, "lock"); err != nil {
		t.Fatalf("lock: %v\n%s", err, output)
	}
	runGit(t, directory, "add", ".")
	runGit(t, directory, "commit", "-qm", "protect secret.env")
	return directory, identity
}

func writeKey(t *testing.T, identity *age.X25519Identity) string {
	t.Helper()
	directory := t.TempDir()
	writeFile(t, directory, "key", identity.String()+"\n")
	return directory + "/key"
}

func TestHistoryAuditFindsPlaintext(t *testing.T) {
	directory, _ := auditFixture(t)
	output, err := runCommand(directory, "history", "audit")
	if !errors.Is(err, errCheckFailed) || !strings.Contains(output, "Protected files committed as plaintext:\n\n  secret.env\n") ||
		!strings.Contains(output, "  before .gitage\n") || strings.Contains(output, "readme") {
		t.Fatalf("audit: %v\n%s", err, output)
	}
	if output, err := runCommand(directory, "history", "audit", "no-such-revision"); err == nil || errors.Is(err, errCheckFailed) {
		t.Fatalf("audit of a bad revision: %v\n%s", err, output)
	}
}

func TestHistoryAuditReflog(t *testing.T) {
	directory, _ := auditFixture(t)
	if _, err := runCommand(directory, "history", "rekey", "--yes", "--plaintext-only"); err != nil {
		t.Fatal(err)
	}
	runGit(t, directory, "update-ref", "-d", "refs/git-age/original/refs/heads/master")
	if output, err := runCommand(directory, "history", "audit"); err != nil {
		t.Fatalf("audit after rekey: %v\n%s", err, output)
	}
	if output, err := runCommand(directory, "history", "audit", "--reflog"); !errors.Is(err, errCheckFailed) || !strings.Contains(output, "  secret.env\n") {
		t.Fatalf("audit --reflog: %v\n%s", err, output)
	}
}

func TestHistoryAuditWarnsAboutInvalidHistoricalRules(t *testing.T) {
	directory, _ := auditFixture(t)
	writeFile(t, directory, "sub/.gitage", "[unknown]\n")
	runGit(t, directory, "add", ".")
	runGit(t, directory, "commit", "-qm", "invalid rules")
	runGit(t, directory, "rm", "-q", "sub/.gitage")
	runGit(t, directory, "commit", "-qm", "drop invalid rules")
	output, err := runCommand(directory, "history", "audit")
	if !errors.Is(err, errCheckFailed) || !strings.Contains(output, "warning:") || !strings.Contains(output, "  secret.env\n") {
		t.Fatalf("audit: %v\n%s", err, output)
	}
}

func TestHistoryRekeyPlaintextOnlyKeepsCiphertext(t *testing.T) {
	directory, identity := auditFixture(t)
	locked := runGit(t, directory, "show", "HEAD:secret.env")
	output, err := runCommand(directory, "history", "rekey", "--yes", "--plaintext-only")
	if err != nil || !strings.Contains(output, "1 plaintext version(s) encrypted, 0 re-encrypted") {
		t.Fatalf("history rekey --plaintext-only: %v\n%s", err, output)
	}
	if !bytes.Equal(runGit(t, directory, "show", "HEAD:secret.env"), locked) {
		t.Fatal("--plaintext-only re-encrypted ciphertext")
	}
	assertDecrypts(t, runGit(t, directory, "show", "HEAD~1:secret.env"), identity, []byte("TOKEN=early\n"))
	if !bytes.Equal(runGit(t, directory, "show", "HEAD~1:readme"), []byte("hello\n")) {
		t.Fatal("an unprotected file changed")
	}
}

func TestHistoryRekeyKeepUndecryptable(t *testing.T) {
	directory, identity := auditFixture(t)
	other := newIdentity(t)
	writeFile(t, directory, "other.env", string(encryptFixture(t, other.Recipient(), "theirs\n", false)))
	runGit(t, directory, "add", ".")
	runGit(t, directory, "commit", "-qm", "someone else's file")
	head := strings.TrimSpace(string(runGit(t, directory, "rev-parse", "HEAD")))
	output, err := runCommand(directory, "history", "rekey", "--yes")
	if err == nil || !strings.Contains(output, "  other.env in ") || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("history rekey: %v\n%s", err, output)
	}
	if strings.TrimSpace(string(runGit(t, directory, "rev-parse", "HEAD"))) != head {
		t.Fatal("a refused rekey moved HEAD")
	}
	output, err = runCommand(directory, "history", "rekey", "--yes", "--keep-undecryptable")
	if err != nil || !strings.Contains(output, "kept 1 version(s) you cannot decrypt") {
		t.Fatalf("history rekey --keep-undecryptable: %v\n%s", err, output)
	}
	assertDecrypts(t, runGit(t, directory, "show", "HEAD:other.env"), other, []byte("theirs\n"))
	assertDecrypts(t, runGit(t, directory, "show", "HEAD~2:secret.env"), identity, []byte("TOKEN=early\n"))
}

func TestHistoryRekeyRewritesStash(t *testing.T) {
	directory, identity := auditFixture(t)
	if _, err := runCommand(directory, "history", "rekey", "--yes"); err != nil {
		t.Fatal(err)
	}
	runGit(t, directory, "update-ref", "-d", "refs/git-age/original/refs/heads/master")
	writeFile(t, directory, "secret.env", "TOKEN=stashed\n")
	runGit(t, directory, "stash", "-q")
	if output, err := runCommand(directory, "history", "audit"); !errors.Is(err, errCheckFailed) || !strings.Contains(output, "WIP on master: ") {
		t.Fatalf("audit of the stash: %v\n%s", err, output)
	}
	output, err := runCommand(directory, "history", "rekey", "--yes")
	if err != nil || !strings.Contains(output, "1 plaintext version(s) encrypted") {
		t.Fatalf("history rekey: %v\n%s", err, output)
	}
	if output, err := runCommand(directory, "history", "audit"); err != nil {
		t.Fatalf("audit after rekey: %v\n%s", err, output)
	}
	assertDecrypts(t, runGit(t, directory, "show", "stash@{0}:secret.env"), identity, []byte("TOKEN=stashed\n"))
	if _, err := runCommand(directory, "history", "rekey", "--yes"); err == nil || !strings.Contains(err.Error(), "previous rewrite") {
		t.Fatalf("second rekey: %v", err)
	}
}

func TestHistoryRekeyDetachedHead(t *testing.T) {
	directory, identity := auditFixture(t)
	runGit(t, directory, "checkout", "-q", "--detach")
	runGit(t, directory, "branch", "-q", "-D", "master")
	output, err := runCommand(directory, "history", "rekey", "--yes")
	if err != nil || !strings.Contains(output, "rewriting 2 of 2 commit(s) and 1 ref(s)") {
		t.Fatalf("history rekey: %v\n%s", err, output)
	}
	assertDecrypts(t, runGit(t, directory, "show", "HEAD~1:secret.env"), identity, []byte("TOKEN=early\n"))
	if !bytes.Equal(readFile(t, directory, "secret.env"), runGit(t, directory, "show", "HEAD:secret.env")) {
		t.Fatal("the working tree was not checked out to the new HEAD")
	}
	if output, err := runCommand(directory, "history", "rekey", "--yes"); err == nil {
		t.Fatalf("second rekey: %s", output)
	}
}
