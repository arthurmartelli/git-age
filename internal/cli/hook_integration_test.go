package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func isolateHookEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{"GIT_AGE_KEY_FILE", "GIT_AGE_RECIPIENT", "GIT_AGE_TRUSTED_RECIPIENTS", "GIT_AGE_HOOK_MODE", "GIT_AGE_ALLOW_EMPTY", "GIT_AGE_ALLOW_REMOVE", "GIT_AGE_ALLOW_PRIVATE_KEYS", "GIT_AGE_ALLOW_STALE_RECIPIENTS", "GIT_AGE_ALLOW_PLAINTEXT_PUSH"} {
		t.Setenv(name, "")
	}
	t.Setenv("GIT_AGE_UNLOCK_AFTER_COMMIT", "0")
}

func TestHookCommitRefusals(t *testing.T) {
	buildGitAge(t)
	for _, scenario := range []string{"abort", "local key", "unprotected key", "stale recipients", "empty encryption"} {
		t.Run(scenario, func(t *testing.T) {
			isolateHookEnvironment(t)
			directory, identity, ciphertext := cleanFixture(t, []byte("original\n"), false)
			mustCommand(t, directory, "install", "--mode=always-lock")
			diagnostic := ""
			switch scenario {
			case "abort":
				writeFile(t, directory, "secret.env", "leaked\n")
				runGit(t, directory, "add", "secret.env")
				t.Setenv("GIT_AGE_HOOK_MODE", "abort")
				diagnostic = "commit aborted"
			case "local key":
				runGit(t, directory, "add", "-f", ".gitage.key")
				diagnostic = "refusing to commit private age keys"
			case "unprotected key":
				writeFile(t, directory, "leaked-key.txt", identity.String()+"\n")
				runGit(t, directory, "add", "leaked-key.txt")
				diagnostic = "leaked-key.txt"
			case "stale recipients":
				writeFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+identity.Recipient().String()+"\n"+newIdentity(t).Recipient().String()+"\n")
				runGit(t, directory, "add", ".gitage")
				diagnostic = "still encrypted to the previous list"
			case "empty encryption":
				writeFile(t, directory, "secret.env", "original\n")
				oid := strings.TrimSpace(string(runGit(t, directory, "hash-object", "-w", "--no-filters", "secret.env")))
				runGit(t, directory, "update-index", "--cacheinfo", "100644,"+oid+",secret.env")
				diagnostic = "encrypt to the ciphertext already in HEAD"
			}
			head := gitRevision(t, directory, "HEAD")
			refuseGit(t, directory, diagnostic, "commit", "-qm", "refused")
			if gitRevision(t, directory, "HEAD") != head {
				t.Fatal("refused commit moved HEAD")
			}
			if scenario == "empty encryption" {
				if !bytes.Equal(ciphertext, runGit(t, directory, "show", ":secret.env")) {
					t.Fatal("empty encryption did not reuse ciphertext")
				}
				t.Setenv("GIT_AGE_ALLOW_EMPTY", "1")
				runGit(t, directory, "commit", "-q", "--amend", "--no-edit")
				if !bytes.Equal(ciphertext, runGit(t, directory, "show", "HEAD:secret.env")) {
					t.Fatal("allowed amend changed ciphertext")
				}
			}
		})
	}
}

func TestHookRuleRemovalWorkflow(t *testing.T) {
	buildGitAge(t)
	isolateHookEnvironment(t)
	directory, _, _ := cleanFixture(t, []byte("original\n"), false)
	writeFile(t, directory, "sub/.gitage", "[files]\n*.env\n")
	writeFile(t, directory, "sub/deep/.keep", "")
	runGit(t, directory, "add", "sub")
	runGit(t, directory, "commit", "-qm", "nested rules")
	mustCommand(t, directory, "install", "--mode=always-lock")
	runGit(t, directory, "rm", "-q", ".gitage")
	output := refuseGit(t, directory, "refusing to commit the removal of .gitage", "commit", "-qm", "drop rules")
	if !bytes.Contains(output, []byte("git-age uninstall")) {
		t.Fatalf("missing uninstall guidance: %s", output)
	}
	runGit(t, directory, "restore", "--staged", "--worktree", "--", ".gitage")
	runGit(t, directory, "mv", "sub/.gitage", "sub/deep/.gitage")
	refuseGit(t, directory, "sub/.gitage", "commit", "-qm", "move rules")
	runGit(t, directory, "mv", "sub/deep/.gitage", "sub/.gitage")
	runGit(t, directory, "rm", "-q", ".gitage", "sub/.gitage")
	t.Setenv("GIT_AGE_ALLOW_REMOVE", "1")
	output = runGit(t, directory, "commit", "-qm", "drop rules explicitly")
	if !bytes.Contains(output, []byte("by explicit choice (GIT_AGE_ALLOW_REMOVE)")) {
		t.Fatalf("missing removal warning: %s", output)
	}
	t.Setenv("GIT_AGE_ALLOW_REMOVE", "")
	t.Setenv("GIT_AGE_UNLOCK_AFTER_COMMIT", "1")
	if output := runGit(t, directory, "commit", "-q", "--allow-empty", "-m", "after removal"); len(output) != 0 {
		t.Fatalf("no-rules commit should be silent: %s", output)
	}
	writeFile(t, directory, "notes.txt", "AGE-SECRET-KEY-1 is the marker\n")
	runGit(t, directory, "add", "notes.txt")
	if output := runGit(t, directory, "commit", "-qm", "marker without rules"); len(output) != 0 {
		t.Fatalf("marker commit should be silent: %s", output)
	}
	runGit(t, directory, "add", "-f", ".gitage.key")
	refuseGit(t, directory, "refusing to commit private age keys", "commit", "-qm", "key without rules")
}

func TestHookTrustAndRecipientMerge(t *testing.T) {
	buildGitAge(t)
	isolateHookEnvironment(t)
	directory, identity, _ := cleanFixture(t, []byte("original\n"), false)
	writeFile(t, directory, "prod/.gitage", "[recipients]\n"+identity.Recipient().String()+"\n")
	runGit(t, directory, "add", "prod/.gitage")
	runGit(t, directory, "commit", "-qm", "unchanged nested recipients")
	mustCommand(t, directory, "install", "--mode=always-lock")
	mustCommand(t, directory, "trust")
	other := newIdentity(t)
	rules := "[files]\n*.env\n[recipients]\n" + identity.Recipient().String() + "\n" + other.Recipient().String() + "\n"
	writeFile(t, directory, ".gitage", rules)
	writeFile(t, directory, "secret.env", "untrusted edit\n")
	runGit(t, directory, "add", ".gitage", "secret.env")
	before := gitRevision(t, directory, "HEAD")
	index := runGit(t, directory, "ls-files", "--stage", "-z")
	refuseGit(t, directory, "untrusted", "commit", "-qm", "untrusted recipients")
	if gitRevision(t, directory, "HEAD") != before || !bytes.Equal(index, runGit(t, directory, "ls-files", "--stage", "-z")) || string(readFile(t, directory, "secret.env")) != "untrusted edit\n" {
		t.Fatal("trust refusal changed commit, index or working copy")
	}
	runGit(t, directory, "reset", "-q", "--hard")
	branch := strings.TrimSpace(string(runGit(t, directory, "branch", "--show-current")))
	runGit(t, directory, "checkout", "-qb", "mallory")
	writeFile(t, directory, ".gitage", rules)
	runGit(t, directory, "add", ".gitage")
	runGit(t, directory, "-c", "user.name=Mallory", "commit", "--no-verify", "-qm", "sneak in recipient")
	runGit(t, directory, "checkout", "-q", branch)
	output := runGit(t, directory, "merge", "-q", "mallory")
	if !bytes.Contains(output, []byte("this merge changes [recipients] in .gitage")) {
		t.Fatalf("missing post-merge warning: %s", output)
	}
}

func TestScopedRecipientWorkflow(t *testing.T) {
	buildGitAge(t)
	for _, explicitBase := range []bool{true, false} {
		name := "identity fallback"
		if explicitBase {
			name = "explicit base"
		}
		t.Run(name, func(t *testing.T) {
			isolateHookEnvironment(t)
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			for key, value := range map[string]string{"user.name": "Test", "user.email": "test@example.invalid", "commit.gpgsign": "false"} {
				runGit(t, directory, "config", key, value)
			}
			alice, carol, dave := newIdentity(t), newIdentity(t), newIdentity(t)
			aliceKey, carolKey, daveKey := writeKey(t, alice), writeKey(t, carol), writeKey(t, dave)
			t.Setenv("GIT_AGE_KEY_FILE", aliceKey)
			rules := "[files]\n*.env\n"
			if explicitBase {
				rules += "[recipients]\n" + alice.Recipient().String() + "\n"
			}
			writeFile(t, directory, ".gitage", rules)
			nested := "[recipients]\n" + carol.Recipient().String() + "\n"
			writeFile(t, directory, "prod/.gitage", nested)
			writeFile(t, directory, "app.env", "app\n")
			writeFile(t, directory, "prod/db.env", "db\n")
			mustCommand(t, directory, "lock")
			app, db := readFile(t, directory, "app.env"), readFile(t, directory, "prod/db.env")
			assertDecrypts(t, app, alice, []byte("app\n"))
			assertCannotDecrypt(t, app, carol)
			assertDecrypts(t, db, alice, []byte("db\n"))
			assertDecrypts(t, db, carol, []byte("db\n"))
			runGit(t, directory, "add", "-A")
			runGit(t, directory, "commit", "-qm", "scoped secrets")
			t.Setenv("GIT_AGE_KEY_FILE", carolKey)
			if output := mustCommand(t, directory, "status", "--porcelain"); output != "LN app.env\nL. prod/db.env\n" {
				t.Fatalf("limited access: %q", output)
			}
			if output := mustCommand(t, directory, "unlock"); !strings.Contains(output, "1 file(s) locked that are not encrypted to you") {
				t.Fatalf("missing skip warning: %s", output)
			}
			if string(readFile(t, directory, "prod/db.env")) != "db\n" || !bytes.Equal(app, readFile(t, directory, "app.env")) {
				t.Fatal("unlock changed inaccessible file")
			}
			if output := mustCommand(t, directory, "status", "--porcelain"); output != "LN app.env\nU. prod/db.env\n" {
				t.Fatalf("unlocked limited-access status: %q", output)
			}
			mustCommand(t, directory, "lock")
			if !bytes.Equal(db, readFile(t, directory, "prod/db.env")) || len(runGit(t, directory, "status", "--porcelain")) != 0 {
				t.Fatal("limited-access lock did not reuse ciphertext")
			}
			if !explicitBase {
				t.Setenv("GIT_AGE_KEY_FILE", daveKey)
				if _, err := runCommand(directory, "unlock"); err == nil || !strings.Contains(err.Error(), "cannot decrypt") {
					t.Fatalf("unknown identity unlock: %v", err)
				}
				return
			}
			writeFile(t, directory, "prod/.gitage", nested+dave.Recipient().String()+"\n")
			t.Setenv("GIT_AGE_KEY_FILE", aliceKey)
			if got := mustCommand(t, directory, "status", "--porcelain"); got != "L. app.env\nLS prod/db.env\n" {
				t.Fatalf("nested staleness: %q", got)
			}
			t.Setenv("GIT_AGE_KEY_FILE", daveKey)
			if output := mustCommand(t, directory, "unlock"); !strings.Contains(output, "not re-encrypted to you yet") {
				t.Fatalf("new recipient warning: %s", output)
			}
			if !bytes.Equal(app, readFile(t, directory, "app.env")) || !bytes.Equal(db, readFile(t, directory, "prod/db.env")) {
				t.Fatal("stale unlock changed files")
			}
			t.Setenv("GIT_AGE_KEY_FILE", aliceKey)
			mustCommand(t, directory, "install", "--mode=always-lock")
			runGit(t, directory, "add", "prod/.gitage")
			refuseGit(t, directory, "prod/db.env", "commit", "-qm", "add dave before rekey")
			t.Setenv("GIT_AGE_KEY_FILE", carolKey)
			if output := mustCommand(t, directory, "rekey", "-v"); !strings.Contains(output, "app.env") {
				t.Fatalf("missing inaccessible path: %s", output)
			}
			assertDecrypts(t, readFile(t, directory, "prod/db.env"), dave, []byte("db\n"))
			runGit(t, directory, "add", "-A")
			runGit(t, directory, "commit", "-qm", "add dave")
			if diff := string(runGit(t, directory, "diff", "--name-only", "HEAD^", "HEAD", "--", "*.env")); diff != "prod/db.env\n" {
				t.Fatalf("rekey changed unrelated file: %s", diff)
			}
			writeFile(t, directory, "prod/db.env", string(encryptFixture(t, alice.Recipient(), "tampered\n", false)))
			t.Setenv("GIT_AGE_KEY_FILE", daveKey)
			if _, err := runCommand(directory, "unlock"); err == nil || !strings.Contains(err.Error(), "cannot decrypt prod/db.env") {
				t.Fatalf("tampered unlock: %v", err)
			}
			if !bytes.Equal(app, readFile(t, directory, "app.env")) {
				t.Fatal("failed unlock changed unrelated file")
			}
		})
	}
}

func TestLockRecipientOverrides(t *testing.T) {
	for _, source := range []string{"flag", "environment"} {
		t.Run(source, func(t *testing.T) {
			isolateHookEnvironment(t)
			directory, alice, _ := cleanFixture(t, []byte("original\n"), false)
			bob := newIdentity(t)
			mustCommand(t, directory, "unlock")
			args := []string{"-r", bob.Recipient().String()}
			if source == "environment" {
				t.Setenv("GIT_AGE_RECIPIENT", bob.Recipient().String())
				args = nil
			}
			mustCommand(t, directory, "lock", args...)
			content := readFile(t, directory, "secret.env")
			assertDecrypts(t, content, bob, []byte("original\n"))
			assertCannotDecrypt(t, content, alice)
		})
	}
}

func TestStatusInvalidRuleSections(t *testing.T) {
	directory := t.TempDir()
	for _, rule := range []struct{ content, diagnostic string }{{"secret.env\n", "outside a section"}, {"[files]\nsecret.env\n[nope]\n", "unknown section [nope]"}} {
		writeFile(t, directory, ".gitage", rule.content)
		if _, err := runCommand(directory, "status"); err == nil || !strings.Contains(err.Error(), rule.diagnostic) {
			t.Fatalf("invalid section: %v", err)
		}
	}
}

func TestLockDirectorySelection(t *testing.T) {
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	isolateHookEnvironment(t)
	identity := newIdentity(t)
	t.Setenv("GIT_AGE_KEY_FILE", writeKey(t, identity))
	writeFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+identity.Recipient().String()+"\n")
	for _, path := range []string{"top.env", "sub/a.env", "sub/b.env"} {
		writeFile(t, directory, path, "secret\n")
	}
	mustCommand(t, directory, "lock", "sub")
	if output := mustCommand(t, directory, "status", "--porcelain"); output != "L. sub/a.env\nL. sub/b.env\nU. top.env\n" {
		t.Fatalf("directory selection: %q", output)
	}
	mustCommand(t, filepath.Join(directory, "sub"), "unlock")
	if output := mustCommand(t, directory, "status", "--porcelain"); output != "U. sub/a.env\nU. sub/b.env\nU. top.env\n" {
		t.Fatalf("subdirectory unlock: %q", output)
	}
	mustCommand(t, filepath.Join(directory, "sub"), "lock")
	if output := mustCommand(t, directory, "status", "--porcelain"); output != "L. sub/a.env\nL. sub/b.env\nU. top.env\n" {
		t.Fatalf("subdirectory lock crossed its scope: %q", output)
	}
	mustCommand(t, directory, "unlock")
	// Reject a mixed selection before touching even its valid first path.
	writeFile(t, directory, "notes.txt", "notes\n")
	if _, err := runCommand(directory, "lock", "sub/a.env", "notes.txt"); err == nil {
		t.Fatal("unprotected path accepted")
	}
	if string(readFile(t, directory, "sub/a.env")) != "secret\n" {
		t.Fatal("invalid selection partially locked files")
	}
	writeFile(t, directory, "docs/readme.txt", "documentation\n")
	before := installSnapshot(t, directory)
	for _, test := range []struct{ directory, command, path, diagnostic string }{
		{directory, "unlock", "missing.env", "no such file or directory"},
		{directory, "status", "docs", "no file in it is protected"},
		{filepath.Join(directory, "sub"), "lock", "../top.env", "outside"},
		{directory, "lock", writeKey(t, identity), "outside"},
	} {
		if _, err := runCommand(test.directory, test.command, test.path); err == nil || !strings.Contains(err.Error(), test.diagnostic) {
			t.Fatalf("%s %s: %v", test.command, test.path, err)
		}
	}
	if !reflect.DeepEqual(before, installSnapshot(t, directory)) {
		t.Fatal("invalid path arguments changed repository files")
	}
	if _, err := os.Stat(filepath.Join(directory, ".gitage.key")); !os.IsNotExist(err) {
		t.Fatalf("unexpected local key: %v", err)
	}
}

func TestHookInteractiveWithoutTerminal(t *testing.T) {
	buildGitAge(t)
	isolateHookEnvironment(t)
	directory, _, _ := cleanFixture(t, []byte("original\n"), false)
	mustCommand(t, directory, "install", "--mode=interactive")
	writeFile(t, directory, "secret.env", "changed\n")
	runGit(t, directory, "add", "secret.env")
	head := gitRevision(t, directory, "HEAD")
	index := runGit(t, directory, "ls-files", "--stage", "-z")
	command := exec.Command("git", "-C", directory, "commit", "-qm", "no terminal")
	detachTerminal(command)
	output, err := command.CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte("interactive confirmation is unavailable")) {
		t.Fatalf("commit without terminal: %v\n%s", err, output)
	}
	if gitRevision(t, directory, "HEAD") != head || !bytes.Equal(index, runGit(t, directory, "ls-files", "--stage", "-z")) {
		t.Fatal("unavailable confirmation changed HEAD or index")
	}
}
