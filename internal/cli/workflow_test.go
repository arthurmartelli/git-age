package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Exercise installed hooks and drivers together through the team's normal
// Git workflow. Command tests separately cover their detailed failure cases.
func TestTeamWorkflow(t *testing.T) {
	buildGitAge(t)
	isolateHookEnvironment(t)
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	for key, value := range map[string]string{"user.name": "Test", "user.email": "test@example.invalid", "commit.gpgsign": "false"} {
		runGit(t, directory, "config", key, value)
	}
	alice, bob, carol := newIdentity(t), newIdentity(t), newIdentity(t)
	runGit(t, directory, "config", "age.keyFile", writeKey(t, alice))
	rules := "[files]\nsecret.env\nconfig/*.yaml\n[recipients]\n" + alice.Recipient().String() + "\n" + bob.Recipient().String() + "\n"
	writeFile(t, directory, ".gitage", rules)
	writeFile(t, directory, "secret.env", "API_TOKEN=s3cr3t\n")
	writeFile(t, directory, "config/credentials.yaml", "password: hunter2\n")
	if output := mustCommand(t, directory, "status", "--porcelain"); output != "U. config/credentials.yaml\nU. secret.env\n" {
		t.Fatalf("initial status: %q", output)
	}
	if output := mustCommand(t, directory, "status", "-z"); output != "U. config/credentials.yaml\x00U. secret.env\x00" {
		t.Fatalf("NUL status: %q", output)
	}
	mustCommand(t, directory, "install", "--mode=always-lock")
	runGit(t, directory, "add", "-A")
	runGit(t, directory, "commit", "-qm", "initial secrets")
	secret := runGit(t, directory, "show", "HEAD:secret.env")
	credentials := runGit(t, directory, "show", "HEAD:config/credentials.yaml")
	for _, ciphertext := range [][]byte{secret, credentials} {
		assertCannotDecrypt(t, ciphertext, carol)
	}
	assertDecrypts(t, secret, alice, []byte("API_TOKEN=s3cr3t\n"))
	assertDecrypts(t, secret, bob, []byte("API_TOKEN=s3cr3t\n"))
	assertDecrypts(t, credentials, bob, []byte("password: hunter2\n"))
	clean := func() {
		t.Helper()
		if status := runGit(t, directory, "status", "--porcelain"); len(status) != 0 {
			t.Fatalf("working tree is dirty: %s", status)
		}
	}
	mustCommand(t, directory, "unlock")
	clean()
	runGit(t, directory, "diff", "--quiet")
	runGit(t, directory, "add", "-A")
	if !bytes.Equal(secret, runGit(t, directory, "show", ":secret.env")) {
		t.Fatal("git add did not reuse ciphertext")
	}
	mustCommand(t, directory, "lock")
	clean()
	if !bytes.Equal(secret, readFile(t, directory, "secret.env")) {
		t.Fatal("relocking unchanged file changed ciphertext")
	}
	mustCommand(t, directory, "unlock")
	writeFile(t, directory, "secret.env", "API_TOKEN=edited\n")
	if status := string(runGit(t, directory, "status", "--porcelain")); status != " M secret.env\n" {
		t.Fatalf("edit status: %q", status)
	}
	writeFile(t, directory, "secret.env", "API_TOKEN=s3cr3t\n")
	clean()
	// Invalidate Git's stat cache before checking that disabled comparison
	// filters and an absent identity expose plaintext as modified.
	forget := func() {
		t.Helper()
		runGit(t, directory, "update-index", "--cacheinfo", "100644,"+gitRevision(t, directory, "HEAD:secret.env")+",secret.env")
	}
	forget()
	if status := string(runGit(t, directory, "-c", "age.keyFile=", "status", "--porcelain", "--", "secret.env")); status != " M secret.env\n" {
		t.Fatalf("identity-free status: %q", status)
	}
	mustCommand(t, directory, "install", "--mode=always-lock", "--no-filter")
	forget()
	if status := string(runGit(t, directory, "status", "--porcelain", "--", "secret.env")); status != " M secret.env\n" {
		t.Fatalf("disabled-filter status: %q", status)
	}
	mustCommand(t, directory, "install", "--mode=always-lock")
	mustCommand(t, directory, "lock")
	clean()
	mustCommand(t, directory, "unlock")
	writeFile(t, directory, "secret.env", "API_TOKEN=rotated\n")
	runGit(t, directory, "add", "secret.env")
	runGit(t, directory, "commit", "-qm", "rotate token")
	assertDecrypts(t, runGit(t, directory, "show", "HEAD:secret.env"), alice, []byte("API_TOKEN=rotated\n"))
	if diff := runGit(t, directory, "show", "HEAD", "--", "secret.env"); !bytes.Contains(diff, []byte("\n+API_TOKEN=rotated\n")) {
		t.Fatalf("git show did not decrypt diff: %s", diff)
	}
	if output := runGit(t, directory, "-c", "age.keyFile=", "show", "--textconv", "HEAD:secret.env"); !bytes.Contains(output, []byte("git-age: encrypted, no identity configured")) {
		t.Fatalf("missing diff placeholder: %s", output)
	}

	writeFile(t, directory, ".gitage", rules+carol.Recipient().String()+"\n")
	if output := mustCommand(t, directory, "status"); !strings.Contains(output, "previous [recipients] list") {
		t.Fatalf("missing stale warning: %s", output)
	}
	mustCommand(t, directory, "rekey")
	runGit(t, directory, "add", "-A")
	runGit(t, directory, "commit", "-qm", "add carol")
	assertDecrypts(t, runGit(t, directory, "show", "HEAD:secret.env"), carol, []byte("API_TOKEN=rotated\n"))
	if status := mustCommand(t, directory, "status", "--porcelain"); status != "L. config/credentials.yaml\nL. secret.env\n" {
		t.Fatalf("stale after committed rekey: %q", status)
	}
	writeFile(t, directory, ".gitage", rules)
	runGit(t, directory, "add", ".gitage")
	refuseGit(t, directory, "still encrypted to the previous list", "commit", "-qm", "remove carol before rekey")
	runGit(t, directory, "reset", "-q", "--hard")

	// Runtime operations refresh attributes when a new pattern is added.
	rules = string(readFile(t, directory, ".gitage"))
	writeFile(t, directory, ".gitage", strings.Replace(rules, "secret.env\n", "secret.env\n*.secret\n", 1))
	writeFile(t, directory, "new.secret", "hidden\n")
	mustCommand(t, directory, "lock")
	runGit(t, directory, "add", "new.secret")
	assertDecrypts(t, runGit(t, directory, "show", ":new.secret"), bob, []byte("hidden\n"))
	if got := string(runGit(t, directory, "cat-file", "--textconv", ":new.secret")); got != "hidden\n" {
		t.Fatalf("new-pattern diff: %q", got)
	}
	runGit(t, directory, "reset", "-q", "--hard")
	mustCommand(t, directory, "lock")

	// Removing the drivers must disable readable diffs without removing hooks
	// that belong to another tool; uninstall and reinstall restore the lifecycle.
	hooks := installGitPath(t, directory, "hooks")
	dry := mustCommand(t, directory, "install", "-n", "--no-diff", "--no-merge", "--no-filter")
	if !strings.Contains(dry, "would remove git-age post-checkout hook") {
		t.Fatalf("disable dry run: %s", dry)
	}
	mustCommand(t, directory, "install", "--mode=always-lock", "--no-diff", "--no-merge", "--no-filter")
	if output := runGit(t, directory, "cat-file", "--textconv", "HEAD:secret.env"); !bytes.HasPrefix(output, []byte("age-encryption.org/v1\n")) {
		t.Fatalf("disabled diff decrypted: %s", output)
	}
	for _, event := range []string{"post-checkout", "post-rewrite"} {
		if _, err := os.Stat(filepath.Join(hooks, event)); !os.IsNotExist(err) {
			t.Fatalf("disabled hook %s: %v", event, err)
		}
	}
	if _, err := os.Stat(filepath.Join(hooks, "post-merge")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, hooks, "post-checkout", "#!/bin/sh\n")
	mustCommand(t, directory, "install", "--mode=always-lock", "--no-diff", "--no-merge", "--no-filter")
	if string(readFile(t, hooks, "post-checkout")) != "#!/bin/sh\n" {
		t.Fatal("disabled install removed unmanaged hook")
	}
	if err := os.Remove(filepath.Join(hooks, "post-checkout")); err != nil {
		t.Fatal(err)
	}
	mustCommand(t, directory, "install", "--mode=always-lock")
	writeFile(t, hooks, "post-rewrite", "#!/bin/sh\n")
	if err := os.Chmod(filepath.Join(hooks, "post-rewrite"), 0755); err != nil {
		t.Fatal(err)
	}
	before := installSnapshot(t, directory)
	if output := mustCommand(t, directory, "uninstall", "-n"); !strings.Contains(output, "would remove git-age pre-push hook") {
		t.Fatalf("uninstall dry run: %s", output)
	}
	if !reflect.DeepEqual(before, installSnapshot(t, directory)) {
		t.Fatal("uninstall dry run changed repository")
	}
	if output := mustCommand(t, directory, "uninstall"); !strings.Contains(output, "Kept post-rewrite hook") {
		t.Fatalf("uninstall did not report unmanaged hook: %s", output)
	}
	for _, event := range []string{"pre-commit", "post-commit", "pre-push", "post-checkout", "post-merge"} {
		if _, err := os.Stat(filepath.Join(hooks, event)); !os.IsNotExist(err) {
			t.Fatalf("uninstall left %s: %v", event, err)
		}
	}
	if string(readFile(t, hooks, "post-rewrite")) != "#!/bin/sh\n" {
		t.Fatal("uninstall removed unmanaged hook")
	}
	runGit(t, directory, "config", "age.keyFile")
	if output := runGit(t, directory, "cat-file", "--textconv", "HEAD:secret.env"); !bytes.HasPrefix(output, []byte("age-encryption.org/v1\n")) {
		t.Fatal("uninstall left readable diffs")
	}
	if !bytes.HasPrefix(readFile(t, directory, "secret.env"), []byte("age-encryption.org/v1\n")) {
		t.Fatal("uninstall unlocked file")
	}
	if output := mustCommand(t, directory, "uninstall"); output != "Kept post-rewrite hook: not managed by git-age\ngit-age: nothing to uninstall\n" {
		t.Fatalf("second uninstall: %q", output)
	}
	if err := os.Remove(filepath.Join(hooks, "post-rewrite")); err != nil {
		t.Fatal(err)
	}
	mustCommand(t, directory, "install", "--mode=always-lock")
	if got := string(runGit(t, directory, "cat-file", "--textconv", "HEAD:secret.env")); got != "API_TOKEN=rotated\n" {
		t.Fatalf("reinstall did not restore readable diffs: %q", got)
	}
	for _, event := range []string{"pre-commit", "pre-push"} {
		if _, err := os.Stat(filepath.Join(hooks, event)); err != nil {
			t.Fatalf("reinstall missing %s: %v", event, err)
		}
	}
}
