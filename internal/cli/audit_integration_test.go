package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestAuditHistoryWorkflow(t *testing.T) {
	directory, alice := auditFixture(t)
	bob := newIdentity(t)
	rules := "[files]\n*.env\n[recipients]\n" + alice.Recipient().String() + "\n" + bob.Recipient().String() + "\n"
	writeFile(t, directory, ".gitage", rules)
	mustCommand(t, directory, "rekey")
	runGit(t, directory, "add", "-A")
	runGit(t, directory, "commit", "-qm", "add bob")
	runGit(t, directory, "checkout", "-qb", "side")
	writeFile(t, directory, "side.env", "TOKEN=side\n")
	runGit(t, directory, "add", "side.env")
	runGit(t, directory, "commit", "-qm", "side plaintext")
	mustCommand(t, directory, "lock")
	runGit(t, directory, "add", "side.env")
	runGit(t, directory, "commit", "-qm", "side locked")
	runGit(t, directory, "branch", "side-head")
	runGit(t, directory, "checkout", "-q", "master")
	writeFile(t, directory, ".gitage", strings.Replace(rules, "*.env\n", "*.env\nold.txt\n", 1))
	writeFile(t, directory, "old.txt", "was protected\n")
	runGit(t, directory, "add", "-A")
	runGit(t, directory, "commit", "-qm", "old.txt protected as plaintext")
	writeFile(t, directory, ".gitage", rules)
	runGit(t, directory, "commit", "-qam", "old.txt no longer protected")
	runGit(t, directory, "merge", "-q", "--no-edit", "side")
	runGit(t, directory, "tag", "-a", "v1", "-m", "release")
	runGit(t, directory, "-c", "advice.nestedTag=false", "tag", "-a", "v1-nested", "-m", "tag of a tag", "v1")

	output, err := runCommand(directory, "audit")
	if !errors.Is(err, errCheckFailed) {
		t.Fatalf("audit: %v\n%s", err, output)
	}
	for _, path := range []string{"secret.env", "side.env", "old.txt"} {
		if !strings.Contains(output, "  "+path+"\n") {
			t.Fatalf("missing %s:\n%s", path, output)
		}
	}
	if strings.Contains(output, "readme") {
		t.Fatalf("unprotected file reported: %s", output)
	}
	output, err = runCommand(directory, "audit", "master~1")
	if !errors.Is(err, errCheckFailed) || strings.Contains(output, "side.env") {
		t.Fatalf("revision selection: %v\n%s", err, output)
	}
	if err := os.Mkdir(filepath.Join(directory, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	output, err = runCommand(filepath.Join(directory, "sub"), "audit")
	if !errors.Is(err, errCheckFailed) || !strings.Contains(output, "  secret.env\n") {
		t.Fatalf("subdirectory audit: %v\n%s", err, output)
	}

	writeFile(t, directory, ".gitage", strings.ReplaceAll(rules, bob.Recipient().String()+"\n", ""))
	runGit(t, directory, "commit", "-qam", "drop bob")
	before := gitRevision(t, directory, "HEAD")
	refs := runGit(t, directory, "for-each-ref", "--format=%(refname) %(objectname)", "refs/heads/", "refs/tags/")
	objects := installSnapshot(t, installGitPath(t, directory, "objects"))
	output = mustCommand(t, directory, "audit", "--rekey", "-n")
	if !strings.Contains(output, "would rewrite") || gitRevision(t, directory, "HEAD") != before || !bytes.Equal(refs, runGit(t, directory, "for-each-ref", "--format=%(refname) %(objectname)", "refs/heads/", "refs/tags/")) || !reflect.DeepEqual(objects, installSnapshot(t, installGitPath(t, directory, "objects"))) {
		t.Fatal("dry run changed history or wrote objects")
	}
	for _, scenario := range []string{"dirty working tree", "revisions", "wrong identity"} {
		t.Run(scenario, func(t *testing.T) {
			args, diagnostic := []string{"--rekey", "--yes"}, ""
			switch scenario {
			case "dirty working tree":
				writeFile(t, directory, "readme", "dirty\n")
				diagnostic = "uncommitted changes"
				defer runGit(t, directory, "checkout", "-q", "--", "readme")
			case "revisions":
				args = append(args, "master")
				diagnostic = "takes no revisions"
			case "wrong identity":
				other := newIdentity(t)
				t.Setenv("GIT_AGE_KEY_FILE", writeKey(t, other))
				t.Setenv("GIT_AGE_RECIPIENT", other.Recipient().String())
				diagnostic = "cannot decrypt"
			}
			output, err := runCommand(directory, "audit", args...)
			if err == nil || !strings.Contains(output+err.Error(), diagnostic) {
				t.Fatalf("refusal: %v\n%s", err, output)
			}
			if gitRevision(t, directory, "HEAD") != before || !bytes.Equal(refs, runGit(t, directory, "for-each-ref", "--format=%(refname) %(objectname)", "refs/heads/", "refs/tags/")) {
				t.Fatal("refusal changed refs")
			}
		})
	}
	output = mustCommand(t, directory, "audit", "--rekey", "--yes")
	if !strings.Contains(output, "git-age audit -- --branches --tags") {
		t.Fatalf("missing verification guidance: %s", output)
	}
	if gitRevision(t, directory, "HEAD") == before {
		t.Fatal("rewrite did not move HEAD")
	}
	for _, line := range strings.Split(strings.TrimSpace(string(refs)), "\n") {
		fields := strings.Fields(line)
		if got := gitRevision(t, directory, "refs/git-age/original/"+fields[0]); got != fields[1] {
			t.Fatalf("backup of %s: %s, want %s", fields[0], got, fields[1])
		}
	}
	mustCommand(t, directory, "audit")
	runGit(t, directory, "update-ref", "refs/remotes/origin/master", before)
	output, err = runCommand(directory, "audit")
	if !errors.Is(err, errCheckFailed) || !strings.Contains(output, "  secret.env\n") {
		t.Fatalf("remote history ignored: %v\n%s", err, output)
	}
	mustCommand(t, directory, "audit", "--", "--branches", "--tags")
	if gitRevision(t, directory, "refs/remotes/origin/master") != before {
		t.Fatal("rewrite changed remote-tracking ref")
	}
	runGit(t, directory, "update-ref", "-d", "refs/remotes/origin/master")

	for _, commit := range strings.Fields(string(runGit(t, directory, "rev-list", "--exclude=refs/git-age/*", "--all"))) {
		for _, path := range strings.Fields(string(runGit(t, directory, "ls-tree", "-r", "--name-only", commit))) {
			if !strings.HasSuffix(path, ".env") {
				continue
			}
			ciphertext := runGit(t, directory, "show", commit+":"+path)
			// Reading to EOF authenticates each historical version, not just its header.
			want := "TOKEN=early\n"
			if path == "side.env" {
				want = "TOKEN=side\n"
			}
			assertDecrypts(t, ciphertext, alice, []byte(want))
			assertCannotDecrypt(t, ciphertext, bob)
		}
	}
	if got := string(runGit(t, directory, "show", "HEAD:old.txt")); got != "was protected\n" {
		t.Fatalf("old.txt changed: %q", got)
	}
	for _, revision := range []string{"v1^{commit}", "v1-nested^{commit}", "side-head"} {
		runGit(t, directory, "merge-base", "--is-ancestor", revision, "HEAD")
	}
	nested := strings.SplitN(string(runGit(t, directory, "cat-file", "-p", "v1-nested")), "\n", 2)[0]
	if nested != "object "+gitRevision(t, directory, "v1") {
		t.Fatalf("nested tag targets old tag: %s", nested)
	}
	if status := runGit(t, directory, "status", "--porcelain"); len(status) != 0 {
		t.Fatalf("rewrite left dirty tree: %s", status)
	}
	if _, err := runCommand(directory, "audit", "--rekey", "--yes"); err == nil || !strings.Contains(err.Error(), "previous rewrite") {
		t.Fatalf("second rewrite: %v", err)
	}
}

func TestAuditPrivateKeyReporting(t *testing.T) {
	directory, identity := auditFixture(t)
	mustCommand(t, directory, "audit", "--rekey", "--yes")
	mustCommand(t, directory, "audit")
	writeFile(t, directory, "k.txt", identity.String()+"\n")
	runGit(t, directory, "add", "k.txt")
	runGit(t, directory, "commit", "-qm", "key as k.txt")
	keyCommit := gitRevision(t, directory, "HEAD")
	runGit(t, directory, "rm", "-q", "k.txt")
	runGit(t, directory, "commit", "-qm", "remove key")
	writeFile(t, directory, ".gitage.key", "not a key\n")
	runGit(t, directory, "add", "-f", ".gitage.key")
	runGit(t, directory, "commit", "-qm", "a .gitage.key")
	writeFile(t, directory, "secret.env", "TOKEN=plain\n")
	runGit(t, directory, "add", "secret.env")
	runGit(t, directory, "commit", "-qm", "plaintext secret.env")
	writeFile(t, directory, ".gitage.key", "not a key either\n")
	runGit(t, directory, "add", "-f", ".gitage.key")
	runGit(t, directory, "commit", "-qm", "change .gitage.key")
	output, err := runCommand(directory, "audit")
	if !errors.Is(err, errCheckFailed) {
		t.Fatalf("audit: %v\n%s", err, output)
	}
	for _, want := range []string{"Private age keys committed to Git history:", "  k.txt\n", "  .gitage.key\n", "in " + keyCommit[:12] + "  key as k.txt", "compromised", "git filter-repo", "and 1 more version(s); -v lists them"} {
		if !strings.Contains(output, want) {
			t.Fatalf("missing %q:\n%s", want, output)
		}
	}
	groups := strings.SplitN(output, "Protected files committed as plaintext:", 2)
	if len(groups) != 2 || strings.Contains(groups[0], "  secret.env\n") || !strings.Contains(groups[1], "  secret.env\n") {
		t.Fatalf("leak groups mixed:\n%s", output)
	}
	output, err = runCommand(directory, "audit", "-v")
	if !errors.Is(err, errCheckFailed) || !strings.Contains(output, "  a .gitage.key\n") || !strings.Contains(output, "  change .gitage.key\n") || strings.Contains(output, "-v lists them") {
		t.Fatalf("verbose audit: %v\n%s", err, output)
	}
	runGit(t, directory, "rm", "-q", "--cached", ".gitage.key")
	if err := os.Remove(filepath.Join(directory, ".gitage.key")); err != nil {
		t.Fatal(err)
	}
	runGit(t, directory, "commit", "-qm", "remove local key")
	runGit(t, directory, "for-each-ref", "--format=%(refname)", "refs/git-age/original/")
	// A dry run warns about committed keys without replacing the earlier backup.
	for _, ref := range strings.Fields(string(runGit(t, directory, "for-each-ref", "--format=%(refname)", "refs/git-age/original/"))) {
		runGit(t, directory, "update-ref", "-d", ref)
	}
	output = mustCommand(t, directory, "audit", "--rekey", "-n")
	if !strings.Contains(output, "private key file(s) are in Git history") {
		t.Fatalf("missing committed-key warning: %s", output)
	}
	// A broken warning stream must stop before refs move, just as a closed
	// pipe from a caller must not let an unreported rewrite proceed.
	streamErr := errors.New("broken warning stream")
	root := newRootCommand()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(cleanBrokenWriter{streamErr})
	root.SetArgs([]string{"-C", directory, "audit", "--rekey", "--yes"})
	head := gitRevision(t, directory, "HEAD")
	if err := root.Execute(); !errors.Is(err, streamErr) || gitRevision(t, directory, "HEAD") != head {
		t.Fatalf("failed warning changed refs or lost the error: %v", err)
	}
}

func TestAuditRekeyRequiresTerminalOrYes(t *testing.T) {
	binary := buildGitAge(t)
	directory, _ := auditFixture(t)
	before := gitRevision(t, directory, "HEAD")
	command := exec.Command(binary, "-C", directory, "audit", "--rekey")
	// A nil Stdin gives the executable the null device, even when go test has a tty.
	output, err := command.CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte("pass --yes")) || gitRevision(t, directory, "HEAD") != before {
		t.Fatalf("confirmation refusal: %v\n%s", err, output)
	}
}

func TestAuditAlreadyEncrypted(t *testing.T) {
	isolateHookEnvironment(t)
	directory, _, ciphertext := cleanFixture(t, []byte("original\n"), false)
	refs := runGit(t, directory, "for-each-ref", "--format=%(refname) %(objectname)")
	objects := installSnapshot(t, installGitPath(t, directory, "objects"))
	output := mustCommand(t, directory, "audit", "--rekey", "--yes", "--plaintext-only")
	if !strings.Contains(output, "history is already encrypted; nothing to do") {
		t.Fatalf("missing no-op message: %s", output)
	}
	if !bytes.Equal(refs, runGit(t, directory, "for-each-ref", "--format=%(refname) %(objectname)")) || !reflect.DeepEqual(objects, installSnapshot(t, installGitPath(t, directory, "objects"))) || !bytes.Equal(ciphertext, readFile(t, directory, "secret.env")) {
		t.Fatal("already encrypted rewrite changed refs, objects or ciphertext")
	}
}
