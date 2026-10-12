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

func assertHistoryPathsAbsent(t *testing.T, directory string, paths ...string) {
	t.Helper()
	for _, commit := range strings.Fields(string(runGit(t, directory, "rev-list", "--branches", "--tags", "HEAD", "--exclude=refs/git-age/*", "--glob=refs/stash"))) {
		entries := bytes.Split(runGit(t, directory, "ls-tree", "-r", "-z", "--name-only", commit), []byte{0})
		for _, entry := range entries {
			for _, name := range paths {
				if string(entry) == name || strings.HasPrefix(string(entry), name+"/") {
					t.Fatalf("%s remains in %s", name, commit)
				}
			}
		}
	}
}

func TestHistoryPurgePathsWorkflow(t *testing.T) {
	directory, _ := auditFixture(t)
	writeFile(t, directory, "sub/old key.txt", "old secret\n")
	writeFile(t, directory, "sub/keep.txt", "keep\n")
	writeFile(t, directory, "gone/nested/token", "deleted secret\n")
	runGit(t, directory, "add", ".")
	runGit(t, directory, "commit", "-qm", "unprotected secrets")
	runGit(t, directory, "branch", "side")
	runGit(t, directory, "rm", "-qr", "gone")
	runGit(t, directory, "commit", "-qm", "delete secret")
	runGit(t, directory, "checkout", "-q", "side")
	writeFile(t, directory, "sub/old key.txt", "branch secret\n")
	runGit(t, directory, "commit", "-qam", "branch changes")
	runGit(t, directory, "checkout", "-q", "master")
	runGit(t, directory, "merge", "-q", "--no-edit", "side")
	runGit(t, directory, "tag", "light")
	runGit(t, directory, "tag", "-a", "v1", "-m", "release")
	runGit(t, directory, "-c", "advice.nestedTag=false", "tag", "-a", "nested", "-m", "nested release", "v1")
	writeFile(t, directory, "sub/old key.txt", "stashed secret\n")
	runGit(t, directory, "stash", "-q")
	head := gitRevision(t, directory, "HEAD")
	runGit(t, directory, "update-ref", "refs/remotes/origin/master", head)
	runGit(t, directory, "update-ref", "refs/notes/test", head)
	refs := runGit(t, directory, "for-each-ref", "--format=%(refname) %(objectname)", "refs/heads/", "refs/tags/", "refs/stash")
	allRefs := runGit(t, directory, "for-each-ref", "--format=%(refname) %(objectname)")
	objects := installSnapshot(t, installGitPath(t, directory, "objects"))
	// From a subdirectory, select an existing file and a directory deleted in HEAD.
	args := []string{"purge", "old key.txt", "../gone"}
	output := mustCommand(t, filepath.Join(directory, "sub"), "history", append(args, "-n")...)
	if !strings.Contains(output, "would remove 2 path(s)") || gitRevision(t, directory, "HEAD") != head || !bytes.Equal(allRefs, runGit(t, directory, "for-each-ref", "--format=%(refname) %(objectname)")) || !reflect.DeepEqual(objects, installSnapshot(t, installGitPath(t, directory, "objects"))) {
		t.Fatalf("dry run changed history or objects: %s", output)
	}
	// Purge must not need a key, even when other protected ciphertext remains.
	t.Setenv("GIT_AGE_KEY_FILE", filepath.Join(directory, "missing.key"))
	mustCommand(t, filepath.Join(directory, "sub"), "history", append(args, "--yes")...)
	assertHistoryPathsAbsent(t, directory, "sub/old key.txt", "gone")
	for _, line := range strings.Split(strings.TrimSpace(string(refs)), "\n") {
		fields := strings.Fields(line)
		if gitRevision(t, directory, fields[0]) == fields[1] || gitRevision(t, directory, "refs/git-age/original/"+fields[0]) != fields[1] {
			t.Fatalf("%s not rewritten or backed up", fields[0])
		}
	}
	for _, ref := range []string{"refs/remotes/origin/master", "refs/notes/test"} {
		if gitRevision(t, directory, ref) != head {
			t.Fatalf("changed %s", ref)
		}
	}
	if gitRevision(t, directory, "nested^{commit}") != gitRevision(t, directory, "v1^{commit}") || gitRevision(t, directory, "light") != gitRevision(t, directory, "HEAD") {
		t.Fatal("tags do not point to rewritten commits")
	}
	for _, name := range []string{"readme", "sub/keep.txt", "secret.env", ".gitage"} {
		if !bytes.Equal(runGit(t, directory, "show", head+":"+name), runGit(t, directory, "show", "HEAD:"+name)) {
			t.Fatalf("changed unrelated %s", name)
		}
	}
	if status := runGit(t, directory, "status", "--porcelain"); len(status) != 0 {
		t.Fatalf("dirty working tree: %s", status)
	}
	if _, err := os.Stat(filepath.Join(directory, "sub/old key.txt")); !os.IsNotExist(err) {
		t.Fatalf("purged working file remains: %v", err)
	}
	if _, err := runCommand(directory, "history", "purge", "readme", "--yes"); err == nil || !strings.Contains(err.Error(), "previous rewrite") {
		t.Fatalf("second rewrite allowed: %v", err)
	}
	runGit(t, directory, "fsck", "--no-reflogs")
}

func TestHistoryPurgeAllHistoricalRules(t *testing.T) {
	directory, _ := auditFixture(t)
	writeFile(t, directory, "old.txt", "before protection\n")
	writeFile(t, directory, "sub/token", "nested secret\n")
	writeFile(t, directory, "sub/public", "public\n")
	writeFile(t, directory, ".gitage.key", "committed private key\n")
	runGit(t, directory, "add", "-f", "old.txt", "sub", ".gitage.key")
	runGit(t, directory, "commit", "-qm", "before historical rules")
	writeFile(t, directory, "sub/.gitage", "[files]\ntoken\n")
	writeFile(t, directory, ".gitage", "[files]\n*.env\nold.txt\n")
	runGit(t, directory, "add", ".")
	runGit(t, directory, "commit", "-qm", "protect unchanged files")
	runGit(t, directory, "rm", "-q", "sub/.gitage", "sub/token")
	writeFile(t, directory, ".gitage", "[files]\n*.env\n")
	runGit(t, directory, "commit", "-qam", "drop historical rules")
	writeFile(t, directory, "old.txt", "after protection\n")
	runGit(t, directory, "commit", "-qam", "change no longer protected file")
	t.Setenv("GIT_AGE_KEY_FILE", "")
	mustCommand(t, directory, "history", "purge", "--all", "--yes")
	assertHistoryPathsAbsent(t, directory, "secret.env", "old.txt", "sub/token")
	for _, name := range []string{".gitage", "readme", "sub/public", ".gitage.key"} {
		runGit(t, directory, "cat-file", "-e", "HEAD:"+name)
	}
	if status := runGit(t, directory, "status", "--porcelain"); len(status) != 0 {
		t.Fatalf("dirty working tree: %s", status)
	}
}

func TestHistoryPurgeLiteralPathsAndEmptyTree(t *testing.T) {
	for _, format := range []string{"sha1", "sha256"} {
		t.Run(format, func(t *testing.T) {
			directory, _ := auditFixture(t)
			if format == "sha256" {
				directory = t.TempDir()
				runGit(t, directory, "init", "-q", "--object-format=sha256", "--initial-branch=master")
			}
			writeFile(t, directory, "[secret]*", "literal name\n")
			writeFile(t, directory, "secret-other", "keep\n")
			writeFile(t, directory, "-secret", "leading dash\n")
			runGit(t, directory, "add", ".")
			runGit(t, directory, "commit", "-qm", "literal paths")
			runGit(t, directory, "checkout", "-q", "--detach")
			runGit(t, directory, "branch", "-D", "master")
			mustCommand(t, directory, "history", "purge", "--yes", "--", "[secret]*", "-secret")
			assertHistoryPathsAbsent(t, directory, "[secret]*", "-secret")
			if string(readFile(t, directory, "secret-other")) != "keep\n" {
				t.Fatal("literal path treated as a glob")
			}
			runGit(t, directory, "update-ref", "-d", "refs/git-age/original/HEAD")
			mustCommand(t, directory, "history", "purge", ".", "--yes")
			if output := runGit(t, directory, "ls-tree", "HEAD"); len(output) != 0 {
				t.Fatalf("root tree not empty: %s", output)
			}
			runGit(t, directory, "fsck", "--no-reflogs")
		})
	}
}

func TestHistoryPurgeRefusals(t *testing.T) {
	for _, scenario := range []string{"missing path", "outside repository", "dirty working tree", "shallow", "replace refs", "merge", "worktree", "broken output"} {
		t.Run(scenario, func(t *testing.T) {
			directory, _ := auditFixture(t)
			head := gitRevision(t, directory, "HEAD")
			args, want := []string{"history", "purge", "--yes", "secret.env"}, ""
			switch scenario {
			case "missing path":
				args = append(args, "absent")
				want = "no such path in local history"
			case "outside repository":
				args = append(args, "../outside")
				want = "outside"
			case "dirty working tree":
				writeFile(t, directory, "readme", "dirty\n")
				want = "uncommitted changes"
			case "shallow":
				if err := os.WriteFile(installGitPath(t, directory, "shallow"), []byte(head+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				want = "shallow clone"
			case "replace refs":
				runGit(t, directory, "update-ref", "refs/replace/"+head, gitRevision(t, directory, "HEAD~1"))
				want = "replace refs or grafts"
			case "merge":
				if err := os.WriteFile(installGitPath(t, directory, "MERGE_HEAD"), []byte(head+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				want = "merge is in progress"
			case "worktree":
				runGit(t, directory, "worktree", "add", "-q", "-b", "other", t.TempDir())
				want = "other worktrees"
			case "broken output":
				want = "broken output"
			}
			root := newRootCommand()
			var output bytes.Buffer
			root.SetOut(&output)
			root.SetErr(&output)
			if scenario == "broken output" {
				root.SetOut(cleanBrokenWriter{os.ErrClosed})
				want = os.ErrClosed.Error()
			}
			root.SetArgs(append([]string{"-C", directory}, args...))
			if err := root.Execute(); err == nil || !strings.Contains(err.Error(), want) || gitRevision(t, directory, "HEAD") != head {
				t.Fatalf("refusal: %v\n%s", err, &output)
			}
			if refs := runGit(t, directory, "for-each-ref", "refs/git-age/original/"); len(refs) != 0 {
				t.Fatalf("refusal created backup refs: %s", refs)
			}
		})
	}
}

func TestHistoryPurgeAllKeepsUnprotectedDirectoryReuse(t *testing.T) {
	directory, _ := auditFixture(t)
	writeFile(t, directory, "reused", "protected file\n")
	writeFile(t, directory, ".gitage", "[files]\nreused\n")
	runGit(t, directory, "add", ".")
	runGit(t, directory, "commit", "-qm", "protect reused file")
	runGit(t, directory, "rm", "-q", "reused")
	writeFile(t, directory, ".gitage", "[files]\n*.env\n")
	writeFile(t, directory, "reused/public", "unprotected directory content\n")
	runGit(t, directory, "add", ".")
	runGit(t, directory, "commit", "-qm", "reuse name as public directory")
	mustCommand(t, directory, "history", "purge", "--all", "--yes")
	if got := string(readFile(t, directory, "reused/public")); got != "unprotected directory content\n" {
		t.Fatalf("lost unprotected reused directory: %q", got)
	}
	if tree := runGit(t, directory, "ls-tree", "HEAD~1", "reused"); len(tree) != 0 {
		t.Fatalf("historical protected file remains: %s", tree)
	}
}

func TestHistoryPurgeRequiresTerminalOrYes(t *testing.T) {
	binary := buildGitAge(t)
	directory, _ := auditFixture(t)
	head := gitRevision(t, directory, "HEAD")
	output, err := exec.Command(binary, "-C", directory, "history", "purge", "secret.env").CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte("pass --yes")) || gitRevision(t, directory, "HEAD") != head {
		t.Fatalf("confirmation refusal: %v\n%s", err, output)
	}
}

func TestHistoryPurgeAllNoRules(t *testing.T) {
	directory, _ := auditFixture(t)
	// A fresh repository has neither commits nor rules.
	empty := t.TempDir()
	initKeygenRepo(t, empty)
	for _, root := range []string{empty, directory} {
		if root == directory {
			mustCommand(t, root, "history", "purge", "--yes", ".")
			runGit(t, root, "update-ref", "-d", "refs/git-age/original/refs/heads/master")
		}
		refs := runGit(t, root, "for-each-ref", "--format=%(refname) %(objectname)")
		objects := installSnapshot(t, installGitPath(t, root, "objects"))
		output := mustCommand(t, root, "history", "purge", "--all", "--yes")
		if !strings.Contains(output, "nothing to do") || !bytes.Equal(refs, runGit(t, root, "for-each-ref", "--format=%(refname) %(objectname)")) || !reflect.DeepEqual(objects, installSnapshot(t, installGitPath(t, root, "objects"))) {
			t.Fatalf("no-op changed repository: %s", output)
		}
	}
}
