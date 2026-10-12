package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestEditReusesCommittedCiphertext(t *testing.T) {
	isolateHookEnvironment(t)
	directory, identity, ciphertext := cleanFixture(t, []byte("original\n"), false)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_EDITOR", "'"+strings.ReplaceAll(filepath.ToSlash(executable), "'", `'"'"'`)+"' -test.run=^TestEditRoundTripEditor$ --")
	t.Setenv("GIT_AGE_TEST_EDIT_REPO", directory)
	scratch := t.TempDir()
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(name, scratch)
	}
	for _, test := range []struct{ before, after string }{{"original\n", "edited\n"}, {"edited\n", "original\n"}} {
		t.Setenv("GIT_AGE_TEST_EDIT_BEFORE", test.before)
		t.Setenv("GIT_AGE_TEST_EDIT_AFTER", test.after)
		t.Setenv("GIT_AGE_TEST_EDIT_STATUS", string(runGit(t, directory, "status", "--porcelain", "--untracked-files=all")))
		mustCommand(t, directory, "edit", "secret.env")
		assertDecrypts(t, readFile(t, directory, "secret.env"), identity, []byte(test.after))
		if entries, err := os.ReadDir(scratch); err != nil || len(entries) != 0 {
			t.Fatalf("decrypted copies left behind: %v, %v", entries, err)
		}
	}
	if !bytes.Equal(ciphertext, readFile(t, directory, "secret.env")) {
		t.Fatal("editing back did not reuse committed ciphertext")
	}
	runGit(t, directory, "diff", "--quiet", "--", "secret.env")
}

func TestEditRoundTripEditor(t *testing.T) {
	directory := os.Getenv("GIT_AGE_TEST_EDIT_REPO")
	if directory == "" {
		return
	}
	path := os.Args[len(os.Args)-1]
	relative, err := filepath.Rel(directory, path)
	if err != nil || relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		t.Fatalf("editor plaintext was inside repository: %s, %v", path, err)
	}
	if plaintext, err := os.ReadFile(path); err != nil || string(plaintext) != os.Getenv("GIT_AGE_TEST_EDIT_BEFORE") {
		t.Fatalf("editor copy: %q, %v", plaintext, err)
	}
	status, err := exec.Command("git", "-C", directory, "status", "--porcelain", "--untracked-files=all").CombinedOutput()
	if err != nil || string(status) != os.Getenv("GIT_AGE_TEST_EDIT_STATUS") {
		t.Fatalf("editor copy appeared in Git status: %v\n%s", err, status)
	}
	if err := os.WriteFile(path, []byte(os.Getenv("GIT_AGE_TEST_EDIT_AFTER")), 0600); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}
