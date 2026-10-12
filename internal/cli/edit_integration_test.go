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
		assertNoEditCopies(t, directory)
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

func TestEditReportsEditorExitStatus(t *testing.T) {
	for _, source := range []string{"GIT_EDITOR", "EDITOR"} {
		t.Run(source, func(t *testing.T) {
			isolateHookEnvironment(t)
			directory, _, ciphertext := cleanFixture(t, []byte("original\n"), false)
			for _, name := range []string{"GIT_EDITOR", "VISUAL"} {
				t.Setenv(name, "")
				if err := os.Unsetenv(name); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("EDITOR", "sh -c 'exit 7'")
			if source == "GIT_EDITOR" {
				t.Setenv("GIT_EDITOR", "sh -c 'exit 7'")
			}
			var stdout, stderr bytes.Buffer
			if code := Run([]string{"-C", directory, "edit", "secret.env"}, &stdout, &stderr); code != 7 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "editor: exit status 7; secret.env was not changed") {
				t.Fatalf("editor failure: exit %d, stdout %q, stderr %q", code, &stdout, &stderr)
			}
			if !bytes.Equal(ciphertext, readFile(t, directory, "secret.env")) {
				t.Fatal("failed editor changed ciphertext")
			}
			assertNoEditCopies(t, directory)
		})
	}
}

func TestEditRoundTripEditor(t *testing.T) {
	directory := os.Getenv("GIT_AGE_TEST_EDIT_REPO")
	if directory == "" {
		return
	}
	path := os.Args[len(os.Args)-1]
	gitDir, err := exec.Command("git", "-C", directory, "rev-parse", "--absolute-git-dir").Output()
	if err != nil {
		t.Fatal(err)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(filepath.Dir(path)))
	expected, expectedErr := filepath.EvalSymlinks(filepath.FromSlash(strings.TrimSpace(string(gitDir))))
	if err != nil || expectedErr != nil || parent != expected {
		t.Fatalf("editor plaintext was outside Git metadata: %s, %v, %v", path, err, expectedErr)
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
