package repository

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEditPlaintextLocation(t *testing.T) {
	for _, scenario := range []string{"Git", "linked worktree", "outside Git"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
			t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
			root := t.TempDir()
			if scenario != "outside Git" {
				if output, err := exec.Command("git", "-C", root, "-c", "init.templateDir=", "init", "-q").CombinedOutput(); err != nil {
					t.Fatalf("init: %v, %s", err, output)
				}
			}
			if scenario == "linked worktree" {
				if output, err := exec.Command("git", "-C", root, "-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", "initial").CombinedOutput(); err != nil {
					t.Fatalf("initial commit: %v, %s", err, output)
				}
				linked := filepath.Join(t.TempDir(), "linked")
				if output, err := exec.Command("git", "-C", root, "worktree", "add", "-qb", "linked", linked).CombinedOutput(); err != nil {
					t.Fatalf("worktree: %v, %s", err, output)
				}
				root = linked
			}
			parent := root
			if scenario != "outside Git" {
				var err error
				parent, err = gitPath(root, "")
				if err != nil {
					t.Fatal(err)
				}
			}
			var copyPath string
			content, err := editPlaintext(root, filepath.Join(root, "secret.env"), []byte("original"), func(path string) error {
				copyPath = path
				got, err := filepath.EvalSymlinks(filepath.Dir(filepath.Dir(path)))
				want, wantErr := filepath.EvalSymlinks(parent)
				if err != nil || wantErr != nil || got != want || !strings.HasPrefix(filepath.Base(filepath.Dir(path)), "git-age-edit-") {
					t.Fatalf("wrong private directory: %s, %v, %v", path, err, wantErr)
				}
				for _, private := range []string{path, filepath.Dir(path)} {
					info, err := os.Stat(private)
					if err != nil || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
						t.Fatalf("non-private copy: %s, %v, %v", private, info, err)
					}
				}
				return os.WriteFile(path, []byte("edited"), 0600)
			})
			if err != nil || string(content) != "edited" {
				t.Fatalf("edit: %q, %v", content, err)
			}
			if _, err := os.Stat(filepath.Dir(copyPath)); !os.IsNotExist(err) {
				t.Fatalf("private directory remains: %v", err)
			}
		})
	}
}

func TestWipePlaintextCopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.env")
	secret := bytes.Repeat([]byte("secret"), 10000)
	if err := os.WriteFile(path, secret, 0600); err != nil {
		t.Fatal(err)
	}
	if err := wipePlaintextCopy(path); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(content, make([]byte, len(secret))) {
		t.Fatalf("copy was not overwritten before removal: %v", err)
	}
}
