package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	for _, scenario := range []string{"plaintext", "locked", "armored", "no matches", "outside Git", "subdirectory", "dry run", "no rules", "invalid rules"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			writeFile(t, directory, ".gitage", "[files]\n*.env\n")
			writeFile(t, directory, "a.env", "secret")
			writeFile(t, directory, "z.env", "secret")
			writeFile(t, directory, "notes.txt", "not protected")
			code, diagnostic := 1, "protected files are currently unlocked:\n\n  a.env\n  z.env\n"
			var args []string
			switch scenario {
			case "locked", "armored":
				identity := newIdentity(t)
				content := encryptFixture(t, identity.Recipient(), "secret", scenario == "armored")
				writeFile(t, directory, "a.env", string(content))
				writeFile(t, directory, "z.env", string(content))
				code, diagnostic = 0, ""
			case "no matches":
				writeFile(t, directory, ".gitage", "[files]\n*.secret\n")
				code, diagnostic = 0, ""
			case "outside Git":
				directory = t.TempDir()
				writeFile(t, directory, ".gitage", "[files]\n*.env\n")
				writeFile(t, directory, "a.env", "secret")
				diagnostic = "protected files are currently unlocked:\n\n  a.env\n"
			case "subdirectory":
				writeFile(t, directory, "sub/b.env", "secret")
				directory = filepath.Join(directory, "sub")
				diagnostic = "protected files are currently unlocked:\n\n  b.env\n"
			case "dry run":
				args = []string{"-n"}
			case "no rules":
				if err := os.Remove(filepath.Join(directory, ".gitage")); err != nil {
					t.Fatal(err)
				}
				code, diagnostic = 2, "no .gitage files found"
			case "invalid rules":
				writeFile(t, directory, ".gitage", "[unknown]\n")
				code, diagnostic = 2, "unknown section"
			}
			got, output, stderr := runCheck(directory, args...)
			if got != code || output != "" || !strings.Contains(stderr, diagnostic) {
				t.Fatalf("exit %d, output %q, stderr %q; want %d, %q", got, output, stderr, code, diagnostic)
			}
			if code == 0 {
				got, output, stderr = runCheck(directory, "-v")
				if got != 0 || output != "git-age: protected working-tree files are locked\n" || stderr != "" {
					t.Fatalf("verbose: exit %d, output %q, stderr %q", got, output, stderr)
				}
			}
		})
	}
}

func TestCheckUnknown(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires Unix permission enforcement")
	}
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	writeFile(t, directory, ".gitage", "[files]\n*.env\n")
	writeFile(t, directory, "unreadable.env", "secret")
	path := filepath.Join(directory, "unreadable.env")
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(path, 0600) })
	code, output, stderr := runCheck(directory)
	if code != 1 || output != "" || stderr != "git-age: could not determine state of protected files:\n\n  unreadable.env\n" {
		t.Fatalf("exit %d, output %q, stderr %q", code, output, stderr)
	}
}

func TestCheckCached(t *testing.T) {
	for _, scenario := range []string{"staged plaintext", "staged encrypted", "staged rules", "unstaged rules", "nested negation", "unchanged plaintext", "ignored tracked file", "private key", "local key", "protected key", "allow private key", "case insensitive", "subdirectory", "missing working file", "symlink"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			t.Setenv("GIT_AGE_ALLOW_PRIVATE_KEYS", "")
			t.Setenv("GIT_AGE_ALLOW_REMOVE", "")
			writeFile(t, directory, ".gitage", "[files]\n*.env\n")
			writeFile(t, directory, "secret.env", "secret")
			runGit(t, directory, "add", ".gitage", "secret.env")
			code, diagnostic := 1, "protected files are staged as plaintext"
			switch scenario {
			case "staged plaintext", "staged encrypted":
				identity := newIdentity(t)
				writeFile(t, directory, "secret.env", string(encryptFixture(t, identity.Recipient(), "secret", false)))
				if scenario == "staged encrypted" {
					runGit(t, directory, "add", "secret.env")
					writeFile(t, directory, "secret.env", "secret")
					code, diagnostic = 0, ""
				}
			case "staged rules":
				writeFile(t, directory, ".gitage", "[files]\n*.txt\n")
			case "unstaged rules":
				writeFile(t, directory, ".gitage", "[files]\n*.txt\n")
				runGit(t, directory, "add", ".gitage")
				writeFile(t, directory, ".gitage", "[files]\n*.env\n")
				code, diagnostic = 0, ""
			case "nested negation":
				writeFile(t, directory, ".gitage", "[files]\n*.txt\n")
				writeFile(t, directory, "sub/.gitage", "[files]\n!public.txt\n*.env\n")
				writeFile(t, directory, "sub/public.txt", "public")
				runGit(t, directory, "add", ".gitage", "sub")
				code, diagnostic = 0, ""
			case "unchanged plaintext":
				runGit(t, directory, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "baseline")
				writeFile(t, directory, "notes.txt", "new")
				runGit(t, directory, "add", "notes.txt")
				code, diagnostic = 0, ""
			case "ignored tracked file":
				writeFile(t, directory, ".gitignore", "secret.env\n")
			case "private key", "local key", "protected key", "allow private key":
				writeFile(t, directory, ".gitage", "[files]\n*.protected\n")
				path, content := "private.txt", "AGE-SECRET-KEY-1TEST"
				if scenario == "local key" {
					path, content = ".gitage.key", "not even a key"
				}
				if scenario == "protected key" {
					path = "private.protected"
				} else {
					diagnostic = "refusing to commit private age keys"
				}
				writeFile(t, directory, path, content)
				runGit(t, directory, "add", "-f", ".gitage", path)
				if scenario == "allow private key" {
					t.Setenv("GIT_AGE_ALLOW_PRIVATE_KEYS", "yes")
					code, diagnostic = 0, ""
				}
			case "case insensitive":
				runGit(t, directory, "config", "core.ignoreCase", "true")
				writeFile(t, directory, ".gitage", "[files]\n*.ENV\n")
				runGit(t, directory, "add", ".gitage")
			case "subdirectory":
				if err := os.Mkdir(filepath.Join(directory, "sub"), 0700); err != nil {
					t.Fatal(err)
				}
				directory = filepath.Join(directory, "sub")
			case "missing working file":
				if err := os.Remove(filepath.Join(directory, "secret.env")); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				oid := strings.TrimSpace(string(runGit(t, directory, "rev-parse", ":secret.env")))
				runGit(t, directory, "update-index", "--cacheinfo", "120000,"+oid+",secret.env")
				code, diagnostic = 0, ""
			}
			got, output, stderr := runCheck(directory, "--cached")
			if got != code || output != "" || !strings.Contains(stderr, diagnostic) || (code == 0 && stderr != "") {
				t.Fatalf("exit %d, output %q, stderr %q; want %d, %q", got, output, stderr, code, diagnostic)
			}
			if code == 0 {
				got, output, stderr = runCheck(directory, "--cached", "-v")
				if got != 0 || output != "git-age: staged protected files are locked\n" || stderr != "" {
					t.Fatalf("verbose: exit %d, output %q, stderr %q", got, output, stderr)
				}
			}
		})
	}
}

func TestCheckCachedRemovedRules(t *testing.T) {
	for _, scenario := range []string{"removed", "moved", "allowed", "symlink", "last rule", "allow last rule"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			t.Setenv("GIT_AGE_ALLOW_REMOVE", "")
			writeFile(t, directory, ".gitage", "[files]\n*.env\n")
			writeFile(t, directory, "sub/.gitage", "[files]\n*.env\n")
			runGit(t, directory, "add", ".")
			runGit(t, directory, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "rules")
			if scenario == "symlink" {
				oid := strings.TrimSpace(string(runGit(t, directory, "rev-parse", ":sub/.gitage")))
				runGit(t, directory, "update-index", "--cacheinfo", "120000,"+oid+",sub/.gitage")
			} else if scenario == "moved" {
				runGit(t, directory, "mv", "sub/.gitage", "sub/moved")
			} else {
				runGit(t, directory, "rm", "sub/.gitage")
			}
			if scenario == "last rule" || scenario == "allow last rule" {
				runGit(t, directory, "rm", ".gitage")
			}
			if scenario == "allowed" || scenario == "allow last rule" {
				t.Setenv("GIT_AGE_ALLOW_REMOVE", "1")
			}
			code, output, stderr := runCheck(directory, "--cached")
			if scenario == "allowed" {
				if code != 0 || output != "" || stderr != "" {
					t.Fatalf("exit %d, output %q, stderr %q", code, output, stderr)
				}
			} else if scenario == "allow last rule" {
				if code != 2 || !strings.Contains(stderr, "no .gitage files staged") {
					t.Fatalf("exit %d, stderr %q", code, stderr)
				}
			} else if code != 1 || !strings.Contains(stderr, "git restore --staged --worktree -- ") || !strings.Contains(stderr, "sub/.gitage") {
				t.Fatalf("exit %d, stderr %q", code, stderr)
			}
		})
	}
}

func TestCommandsRequireWorktree(t *testing.T) {
	for _, test := range []struct {
		command string
		args    []string
		want    string
	}{
		{"install", nil, "install"},
		{"uninstall", nil, "uninstall"},
		{"check", []string{"--cached"}, "check --cached"},
		{"hook", []string{"pre-push", "origin", "url"}, "pre-push"},
	} {
		t.Run(test.want, func(t *testing.T) {
			output, err := runCommand(t.TempDir(), test.command, test.args...)
			if err == nil || err.Error() != test.want+" requires a Git worktree" || output != "" {
				t.Fatalf("outside Git: output %q, error %v", output, err)
			}
		})
	}
}

func TestCheckCachedErrors(t *testing.T) {
	for _, scenario := range []string{"outside Git", "no staged rules", "malformed staged rules", "unmerged", "unexpected argument"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			var args []string
			if scenario != "outside Git" {
				initKeygenRepo(t, directory)
				writeFile(t, directory, ".gitage", "[files]\n*.env\n")
				if scenario == "malformed staged rules" {
					writeFile(t, directory, ".gitage", "[typo]\n")
				}
				if scenario != "no staged rules" {
					runGit(t, directory, "add", ".gitage")
				}
				if scenario == "unmerged" {
					oid := strings.TrimSpace(string(runGit(t, directory, "rev-parse", ":.gitage")))
					cmd := exec.Command("git", "-C", directory, "update-index", "--index-info")
					cmd.Stdin = strings.NewReader("0 " + strings.Repeat("0", 40) + "\t.gitage\n100644 " + oid + " 1\t.gitage\n")
					if output, err := cmd.CombinedOutput(); err != nil {
						t.Fatalf("update-index: %v\n%s", err, output)
					}
				}
			}
			if scenario == "unexpected argument" {
				args = []string{"secret.env"}
			}
			code, output, stderr := runCheck(directory, append([]string{"--cached"}, args...)...)
			if code != 2 || output != "" || stderr == "" {
				t.Fatalf("exit %d, output %q, stderr %q", code, output, stderr)
			}
		})
	}
}

func TestCheckReadOnly(t *testing.T) {
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	writeFile(t, directory, ".gitage", "[files]\n*.env\n")
	writeFile(t, directory, "secret.env", "secret")
	runGit(t, directory, "add", ".")
	snapshot := func() map[string]string {
		files := map[string]string{}
		err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			files[path] = string(content) + info.Mode().String() + info.ModTime().String()
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return files
	}
	before := snapshot()
	for _, args := range [][]string{nil, {"--cached"}, {"--cached", "-n"}} {
		if code, _, stderr := runCheck(directory, args...); code != 1 {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
	}
	if !reflect.DeepEqual(before, snapshot()) {
		t.Fatal("check changed the repository")
	}
}

func runCheck(directory string, args ...string) (int, string, string) {
	var output, stderr bytes.Buffer
	code := Run(append([]string{"-C", directory, "check"}, args...), &output, &stderr)
	return code, output.String(), stderr.String()
}
