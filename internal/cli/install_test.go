package cli

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestInstall(t *testing.T) {
	for _, scenario := range []string{"default", "subdirectory", "relative hooks path", "absolute hooks path", "linked worktree", "no rules"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n")
			writeStatusFile(t, directory, "sub/.keep", "")
			workingDirectory := directory
			if scenario == "linked worktree" {
				cleanGit(t, directory, "config", "user.name", "Test")
				cleanGit(t, directory, "config", "user.email", "test@example.com")
				cleanGit(t, directory, "config", "commit.gpgsign", "false")
				cleanGit(t, directory, "add", ".gitage")
				cleanGit(t, directory, "commit", "-qm", "rules")
				workingDirectory = filepath.Join(t.TempDir(), "linked")
				cleanGit(t, directory, "worktree", "add", "-qb", "linked", workingDirectory)
			} else if scenario == "subdirectory" {
				workingDirectory = filepath.Join(directory, "sub")
			} else if scenario == "no rules" {
				if err := os.Remove(filepath.Join(directory, ".gitage")); err != nil {
					t.Fatal(err)
				}
			}
			hooks := installGitPath(t, directory, "hooks")
			if scenario == "relative hooks path" {
				cleanGit(t, directory, "config", "core.hooksPath", "custom hooks")
				hooks = filepath.Join(directory, "custom hooks")
				workingDirectory = filepath.Join(directory, "sub")
			} else if scenario == "absolute hooks path" {
				hooks = filepath.Join(t.TempDir(), "custom hooks")
				cleanGit(t, directory, "config", "core.hooksPath", hooks)
			}
			beforeIndex := cleanGit(t, directory, "ls-files", "--stage", "-z")
			output, err := runInstall(workingDirectory, "--mode", "always-lock", "--unlock-after-commit")
			if err != nil || !strings.Contains(output, "Installed git-age hooks:") {
				t.Fatalf("install: %v, %s", err, output)
			}
			for _, event := range []string{"pre-commit", "post-commit", "pre-push", "post-checkout", "post-merge", "post-rewrite"} {
				path := filepath.Join(hooks, event)
				content, err := os.ReadFile(path)
				if err != nil || !bytes.Contains(content, []byte("# git-age managed "+event+" hook\n")) || !bytes.Contains(content, []byte("exec git age hook "+event)) {
					t.Fatalf("hook %s: %v, %q", event, err, content)
				}
				if runtime.GOOS != "windows" {
					info, err := os.Stat(path)
					if err != nil || info.Mode().Perm() != 0755 {
						t.Fatalf("hook permissions: %v, %v", info, err)
					}
				}
			}
			for key, want := range map[string]string{
				"age.hookMode": "always-lock", "age.unlockAfterCommit": "true",
				"diff.age.textconv": "git age textconv", "diff.age.cachetextconv": "false",
				"merge.age.name":   "git-age: merge decrypted",
				"merge.age.driver": "git age merge --path %P --marker-size %L %O %A %B",
				"filter.age.clean": "git age clean %f", "filter.age.smudge": "cat", "filter.age.required": "true",
			} {
				got := strings.TrimSpace(string(cleanGit(t, directory, "config", "--local", "--get", key)))
				if got != want {
					t.Errorf("%s: got %q, want %q", key, got, want)
				}
			}
			attributes := installGitPath(t, workingDirectory, "info/attributes")
			if _, err := os.Stat(attributes); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(beforeIndex, cleanGit(t, directory, "ls-files", "--stage", "-z")) {
				t.Fatal("install changed the index")
			}
		})
	}
}

func TestInstallAttributes(t *testing.T) {
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n/root.secret\nsecrets/\n/a/b.key\nsecret file\n\\!literal\n\\#literal\nspace\\ \ncontrol\x01name\n!public.env\n")
	writeStatusFile(t, directory, "nested [x]/.gitage", "[files]\n*.key\n/only.here\nrelative/path\n")
	writeStatusFile(t, directory, "ignored/.gitage", "[unknown]\n")
	writeStatusFile(t, directory, ".gitignore", "ignored/\n")
	if _, err := runInstall(directory); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path string
		want bool
	}{
		{"future.env", true}, {"sub/future.env", true}, {"root.secret", true}, {"sub/root.secret", false},
		{"secrets/new", true}, {"sub/secrets/new", true}, {"a/b.key", true}, {"sub/a/b.key", false},
		{"secret file", true}, {"sub/secret file/inside", true}, {"!literal", true}, {"#literal", true}, {"space ", true},
		{"nested [x]/new.key", true}, {"nested [x]/sub/new.key", true}, {"elsewhere/new.key", false},
		{"nested [x]/only.here", true}, {"nested [x]/sub/only.here", false},
		{"nested [x]/relative/path", true}, {"nested [x]/sub/relative/path", false},
		{"public.env", true}, // Attribute patterns over-match negations, like the previous installer.
		{"readme.txt", false},
	} {
		output := cleanGit(t, directory, "check-attr", "diff", "filter", "merge", "--", test.path)
		want := "unspecified"
		if test.want {
			want = "age"
		}
		for _, attribute := range []string{"diff", "filter", "merge"} {
			if !bytes.Contains(output, []byte(": "+attribute+": "+want+"\n")) {
				t.Errorf("%s: %s", test.path, output)
			}
		}
	}
	// NUL-delimited output checks control bytes without Git's display quoting.
	output := cleanGit(t, directory, "check-attr", "-z", "diff", "--", "control\x01name")
	if string(output) != "control\x01name\x00diff\x00age\x00" {
		t.Fatalf("control byte pattern: %q", output)
	}
}

func TestInstallGitIntegration(t *testing.T) {
	t.Setenv("GIT_AGE_KEY_FILE", "")
	t.Setenv("GIT_AGE_RECIPIENT", "")
	bin := filepath.Join(t.TempDir(), "bin with spaces")
	if err := os.MkdirAll(bin, 0755); err != nil {
		t.Fatal(err)
	}
	name := "git-age"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	executable := filepath.Join(bin, name)
	build := exec.Command("go", "build", "-o", executable, "./cmd/git-age")
	build.Dir = "../.."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	directory, identity, _ := cleanFixture(t, []byte("A=1\nB=1\nC=1\n"), false)
	cleanGit(t, directory, "branch", "ours")
	cleanGit(t, directory, "checkout", "-qb", "theirs")
	writeStatusFile(t, directory, "secret.env", string(encryptUnlockFixture(t, identity, "A=1\nB=1\nC=2\n", false)))
	cleanGit(t, directory, "add", "secret.env")
	cleanGit(t, directory, "commit", "-qm", "theirs")
	cleanGit(t, directory, "checkout", "-q", "ours")
	ours := encryptUnlockFixture(t, identity, "A=2\nB=1\nC=1\n", false)
	writeStatusFile(t, directory, "secret.env", string(ours))
	cleanGit(t, directory, "add", "secret.env")
	cleanGit(t, directory, "commit", "-qm", "ours")
	cleanGit(t, directory, "config", "diff.age.cachetextconv", "true")
	output, err := exec.Command(executable, "-C", directory, "install", "--mode=always-lock").CombinedOutput()
	if err != nil {
		t.Fatalf("install binary: %v, %s", err, output)
	}
	if text := cleanGit(t, directory, "cat-file", "--textconv", "HEAD:secret.env"); string(text) != "A=2\nB=1\nC=1\n" {
		t.Fatalf("installed diff driver: %q", text)
	}
	writeStatusFile(t, directory, "secret.env", "A=2\nB=1\nC=1\n")
	oid := strings.TrimSpace(string(cleanGit(t, directory, "rev-parse", "HEAD:secret.env")))
	cleanGit(t, directory, "update-index", "--cacheinfo", "100644,"+oid+",secret.env")
	if status := cleanGit(t, directory, "status", "--porcelain", "--", "secret.env"); len(status) != 0 {
		t.Fatalf("installed filter shows unchanged plaintext as modified: %s", status)
	}
	cleanGit(t, directory, "add", "secret.env")
	if staged := cleanGit(t, directory, "show", ":secret.env"); !bytes.Equal(staged, ours) {
		t.Fatal("installed filter did not reuse ciphertext")
	}
	writeStatusFile(t, directory, "secret.env", string(ours))
	cleanGit(t, directory, "add", "secret.env")
	// Hook policy handlers are a separate porting task; exercise the installed
	// merge driver with hooks disabled for this Git operation only.
	cleanGit(t, directory, "-c", "core.hooksPath="+t.TempDir(), "merge", "--no-edit", "theirs")
	assertCleanDecrypts(t, cleanGit(t, directory, "show", "HEAD:secret.env"), identity, []byte("A=2\nB=1\nC=2\n"))
	if _, err := runInstall(directory, "--no-diff", "--no-filter", "--no-merge"); err != nil {
		t.Fatal(err)
	}
	if text := cleanGit(t, directory, "cat-file", "--textconv", "HEAD:secret.env"); bytes.HasPrefix(text, []byte("A=2")) {
		t.Fatal("disabled diff still decrypts")
	}
}

func TestInstallHookEntrypoints(t *testing.T) {
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	if _, err := runInstall(directory); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	writeStatusFile(t, bin, "git-age", "#!/bin/sh\nprintf '%s\\n' \"$@\"\ncat\n")
	if err := os.Chmod(filepath.Join(bin, "git-age"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	writeStatusFile(t, directory, ".hook-input", "input\n")
	for _, test := range []struct {
		event, want string
		args        []string
	}{
		{"pre-commit", "hook\npre-commit\ninput\n", nil},
		{"pre-push", "hook\npre-push\nremote name\nssh://example/repo\ninput\n", []string{"remote name", "ssh://example/repo"}},
		{"post-checkout", "hook\npost-checkout\ninput\n", []string{"old", "new", "1"}},
		{"post-rewrite", "hook\npost-rewrite\ninput\n", []string{"rebase"}},
	} {
		args := append([]string{"-C", directory, "hook", "run", "--to-stdin=" + filepath.Join(directory, ".hook-input"), test.event, "--"}, test.args...)
		command := exec.Command("git", args...)
		output, err := command.CombinedOutput()
		if err != nil || string(output) != test.want {
			t.Fatalf("%s: %v, %q; want %q", test.event, err, output, test.want)
		}
	}
}

func TestInstallUpdateAndDisable(t *testing.T) {
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n")
	cleanGit(t, directory, "config", "age.hookMode", "abort")
	cleanGit(t, directory, "config", "age.unlockAfterCommit", "true")
	cleanGit(t, directory, "config", "age.keyFile", "keep.key")
	cleanGit(t, directory, "config", "age.recipient", "age1keep")
	attributes := installGitPath(t, directory, "info/attributes")
	writeStatusFile(t, filepath.Dir(attributes), "attributes", "# user prefix\r\n*.txt diff=custom\r\n")
	if runtime.GOOS != "windows" {
		if err := os.Chmod(attributes, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := runInstall(directory); err != nil {
		t.Fatal(err)
	}
	before := installSnapshot(t, directory)
	if _, err := runInstall(directory); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, installSnapshot(t, directory)) {
		t.Fatal("repeat install changed contents or modes")
	}
	file, err := os.OpenFile(attributes, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteString("*.md diff=markdown\r\n# user suffix\r\n")
	if err := errors.Join(writeErr, file.Close()); err != nil {
		t.Fatal(err)
	}
	writeStatusFile(t, directory, ".gitage", "[files]\n*.secret\n")
	if _, err := runInstall(directory, "--no-unlock-after-commit"); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(attributes)
	if err != nil || !bytes.HasPrefix(content, []byte("# user prefix\r\n*.txt diff=custom\r\n")) || !bytes.HasSuffix(content, []byte("*.md diff=markdown\r\n# user suffix\r\n")) || bytes.Contains(content, []byte("*.env")) || !bytes.Contains(content, []byte("*.secret")) {
		t.Fatalf("attribute update: %v, %q", err, content)
	}
	if mode := strings.TrimSpace(string(cleanGit(t, directory, "config", "age.hookMode"))); mode != "abort" {
		t.Fatalf("overwrote policy: %q", mode)
	}
	if unlock := strings.TrimSpace(string(cleanGit(t, directory, "config", "age.unlockAfterCommit"))); unlock != "false" {
		t.Fatalf("unlock flag: %q", unlock)
	}
	if _, err := runInstall(directory, "--no-diff", "--no-merge", "--no-filter"); err != nil {
		t.Fatal(err)
	}
	content, err = os.ReadFile(attributes)
	want := "# user prefix\r\n*.txt diff=custom\r\n*.md diff=markdown\r\n# user suffix\r\n"
	if err != nil || string(content) != want {
		t.Fatalf("removed user attributes: %v, %q", err, content)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(attributes)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("changed attribute permissions: %v, %v", info, err)
		}
	}
	for _, key := range []string{"diff.age.textconv", "merge.age.name", "merge.age.driver", "filter.age.clean", "filter.age.smudge", "filter.age.required"} {
		if err := exec.Command("git", "-C", directory, "config", "--local", "--get", key).Run(); err == nil {
			t.Errorf("did not unset %s", key)
		}
	}
	for _, event := range []string{"post-checkout", "post-rewrite"} {
		if _, err := os.Stat(filepath.Join(installGitPath(t, directory, "hooks"), event)); !os.IsNotExist(err) {
			t.Fatalf("did not remove %s: %v", event, err)
		}
	}
	for _, key := range []string{"age.keyFile", "age.recipient", "age.hookMode", "age.unlockAfterCommit"} {
		cleanGit(t, directory, "config", "--local", "--get", key)
	}
	hooks := installGitPath(t, directory, "hooks")
	writeStatusFile(t, hooks, "post-checkout", "#!/bin/sh\n# other tool\n")
	if _, err := runInstall(directory, "--no-diff", "--no-merge", "--no-filter"); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(filepath.Join(hooks, "post-checkout")); err != nil || string(content) != "#!/bin/sh\n# other tool\n" {
		t.Fatal("removed an unrelated sync hook")
	}
}

func TestInstallDriverFlags(t *testing.T) {
	for _, test := range []struct {
		name                string
		args                []string
		diff, merge, filter bool
	}{
		{"no diff", []string{"--no-diff"}, false, true, true},
		{"no merge", []string{"--no-merge"}, true, false, true},
		{"no filter", []string{"--no-filter"}, true, true, false},
		{"only diff", []string{"--merge=false", "--filter=false"}, true, false, false},
		{"only merge", []string{"--diff=false", "--filter=false"}, false, true, false},
		{"only filter", []string{"--diff=false", "--merge=false"}, false, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n")
			if _, err := runInstall(directory); err != nil {
				t.Fatal(err)
			}
			if _, err := runInstall(directory, test.args...); err != nil {
				t.Fatal(err)
			}
			for key, enabled := range map[string]bool{
				"diff.age.textconv": test.diff, "diff.age.cachetextconv": true,
				"merge.age.driver": test.merge, "merge.age.name": test.merge,
				"filter.age.clean": test.filter, "filter.age.smudge": test.filter, "filter.age.required": test.filter,
			} {
				err := exec.Command("git", "-C", directory, "config", "--local", "--get", key).Run()
				if (err == nil) != enabled {
					t.Errorf("%s enabled=%v: %v", key, enabled, err)
				}
			}
			for _, event := range []string{"post-checkout", "post-rewrite", "post-merge"} {
				if _, err := os.Stat(filepath.Join(installGitPath(t, directory, "hooks"), event)); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestInstallDisablesInheritedDrivers(t *testing.T) {
	bin := t.TempDir()
	name := "git-age"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	build := exec.Command("go", "build", "-o", filepath.Join(bin, name), "./cmd/git-age")
	build.Dir = "../.."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, disabled := range []string{"diff", "filter", "merge"} {
		t.Run(disabled, func(t *testing.T) {
			t.Setenv("GIT_AGE_KEY_FILE", "")
			t.Setenv("GIT_AGE_RECIPIENT", "")
			directory, identity, ciphertext := cleanFixture(t, []byte("original\n"), false)
			plaintext := "original\n"
			if disabled == "merge" {
				cleanGit(t, directory, "branch", "ours")
				cleanGit(t, directory, "checkout", "-qb", "theirs")
				writeStatusFile(t, directory, "secret.env", string(encryptUnlockFixture(t, identity, "theirs\n", false)))
				cleanGit(t, directory, "add", "secret.env")
				cleanGit(t, directory, "commit", "-qm", "theirs")
				cleanGit(t, directory, "checkout", "-q", "ours")
				plaintext = "ours\n"
				ciphertext = encryptUnlockFixture(t, identity, plaintext, false)
				writeStatusFile(t, directory, "secret.env", string(ciphertext))
				cleanGit(t, directory, "add", "secret.env")
				cleanGit(t, directory, "commit", "-qm", "ours")
			}
			globalDirectory := t.TempDir()
			global := "[diff \"age\"]\ntextconv = printf inherited\ncachetextconv = true\n[filter \"age\"]\nclean = printf inherited\nsmudge = printf inherited\nrequired = true\n[merge]\ndefault = age\n[merge \"age\"]\ndriver = printf inherited\n"
			writeStatusFile(t, globalDirectory, "gitconfig", global)
			t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(globalDirectory, "gitconfig"))
			if _, err := runInstall(directory, "--no-"+disabled); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			if code := Run([]string{"-C", directory, "hook", "post-checkout"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
				t.Fatalf("attribute refresh: exit %d, %s", code, &stderr)
			}
			wantAttribute := "unset"
			if disabled == "diff" {
				wantAttribute = "unspecified"
			}
			if got := cleanGit(t, directory, "check-attr", disabled, "--", "secret.env"); !bytes.Contains(got, []byte(": "+disabled+": "+wantAttribute+"\n")) {
				t.Fatalf("disabled driver reactivated: %s", got)
			}
			if got := cleanGit(t, directory, "config", "--bool", "--get", "diff.age.cachetextconv"); string(got) != "false\n" {
				t.Fatalf("inherited plaintext cache remains enabled: %q", got)
			}
			converted := cleanGit(t, directory, "cat-file", "--textconv", "HEAD:secret.env")
			if disabled == "diff" {
				if !bytes.Equal(converted, ciphertext) {
					t.Fatalf("disabled textconv ran: %q", converted)
				}
			} else if string(converted) != plaintext {
				t.Fatalf("enabled textconv failed: %q", converted)
			}
			writeStatusFile(t, directory, "secret.env", plaintext)
			cleanGit(t, directory, "add", "secret.env")
			staged := cleanGit(t, directory, "show", ":secret.env")
			if disabled == "filter" {
				if string(staged) != plaintext {
					t.Fatalf("disabled clean filter ran: %q", staged)
				}
			} else if !bytes.Equal(staged, ciphertext) {
				t.Fatal("enabled filter failed to reuse ciphertext")
			}
			if disabled == "merge" {
				noHooks := t.TempDir()
				cleanGit(t, directory, "-c", "core.hooksPath="+noHooks, "reset", "--hard", "HEAD")
				output, err := exec.Command("git", "-C", directory, "-c", "core.hooksPath="+noHooks, "merge", "--no-edit", "theirs").CombinedOutput()
				if err == nil || !bytes.Contains(output, []byte("CONFLICT")) || bytes.Contains(output, []byte("inherited")) {
					t.Fatalf("disabled merge driver ran: %v, %s", err, output)
				}
			}
			unchanged, err := os.ReadFile(filepath.Join(globalDirectory, "gitconfig"))
			if err != nil || string(unchanged) != global {
				t.Fatal("install changed global configuration")
			}
		})
	}
}

func TestInstallDryRunAndPreflight(t *testing.T) {
	for _, scenario := range []string{"dry run", "disable dry run", "existing hook", "symlink hook", "directory hook", "malformed rules", "broken attributes", "symlink attributes", "disabled hooks"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n")
			hooks := installGitPath(t, directory, "hooks")
			attributes := installGitPath(t, directory, "info/attributes")
			args, want := []string{"--mode", "always-lock"}, ""
			switch scenario {
			case "dry run":
				args, want = append(args, "-n"), "would install git-age pre-commit hook"
			case "disable dry run":
				if _, err := runInstall(directory); err != nil {
					t.Fatal(err)
				}
				args, want = append(args, "-n", "--no-diff", "--no-merge", "--no-filter"), "would remove git-age post-checkout hook"
			case "existing hook":
				writeStatusFile(t, hooks, "post-rewrite", "#!/bin/sh\n# another tool\n")
			case "symlink hook":
				writeStatusFile(t, directory, "target", "# git-age managed post-rewrite hook\n")
				if err := os.MkdirAll(hooks, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(directory, "target"), filepath.Join(hooks, "post-rewrite")); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			case "directory hook":
				if err := os.MkdirAll(filepath.Join(hooks, "post-rewrite"), 0755); err != nil {
					t.Fatal(err)
				}
			case "malformed rules":
				writeStatusFile(t, directory, "sub/.gitage", "[unknown]\n")
			case "broken attributes":
				writeStatusFile(t, filepath.Dir(attributes), "attributes", "# BEGIN git-age (generated from .gitage; do not edit)\n# user data\n")
			case "symlink attributes":
				writeStatusFile(t, directory, "target", "# user data\n")
				if err := os.MkdirAll(filepath.Dir(attributes), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(directory, "target"), attributes); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			case "disabled hooks":
				cleanGit(t, directory, "config", "core.hooksPath", os.DevNull)
			}
			before := installSnapshot(t, directory)
			output, err := runInstall(directory, args...)
			if want != "" {
				if err != nil || !strings.Contains(output, want) {
					t.Fatalf("dry run: %v, %q", err, output)
				}
			} else if err == nil {
				t.Fatal("expected preflight failure")
			}
			if !reflect.DeepEqual(before, installSnapshot(t, directory)) {
				t.Fatal("dry run or failed preflight changed repository files")
			}
		})
	}
	for _, args := range [][]string{{"extra"}, {"--mode", "invalid"}} {
		var stdout, stderr bytes.Buffer
		if code := Run(append([]string{"install"}, args...), &stdout, &stderr); code != 2 || stdout.Len() != 0 {
			t.Fatalf("args %v: exit %d, output %q", args, code, &stdout)
		}
	}
	if _, err := runInstall(t.TempDir()); err == nil {
		t.Fatal("install worked outside Git")
	}
}

func runInstall(directory string, args ...string) (string, error) {
	var output bytes.Buffer
	root := newRootCommand()
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs(append([]string{"-C", directory, "install"}, args...))
	err := root.Execute()
	return output.String(), err
}

func installGitPath(t *testing.T, directory, name string) string {
	t.Helper()
	return filepath.FromSlash(strings.TrimSpace(string(cleanGit(t, directory, "rev-parse", "--path-format=absolute", "--git-path", name))))
}

func installSnapshot(t *testing.T, directory string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		content := ""
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			content = string(data)
		} else if info.Mode()&os.ModeSymlink != 0 {
			content, err = os.Readlink(path)
			if err != nil {
				return err
			}
		}
		files[path] = info.Mode().String() + "\n" + content
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}
