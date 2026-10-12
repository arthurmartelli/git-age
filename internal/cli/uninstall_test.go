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

func TestUninstall(t *testing.T) {
	for _, scenario := range []string{"default", "subdirectory", "relative hooks path", "absolute hooks path", "linked worktree", "missing rules", "malformed rules"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			writeFile(t, directory, ".gitage", "[files]\n*.env\n")
			workingDirectory := directory
			if scenario == "linked worktree" {
				runGit(t, directory, "config", "user.name", "Test")
				runGit(t, directory, "config", "user.email", "test@example.com")
				runGit(t, directory, "config", "commit.gpgsign", "false")
				runGit(t, directory, "add", ".gitage")
				runGit(t, directory, "commit", "-qm", "rules")
				workingDirectory = filepath.Join(t.TempDir(), "linked")
				runGit(t, directory, "worktree", "add", "-qb", "linked", workingDirectory)
			} else if scenario == "relative hooks path" {
				runGit(t, directory, "config", "core.hooksPath", "custom hooks")
			} else if scenario == "absolute hooks path" {
				runGit(t, directory, "config", "core.hooksPath", filepath.Join(t.TempDir(), "custom hooks"))
			}
			attributes := installGitPath(t, workingDirectory, "info/attributes")
			prefix, suffix := "# user prefix\r\n*.txt diff=custom\r\n", "*.md diff=markdown\r\n# user suffix\r\n"
			writeFile(t, filepath.Dir(attributes), "attributes", prefix)
			if _, err := runCommand(workingDirectory, "install", "--hook-mode=always-lock", "--unlock-after-commit"); err != nil {
				t.Fatal(err)
			}
			content, err := os.ReadFile(attributes)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(attributes, append(content, []byte(suffix)...), 0644); err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" {
				if err := os.Chmod(attributes, 0600); err != nil {
					t.Fatal(err)
				}
			}
			preserved := map[string]string{
				"age.keyFile": "keep.key", "age.recipient": "age1keep", "age.trustedRecipients": "trusted",
				"age.custom": "keep", "diff.age.custom": "keep", "diff.other.textconv": "cat",
				"merge.other.driver": "true", "filter.other.clean": "cat",
			}
			for key, value := range preserved {
				runGit(t, directory, "config", key, value)
			}
			// Duplicate values and valueless settings must also be removed.
			runGit(t, directory, "config", "--add", "age.hookMode", "abort")
			config := installGitPath(t, workingDirectory, "config")
			file, err := os.OpenFile(config, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, writeErr := file.WriteString("\n[diff \"age\"]\ntextconv\n")
			closeErr := file.Close()
			if writeErr != nil || closeErr != nil {
				t.Fatalf("config: %v, %v", writeErr, closeErr)
			}
			writeFile(t, workingDirectory, "locked.env", "age-encryption.org/v1\nciphertext\n")
			writeFile(t, workingDirectory, "unlocked.env", "secret\n")
			writeFile(t, workingDirectory, ".gitage.key", "private key\n")
			if scenario == "missing rules" {
				if err := os.Remove(filepath.Join(workingDirectory, ".gitage")); err != nil {
					t.Fatal(err)
				}
			} else if scenario == "malformed rules" {
				writeFile(t, workingDirectory, ".gitage", "[unknown]\n")
			}
			beforeIndex := runGit(t, workingDirectory, "ls-files", "--stage", "-z")
			beforeFiles := map[string][]byte{}
			for _, name := range []string{"locked.env", "unlocked.env", ".gitage", ".gitage.key"} {
				data, err := os.ReadFile(filepath.Join(workingDirectory, name))
				if err == nil {
					beforeFiles[name] = data
				} else if !os.IsNotExist(err) {
					t.Fatal(err)
				}
			}
			hooks := installGitPath(t, workingDirectory, "hooks")
			if scenario == "subdirectory" || scenario == "relative hooks path" {
				writeFile(t, directory, "sub/.keep", "")
				workingDirectory = filepath.Join(directory, "sub")
			}
			output, err := runCommand(workingDirectory, "uninstall")
			if err != nil || !strings.Contains(output, "uninstalled Git integration") {
				t.Fatalf("uninstall: %v, %s", err, output)
			}
			keptConfig := "Kept user Git config: age.keyFile, age.recipient, age.trustedRecipients\n"
			if !strings.Contains(output, keptConfig) {
				t.Fatalf("missing kept config: %q", output)
			}
			for _, event := range []string{"pre-commit", "post-commit", "pre-push", "post-checkout", "post-merge", "post-rewrite"} {
				if _, err := os.Lstat(filepath.Join(hooks, event)); !os.IsNotExist(err) {
					t.Errorf("hook %s remains: %v", event, err)
				}
			}
			for _, key := range []string{"age.hookMode", "age.unlockAfterCommit", "diff.age.textconv", "diff.age.cachetextconv", "merge.age.name", "merge.age.driver", "filter.age.clean", "filter.age.smudge", "filter.age.required"} {
				if err := exec.Command("git", "-C", directory, "config", "--local", "--get-all", key).Run(); err == nil {
					t.Errorf("config %s remains", key)
				}
			}
			for key, want := range preserved {
				if got := strings.TrimSpace(string(runGit(t, directory, "config", "--local", "--get", key))); got != want {
					t.Errorf("%s: got %q, want %q", key, got, want)
				}
			}
			content, err = os.ReadFile(attributes)
			if err != nil || string(content) != prefix+suffix {
				t.Fatalf("user attributes changed: %v, %q", err, content)
			}
			if runtime.GOOS != "windows" {
				info, err := os.Stat(attributes)
				if err != nil || info.Mode().Perm() != 0600 {
					t.Fatalf("attribute permissions: %v, %v", info, err)
				}
			}
			if !bytes.Equal(beforeIndex, runGit(t, workingDirectory, "ls-files", "--stage", "-z")) {
				t.Fatal("uninstall changed the index")
			}
			fileRoot := directory
			if scenario == "linked worktree" {
				fileRoot = workingDirectory
			}
			for name, want := range beforeFiles {
				got, err := os.ReadFile(filepath.Join(fileRoot, name))
				if err != nil || !bytes.Equal(got, want) {
					t.Errorf("changed %s: %v, %q", name, err, got)
				}
			}
			before := installSnapshot(t, directory)
			output, err = runCommand(workingDirectory, "uninstall")
			if err != nil || output != keptConfig+"git-age: nothing to uninstall\n" || !reflect.DeepEqual(before, installSnapshot(t, directory)) {
				t.Fatalf("repeat uninstall: %v, %q", err, output)
			}
		})
	}
}

func TestUninstallReportsUserConfig(t *testing.T) {
	for _, scenario := range []struct {
		name, config, keys string
		global             bool
	}{
		{name: "no user config"},
		{name: "key file", config: "[age]\nkeyFile = private.key\n", keys: "age.keyFile"},
		{name: "recipient", config: "[age]\nrecipient = age1keep\n", keys: "age.recipient"},
		{name: "trust", config: "[age]\ntrustedRecipients = trusted-hash\n", keys: "age.trustedRecipients"},
		{name: "duplicate and empty values", config: "[AGE]\nKEYFILE = private.key\nkeyFile = other.key\nrecipient =\ntrustedRecipients\n", keys: "age.keyFile, age.recipient, age.trustedRecipients"},
		{name: "inherited", config: "[age]\nkeyFile = private.key\nrecipient = age1keep\ntrustedRecipients = trusted-hash\n", keys: "age.keyFile, age.recipient, age.trustedRecipients", global: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			if scenario.global {
				globalDirectory := t.TempDir()
				writeFile(t, globalDirectory, "gitconfig", scenario.config)
				t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(globalDirectory, "gitconfig"))
			} else {
				config := installGitPath(t, directory, "config")
				content := readFile(t, filepath.Dir(config), "config")
				writeFile(t, filepath.Dir(config), "config", string(content)+scenario.config)
			}
			mustCommand(t, directory, "install")
			want := ""
			if scenario.keys != "" {
				want = "Kept user Git config: " + scenario.keys + "\n"
			}
			for _, args := range [][]string{{"-n"}, nil, nil} {
				before := installSnapshot(t, directory)
				var stdout, stderr bytes.Buffer
				root := newRootCommand()
				root.SetOut(&stdout)
				root.SetErr(&stderr)
				root.SetArgs(append([]string{"-C", directory, "uninstall"}, args...))
				if err := root.Execute(); err != nil {
					t.Fatal(err)
				}
				if stderr.String() != want {
					t.Fatalf("uninstall %v: got %q, want %q", args, &stderr, want)
				}
				if len(args) != 0 && !reflect.DeepEqual(before, installSnapshot(t, directory)) {
					t.Fatal("dry run changed repository files")
				}
			}
		})
	}
}

func TestUninstallDryRunAndPreflight(t *testing.T) {
	for _, scenario := range []string{"dry run", "missing installation", "broken attributes", "symlink attributes", "directory attributes", "disabled hooks"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			args, want := []string{}, ""
			if scenario != "missing installation" {
				if _, err := runCommand(directory, "install", "--hook-mode=abort"); err != nil {
					t.Fatal(err)
				}
			}
			attributes := installGitPath(t, directory, "info/attributes")
			switch scenario {
			case "dry run":
				args, want = []string{"-n"}, "would remove git-age pre-push hook"
			case "missing installation":
				want = "git-age: nothing to uninstall"
			case "broken attributes":
				writeFile(t, filepath.Dir(attributes), "attributes", "# BEGIN git-age (generated from .gitage; do not edit)\n# user data\n")
			case "symlink attributes", "directory attributes":
				if err := os.Remove(attributes); err != nil {
					t.Fatal(err)
				}
				if scenario == "directory attributes" {
					if err := os.Mkdir(attributes, 0755); err != nil {
						t.Fatal(err)
					}
				} else {
					writeFile(t, directory, "target", "# user data\n")
					if err := os.Symlink(filepath.Join(directory, "target"), attributes); err != nil {
						t.Skipf("symlinks unavailable: %v", err)
					}
				}
			case "disabled hooks":
				runGit(t, directory, "config", "core.hooksPath", os.DevNull)
				want = "uninstalled Git integration"
			}
			before := installSnapshot(t, directory)
			output, err := runCommand(directory, "uninstall", args...)
			if want != "" {
				if err != nil || !strings.Contains(output, want) {
					t.Fatalf("uninstall: %v, %q", err, output)
				}
			} else if err == nil {
				t.Fatal("expected preflight failure")
			}
			if scenario != "disabled hooks" && !reflect.DeepEqual(before, installSnapshot(t, directory)) {
				t.Fatal("dry run or failed preflight changed repository files")
			}
		})
	}
	if _, err := runCommand(t.TempDir(), "uninstall"); err == nil || !strings.Contains(err.Error(), "requires a Git worktree") {
		t.Fatalf("outside Git: %v", err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"uninstall", "extra"}, &stdout, &stderr); code != 2 || stdout.Len() != 0 {
		t.Fatalf("extra args: exit %d, output %q", code, &stdout)
	}
}

func TestUninstallKeepsUnmanagedHooks(t *testing.T) {
	for _, scenario := range []string{"other tool", "symlink", "directory", "wrong marker"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			if _, err := runCommand(directory, "install"); err != nil {
				t.Fatal(err)
			}
			hooks := installGitPath(t, directory, "hooks")
			path := filepath.Join(hooks, "post-rewrite")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "other tool":
				writeFile(t, hooks, "post-rewrite", "#!/bin/sh\n# other tool\n")
			case "wrong marker":
				writeFile(t, hooks, "post-rewrite", "#!/bin/sh\n# git-age managed pre-commit hook\n")
			case "directory":
				if err := os.Mkdir(path, 0755); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				writeFile(t, directory, "target", "# git-age managed post-rewrite hook\n")
				if err := os.Symlink(filepath.Join(directory, "target"), path); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			before := installSnapshot(t, directory)
			output, err := runCommand(directory, "uninstall")
			if err != nil || !strings.Contains(output, "Kept post-rewrite hook") {
				t.Fatalf("uninstall: %v, %q", err, output)
			}
			after := installSnapshot(t, directory)
			if before[path] != after[path] || before[filepath.Join(directory, "target")] != after[filepath.Join(directory, "target")] {
				t.Fatal("uninstall changed the unmanaged hook or its target")
			}
			if _, err := os.Stat(filepath.Join(hooks, "pre-commit")); !os.IsNotExist(err) {
				t.Fatalf("managed hook remains: %v", err)
			}
		})
	}
}

func TestUninstallKeepsInheritedConfig(t *testing.T) {
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	globalDirectory := t.TempDir()
	global := "[age]\nhookMode = abort\nunlockAfterCommit = true\n[diff \"age\"]\ntextconv = global\ncachetextconv = false\n[merge \"age\"]\ndriver = global\n[filter \"age\"]\nclean = global\n"
	writeFile(t, globalDirectory, "gitconfig", global)
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(globalDirectory, "gitconfig"))
	if _, err := runCommand(directory, "install", "--hook-mode=always-lock"); err != nil {
		t.Fatal(err)
	}
	if _, err := runCommand(directory, "uninstall"); err != nil {
		t.Fatal(err)
	}
	if got := string(runGit(t, directory, "config", "--get", "diff.age.textconv")); got != "global\n" {
		t.Fatalf("inherited config changed: %q", got)
	}
	content, err := os.ReadFile(filepath.Join(globalDirectory, "gitconfig"))
	if err != nil || string(content) != global {
		t.Fatalf("global config changed: %v, %q", err, content)
	}
	before := installSnapshot(t, directory)
	output, err := runCommand(directory, "uninstall")
	if err != nil || output != "git-age: nothing to uninstall\n" || !reflect.DeepEqual(before, installSnapshot(t, directory)) {
		t.Fatalf("inherited config counted as installed: %v, %q", err, output)
	}
}
