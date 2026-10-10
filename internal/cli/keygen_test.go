package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestKeygen(t *testing.T) {
	for _, scenario := range []string{"default", "subdirectory", "short output flag", "long output flag", "no exclude", "outside Git"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			inGit := scenario != "outside Git"
			if inGit {
				initKeygenRepo(t, directory)
			}

			workingDirectory := directory
			path := filepath.Join(directory, ".gitage.key")
			args := []string{}

			switch scenario {
			case "subdirectory":
				workingDirectory = filepath.Join(directory, "sub")
				if err := os.Mkdir(workingDirectory, 0700); err != nil {
					t.Fatal(err)
				}
			case "short output flag":
				path = filepath.Join(directory, "custom.key")
				args = []string{"-o", "custom.key"}
			case "long output flag":
				path = filepath.Join(t.TempDir(), "external.key")
				args = []string{"--output", path}
			case "no exclude":
				args = []string{"--no-exclude"}
			}

			output, err := runKeygen(workingDirectory, args...)
			if err != nil {
				t.Fatal(err)
			}

			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			identities, err := age.ParseIdentities(bytes.NewReader(content))
			if err != nil || len(identities) != 1 {
				t.Fatalf("expected one valid age identity, got %v: %v", identities, err)
			}
			identity, ok := identities[0].(*age.X25519Identity)
			if !ok {
				t.Fatalf("expected an X25519 identity, got %T", identities[0])
			}
			if !strings.Contains(output, identity.Recipient().String()) {
				t.Error("output does not include the generated key's public recipient")
			}
			if strings.Contains(output, identity.String()) {
				t.Error("output exposes the private identity")
			}

			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
				t.Errorf("key permissions: got %o, want 600", info.Mode().Perm())
			}

			if scenario == "subdirectory" {
				if _, err := os.Stat(filepath.Join(workingDirectory, ".gitage.key")); !os.IsNotExist(err) {
					t.Errorf("unexpected key in subdirectory: %v", err)
				}
			}
			if inGit && scenario != "long output flag" {
				ignored := exec.Command("git", "-C", directory, "check-ignore", "-q", path).Run() == nil
				if ignored != (scenario != "no exclude") {
					t.Errorf("Git exclusion: ignored=%v", ignored)
				}

				if output, err := exec.Command("git", "-C", directory, "add", "-A").CombinedOutput(); err != nil {
					t.Fatalf("git add: %v\n%s", err, output)
				}
				staged, err := exec.Command("git", "-C", directory, "ls-files", "--cached").Output()
				if err != nil {
					t.Fatal(err)
				}
				if tracked := strings.TrimSpace(string(staged)) != ""; tracked != (scenario == "no exclude") {
					t.Errorf("private key staging: tracked=%v", tracked)
				}
			}
		})
	}
}

func TestKeygenRefusesOverwrite(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, ".gitage.key")
	original := []byte("existing key\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}

	_, err := runKeygen(directory)
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Errorf("expected overwrite refusal, got %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, original) {
		t.Error("existing key was changed")
	}
}

func TestKeygenMissingOutputDirectory(t *testing.T) {
	directory := t.TempDir()
	_, err := runKeygen(directory, "-o", "missing/key")
	if err == nil || !strings.Contains(err.Error(), "output directory does not exist") {
		t.Errorf("expected missing output directory error, got %v", err)
	}

	if _, err := os.Stat(filepath.Join(directory, "missing")); !os.IsNotExist(err) {
		t.Errorf("output directory was unexpectedly created: %v", err)
	}
}

func TestKeygenDryRun(t *testing.T) {
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	exclude := filepath.Join(directory, ".git", "info", "exclude")
	before, err := os.ReadFile(exclude)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	output, err := runKeygen(directory, "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "would generate identity:") {
		t.Errorf("unexpected dry-run output: %s", output)
	}
	if _, err := os.Stat(filepath.Join(directory, ".gitage.key")); !os.IsNotExist(err) {
		t.Errorf("dry run created a key: %v", err)
	}

	after, err := os.ReadFile(exclude)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("dry run changed Git exclusions")
	}
}

func TestKeygenDirectoryAlias(t *testing.T) {
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	alias := filepath.Join(t.TempDir(), "repository")
	if err := os.Symlink(directory, alias); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}
	if _, err := runKeygen(alias, "-o", "custom.key"); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "-C", directory, "check-ignore", "-q", "custom.key")
	if err := cmd.Run(); err != nil {
		t.Fatalf("custom key generated through a directory alias is not ignored: %v", err)
	}
	if output, err := exec.Command("git", "-C", directory, "add", "-A").CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, output)
	}
	staged, err := exec.Command("git", "-C", directory, "ls-files", "--cached").Output()
	if err != nil {
		t.Fatal(err)
	}
	if len(staged) != 0 {
		t.Fatal("private key was staged")
	}
}

func initKeygenRepo(t *testing.T, directory string) {
	t.Helper()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")

	cmd := exec.Command("git", "-C", directory, "-c", "init.templateDir=", "init", "-q")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, output)
	}
}

func runKeygen(directory string, args ...string) (string, error) {
	var output bytes.Buffer
	root := newRootCommand()
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs(append([]string{"-C", directory, "keygen"}, args...))

	err := root.Execute()
	return output.String(), err
}
