package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStatus(t *testing.T) {
	for _, inGit := range []bool{false, true} {
		name := "outside Git"
		if inGit {
			name = "Git worktree"
		}
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			if inGit {
				initKeygenRepo(t, directory)
			}
			writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n!public.env\n[recipients]\nage1example\n")
			writeStatusFile(t, directory, "a.env", "plaintext")
			writeStatusFile(t, directory, "sub/b.env", "age-encryption.org/v1\n")
			writeStatusFile(t, directory, "sub/c.env", "-----BEGIN AGE ENCRYPTED FILE-----\n")
			writeStatusFile(t, directory, "public.env", "public")
			writeStatusFile(t, directory, "readme", "public")
			for _, tc := range []struct {
				name      string
				directory string
				args      []string
				want      string
			}{
				{"human", directory, nil, "UNLOCKED   a.env\nLOCKED     sub/b.env\nLOCKED     sub/c.env\n"},
				{"porcelain", directory, []string{"--porcelain"}, "U. a.env\nL. sub/b.env\nL. sub/c.env\n"},
				{"NUL", directory, []string{"-z"}, "U. a.env\x00L. sub/b.env\x00L. sub/c.env\x00"},
				{"directory selection", directory, []string{"--porcelain", "sub"}, "L. sub/b.env\nL. sub/c.env\n"},
				{"sorted selection", directory, []string{"--porcelain", "sub/c.env", "a.env", "a.env"}, "U. a.env\nL. sub/c.env\n"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					got, err := runStatus(tc.directory, tc.args...)
					if err != nil {
						t.Fatal(err)
					}
					if got != tc.want {
						t.Fatalf("got %q, want %q", got, tc.want)
					}
				})
			}
			if inGit {
				got, err := runStatus(filepath.Join(directory, "sub"), "--porcelain")
				if err != nil || got != "L. b.env\nL. c.env\n" {
					t.Fatalf("subdirectory: %q, %v", got, err)
				}
			}
		})
	}
}

func TestStatusRules(t *testing.T) {
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	writeStatusFile(t, directory, ".gitage", "[files]\n**/*.env\nsecrets/\n!secrets/public.txt\n")
	writeStatusFile(t, directory, "sub/.gitage", "[files]\n!public.env\n*.txt\n")
	writeStatusFile(t, directory, ".gitignore", "ignored.env\n")
	for _, name := range []string{"a.env", "ignored.env", "sub/public.env", "sub/private.txt", "secrets/public.txt", "secrets/.gitage.key"} {
		writeStatusFile(t, directory, name, "plaintext")
	}
	got, err := runStatus(directory, "--porcelain")
	if err != nil {
		t.Fatal(err)
	}
	if want := "U. a.env\nU. secrets/public.txt\nU. sub/private.txt\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestStatusErrors(t *testing.T) {
	directory := t.TempDir()
	if _, err := runStatus(directory); err == nil || !strings.Contains(err.Error(), "no .gitage files") {
		t.Fatalf("missing rules: %v", err)
	}
	writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n")
	writeStatusFile(t, directory, "readme", "hello")
	for _, tc := range []struct{ path, message string }{
		{"missing.env", "no such file or directory"},
		{"readme", "not protected by .gitage"},
		{".", "no file in it is protected"},
		{"../outside", "outside"},
	} {
		_, err := runStatus(directory, tc.path)
		if err == nil || !strings.Contains(err.Error(), tc.message) {
			t.Errorf("%s: %v", tc.path, err)
		}
	}
	writeStatusFile(t, directory, ".gitage", "[file]\n*.env\n")
	if _, err := runStatus(directory); err == nil || !strings.Contains(err.Error(), "unknown section") {
		t.Fatalf("invalid rules: %v", err)
	}
}

func TestStatusQuotedPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows filenames cannot contain tabs")
	}
	directory := t.TempDir()
	writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n")
	writeStatusFile(t, directory, "a\tb.env", "plaintext")
	got, err := runStatus(directory, "--porcelain")
	if err != nil || got != "U. \"a\\tb.env\"\n" {
		t.Fatalf("quoted: %q, %v", got, err)
	}
	got, err = runStatus(directory, "-z")
	if err != nil || got != "U. a\tb.env\x00" {
		t.Fatalf("NUL: %q, %v", got, err)
	}
}

func TestStatusReadOnly(t *testing.T) {
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n")
	writeStatusFile(t, directory, "a.env", "plaintext")
	snapshot := func() map[string]string {
		result := map[string]string{}
		err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			result[path] = string(content) + info.Mode().String() + info.ModTime().String()
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	before := snapshot()
	if _, err := runStatus(directory); err != nil {
		t.Fatal(err)
	}
	after := snapshot()
	if len(before) != len(after) {
		t.Fatal("status changed the file list")
	}
	for path, content := range before {
		if after[path] != content {
			t.Errorf("status changed %s", path)
		}
	}
}

func writeStatusFile(t *testing.T, directory, name, content string) {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func runStatus(directory string, args ...string) (string, error) {
	var output bytes.Buffer
	root := newRootCommand()
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs(append([]string{"-C", directory, "status"}, args...))
	err := root.Execute()
	return output.String(), err
}
