package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStatus(t *testing.T) {
	// The user's identity would mark files not encrypted to it.
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_AGE_KEY_FILE", "")
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
			writeFile(t, directory, ".gitage", "[files]\n*.env\n!public.env\n[recipients]\nage1example\n")
			writeFile(t, directory, "a.env", "plaintext")
			writeFile(t, directory, "sub/b.env", "age-encryption.org/v1\n")
			writeFile(t, directory, "sub/c.env", "-----BEGIN AGE ENCRYPTED FILE-----\n")
			writeFile(t, directory, "public.env", "public")
			writeFile(t, directory, "readme", "public")
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
					got, err := runCommand(tc.directory, "status", tc.args...)
					if err != nil {
						t.Fatal(err)
					}
					if got != tc.want {
						t.Fatalf("got %q, want %q", got, tc.want)
					}
				})
			}
			if inGit {
				got, err := runCommand(filepath.Join(directory, "sub"), "status", "--porcelain")
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
	writeFile(t, directory, ".gitage", "[files]\n**/*.env\nsecrets/\n!secrets/public.txt\n")
	writeFile(t, directory, "sub/.gitage", "[files]\n!public.env\n*.txt\n")
	writeFile(t, directory, ".gitignore", "ignored.env\n")
	for _, name := range []string{"a.env", "ignored.env", "sub/public.env", "sub/private.txt", "secrets/public.txt", "secrets/.gitage.key"} {
		writeFile(t, directory, name, "plaintext")
	}
	got, err := runCommand(directory, "status", "--porcelain")
	if err != nil {
		t.Fatal(err)
	}
	if want := "U. a.env\nU. secrets/public.txt\nU. sub/private.txt\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestStatusErrors(t *testing.T) {
	directory := t.TempDir()
	if _, err := runCommand(directory, "status"); err == nil || !strings.Contains(err.Error(), "no .gitage files") {
		t.Fatalf("missing rules: %v", err)
	}
	writeFile(t, directory, ".gitage", "[files]\n*.env\n")
	writeFile(t, directory, "readme", "hello")
	for _, tc := range []struct{ path, message string }{
		{"missing.env", "no such file or directory"},
		{"readme", "not protected by .gitage"},
		{".", "no file in it is protected"},
		{"../outside", "outside"},
	} {
		_, err := runCommand(directory, "status", tc.path)
		if err == nil || !strings.Contains(err.Error(), tc.message) {
			t.Errorf("%s: %v", tc.path, err)
		}
	}
	writeFile(t, directory, ".gitage", "[file]\n*.env\n")
	if _, err := runCommand(directory, "status"); err == nil || !strings.Contains(err.Error(), "unknown section") {
		t.Fatalf("invalid rules: %v", err)
	}
}

func TestStatusQuotedPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows filenames cannot contain tabs")
	}
	directory := t.TempDir()
	writeFile(t, directory, ".gitage", "[files]\n*.env\n")
	writeFile(t, directory, "a\tb.env", "plaintext")
	got, err := runCommand(directory, "status", "--porcelain")
	if err != nil || got != "U. \"a\\tb.env\"\n" {
		t.Fatalf("quoted: %q, %v", got, err)
	}
	got, err = runCommand(directory, "status", "-z")
	if err != nil || got != "U. a\tb.env\x00" {
		t.Fatalf("NUL: %q, %v", got, err)
	}
}

func TestStatusReadOnly(t *testing.T) {
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	writeFile(t, directory, ".gitage", "[files]\n*.env\n")
	writeFile(t, directory, "a.env", "plaintext")
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
	if _, err := runCommand(directory, "status"); err != nil {
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

// Carol is listed only in prod/.gitage, so app.env is not encrypted to her.
func TestStatusAndUnlockWithoutAccess(t *testing.T) {
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	alice, carol := newIdentity(t), newIdentity(t)
	writeFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+alice.Recipient().String()+"\n")
	writeFile(t, directory, "prod/.gitage", "[recipients]\n"+carol.Recipient().String()+"\n")
	writeFile(t, directory, "app.env", string(encryptFixture(t, alice.Recipient(), "app", false)))
	writeFile(t, directory, "prod/db.env", string(encryptFixture(t, carol.Recipient(), "db", false)))
	key := filepath.Join(t.TempDir(), "carol")
	writeFile(t, filepath.Dir(key), "carol", carol.String()+"\n")
	t.Setenv("GIT_AGE_KEY_FILE", key)

	if got, err := runCommand(directory, "status", "--porcelain"); err != nil || got != "LN app.env\nL. prod/db.env\n" {
		t.Fatalf("porcelain: %q, %v", got, err)
	}
	if got, err := runCommand(directory, "status"); err != nil || !strings.Contains(got, "LOCKED     app.env (no access)\n") {
		t.Fatalf("status: %q, %v", got, err)
	}
	if got, err := runCommand(directory, "-v", "status"); err != nil || !strings.Contains(got, "encrypted to .gitage [recipients] + prod/.gitage [recipients]\n") {
		t.Fatalf("status -v: %q, %v", got, err)
	}
	output, err := runCommand(directory, "unlock")
	if err != nil || !strings.Contains(output, "left 1 file(s) locked that are not encrypted to you") {
		t.Fatalf("unlock: %q, %v", output, err)
	}
	if string(readFile(t, directory, "prod/db.env")) != "db" || !strings.HasPrefix(string(readFile(t, directory, "app.env")), "age-encryption.org/v1\n") {
		t.Fatal("unlock decrypted the wrong files")
	}
}

func TestStatusStaleRecipients(t *testing.T) {
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	alice, carol := newIdentity(t), newIdentity(t)
	writeFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+alice.Recipient().String()+"\n")
	writeFile(t, directory, "secret.env", string(encryptFixture(t, alice.Recipient(), "secret", false)))
	runGit(t, directory, "add", "-A")
	runGit(t, directory, "-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", "commit", "-qm", "secrets")
	if got, err := runCommand(directory, "status", "--porcelain"); err != nil || got != "L. secret.env\n" {
		t.Fatalf("before the change: %q, %v", got, err)
	}

	writeFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+alice.Recipient().String()+"\n"+carol.Recipient().String()+"\n")
	if got, err := runCommand(directory, "status", "--porcelain"); err != nil || got != "LS secret.env\n" {
		t.Fatalf("porcelain: %q, %v", got, err)
	}
	if got, err := runCommand(directory, "status"); err != nil || !strings.Contains(got, "previous [recipients] list (run `git-age rekey`):\n  secret.env\n") {
		t.Fatalf("status: %q, %v", got, err)
	}
}

func TestStatusGitPatternWorkflow(t *testing.T) {
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	t.Setenv("GIT_AGE_KEY_FILE", "")
	writeFile(t, directory, ".gitage", "[files]\n*.env\nsecrets/**\n!public.txt\n")
	for _, path := range []string{"secrets/a.txt", "secrets/public.txt", "secrets/deep/public.txt", "PROD.ENV"} {
		writeFile(t, directory, path, "x\n")
	}
	for _, test := range []struct{ ignoreCase, want string }{
		{"false", "U. secrets/a.txt\nU. secrets/deep/public.txt\n"},
		{"true", "U. PROD.ENV\nU. secrets/a.txt\nU. secrets/deep/public.txt\n"},
	} {
		runGit(t, directory, "config", "core.ignoreCase", test.ignoreCase)
		if got := mustCommand(t, directory, "status", "--porcelain"); got != test.want {
			t.Fatalf("ignoreCase=%s: %q, want %q", test.ignoreCase, got, test.want)
		}
	}
}
