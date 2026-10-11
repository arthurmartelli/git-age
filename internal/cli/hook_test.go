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

func TestPreCommit(t *testing.T) {
	for _, scenario := range []string{
		"full staging", "partial staging", "staged recipients", "nested recipients",
		"abort", "environment policy", "invalid policy", "private key", "protected key",
		"removed rules", "stale recipients", "allow stale", "bad second recipient", "bad identity",
		"empty encryption", "allow empty", "dry run", "missing working file",
	} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("GIT_AGE_KEY_FILE", "")
			t.Setenv("GIT_AGE_RECIPIENT", "")
			t.Setenv("GIT_AGE_HOOK_MODE", "")
			for _, variable := range []string{"GIT_AGE_ALLOW_EMPTY", "GIT_AGE_ALLOW_REMOVE", "GIT_AGE_ALLOW_PRIVATE_KEYS", "GIT_AGE_ALLOW_STALE_RECIPIENTS"} {
				t.Setenv(variable, "")
			}
			directory, identity, previous := cleanFixture(t, []byte("original\n"), false)
			cleanGit(t, directory, "config", "age.hookMode", "always-lock")
			stagedText, workingText := "staged edit\n", "staged edit\n"
			wantCode, diagnostic := 0, ""
			var extra *age.X25519Identity
			if scenario == "empty encryption" || scenario == "allow empty" {
				stagedText, workingText = "original\n", "original\n"
			}
			writeStatusFile(t, directory, "secret.env", stagedText)
			cleanGit(t, directory, "add", "secret.env")
			switch scenario {
			case "partial staging":
				workingText = "staged edit\nunstaged edit\n"
				writeStatusFile(t, directory, "secret.env", workingText)
				diagnostic = "unstaged changes"
			case "staged recipients":
				extra = rekeyIdentity(t)
				writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+extra.Recipient().String()+"\n")
				cleanGit(t, directory, "add", ".gitage")
				writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+identity.Recipient().String()+"\n")
			case "nested recipients":
				extra = rekeyIdentity(t)
				writeStatusFile(t, directory, "sub/.gitage", "[recipients]\n"+extra.Recipient().String()+"\n")
				writeStatusFile(t, directory, "sub/nested.env", "nested\n")
				cleanGit(t, directory, "add", "sub")
				writeStatusFile(t, directory, "sub/.gitage", "[recipients]\n"+rekeyIdentity(t).Recipient().String()+"\n")
			case "abort":
				cleanGit(t, directory, "config", "age.hookMode", "abort")
				wantCode, diagnostic = 1, "commit aborted"
			case "environment policy":
				cleanGit(t, directory, "config", "age.hookMode", "abort")
				t.Setenv("GIT_AGE_HOOK_MODE", "always-lock")
			case "invalid policy":
				t.Setenv("GIT_AGE_HOOK_MODE", "invalid")
				wantCode, diagnostic = 2, "invalid choice"
			case "private key":
				writeStatusFile(t, directory, "leaked.txt", "AGE-SECRET-KEY-1SECRET")
				cleanGit(t, directory, "add", "leaked.txt")
				wantCode, diagnostic = 1, "refusing to commit private age keys"
			case "protected key":
				stagedText, workingText = identity.String(), identity.String()
				writeStatusFile(t, directory, "secret.env", stagedText)
				cleanGit(t, directory, "add", "secret.env")
			case "removed rules":
				cleanGit(t, directory, "rm", ".gitage")
				wantCode, diagnostic = 1, "refusing to commit the removal"
			case "stale recipients", "allow stale":
				writeStatusFile(t, directory, "secret.env", string(previous))
				cleanGit(t, directory, "add", "secret.env")
				writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+identity.Recipient().String()+"\n"+rekeyIdentity(t).Recipient().String()+"\n")
				cleanGit(t, directory, "add", ".gitage")
				wantCode, diagnostic = 1, "still encrypted to the previous list"
				if scenario == "allow stale" {
					t.Setenv("GIT_AGE_ALLOW_STALE_RECIPIENTS", "1")
					wantCode, diagnostic = 0, ""
				}
			case "bad second recipient":
				writeStatusFile(t, directory, "z/.gitage", "[recipients]\nage1invalid\n")
				writeStatusFile(t, directory, "z/b.env", "second secret\n")
				cleanGit(t, directory, "add", "z")
				wantCode, diagnostic = 1, "could not encrypt staged files"
			case "bad identity":
				t.Setenv("GIT_AGE_KEY_FILE", filepath.Join(directory, "absent.key"))
				wantCode, diagnostic = 1, "could not encrypt staged files"
			case "empty encryption":
				wantCode, diagnostic = 1, "encrypt to the ciphertext already in HEAD"
			case "allow empty":
				t.Setenv("GIT_AGE_ALLOW_EMPTY", "yes")
			case "missing working file":
				if err := os.Remove(filepath.Join(directory, "secret.env")); err != nil {
					t.Fatal(err)
				}
				diagnostic = "could not be safely replaced"
			}
			beforeIndex := cleanGit(t, directory, "ls-files", "--stage", "-z")
			args := []string{"-C", directory, "hook", "pre-commit"}
			if scenario == "dry run" {
				args = append(args, "-n")
			}
			var stdout, stderr bytes.Buffer
			code := Run(args, &stdout, &stderr)
			if code != wantCode || !strings.Contains(stderr.String(), diagnostic) {
				t.Fatalf("hook: exit %d, stdout %q, stderr %q; want %d, %q", code, &stdout, &stderr, wantCode, diagnostic)
			}
			if scenario == "dry run" {
				if stdout.String() != "would encrypt staged: secret.env\n" || !bytes.Equal(beforeIndex, cleanGit(t, directory, "ls-files", "--stage", "-z")) {
					t.Fatal("dry run changed the index")
				}
				return
			}
			if scenario == "empty encryption" {
				if staged := cleanGit(t, directory, "show", ":secret.env"); !bytes.Equal(staged, previous) {
					t.Fatal("empty commit did not reuse existing ciphertext")
				}
				return
			}
			if wantCode != 0 {
				if !bytes.Equal(beforeIndex, cleanGit(t, directory, "ls-files", "--stage", "-z")) {
					t.Fatal("refusal changed the index")
				}
				working, err := os.ReadFile(filepath.Join(directory, "secret.env"))
				if err != nil || string(working) != workingText && scenario != "stale recipients" {
					t.Fatalf("refusal changed working copy: %v, %q", err, working)
				}
				return
			}
			if scenario == "allow stale" {
				return
			}
			staged := cleanGit(t, directory, "show", ":secret.env")
			decrypting := identity
			if scenario == "staged recipients" {
				decrypting = extra
				if _, err := age.Decrypt(bytes.NewReader(staged), identity); err == nil {
					t.Fatal("used unstaged recipients")
				}
			}
			assertCleanDecrypts(t, staged, decrypting, []byte(stagedText))
			if scenario == "nested recipients" {
				nested := cleanGit(t, directory, "show", ":sub/nested.env")
				assertCleanDecrypts(t, nested, identity, []byte("nested\n"))
				assertCleanDecrypts(t, nested, extra, []byte("nested\n"))
			}
			working, err := os.ReadFile(filepath.Join(directory, "secret.env"))
			if scenario == "missing working file" {
				if !os.IsNotExist(err) {
					t.Fatalf("recreated missing working file: %v", err)
				}
			} else if scenario == "partial staging" {
				if err != nil || string(working) != workingText {
					t.Fatal("overwrote unstaged edits")
				}
			} else if err != nil || !bytes.Equal(working, staged) {
				t.Fatalf("working copy differs from encrypted index: %v", err)
			}
		})
	}
}

func TestPreCommitNoRules(t *testing.T) {
	for _, localKey := range []bool{false, true} {
		directory := t.TempDir()
		initKeygenRepo(t, directory)
		writeStatusFile(t, directory, "notes.txt", "AGE-SECRET-KEY-1 is a marker")
		cleanGit(t, directory, "add", "notes.txt")
		if localKey {
			writeStatusFile(t, directory, ".gitage.key", "local key")
			cleanGit(t, directory, "add", "-f", ".gitage.key")
		}
		var stdout, stderr bytes.Buffer
		code := Run([]string{"-C", directory, "hook", "pre-commit"}, &stdout, &stderr)
		if localKey {
			if code != 1 || !strings.Contains(stderr.String(), "refusing to commit private age keys") {
				t.Fatalf("local key: exit %d, %s", code, &stderr)
			}
		} else if code != 0 || stdout.Len() != 0 || stderr.Len() != 0 {
			t.Fatalf("no rules: exit %d, stdout %q, stderr %q", code, &stdout, &stderr)
		}
	}
}

func TestHookGitCommit(t *testing.T) {
	bin := t.TempDir()
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
	for _, scenario := range []string{"commit", "partial staging", "commit only", "post-commit unlock", "exported Git paths", "linked worktree", "lock unlock status"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("GIT_AGE_KEY_FILE", "")
			t.Setenv("GIT_AGE_RECIPIENT", "")
			t.Setenv("GIT_AGE_HOOK_MODE", "")
			t.Setenv("GIT_AGE_UNLOCK_AFTER_COMMIT", "")
			// An unset override allows the repository's post-commit setting.
			os.Unsetenv("GIT_AGE_UNLOCK_AFTER_COMMIT")
			directory, identity, _ := cleanFixture(t, []byte("original\n"), false)
			if scenario == "linked worktree" {
				cleanGit(t, directory, "config", "age.keyFile", filepath.Join(directory, ".gitage.key"))
				linked := filepath.Join(t.TempDir(), "linked")
				cleanGit(t, directory, "worktree", "add", "-qb", "linked", linked)
				directory = linked
			}
			if _, err := runInstall(directory, "--mode", "always-lock"); err != nil {
				t.Fatal(err)
			}
			if scenario == "post-commit unlock" {
				cleanGit(t, directory, "config", "age.unlockAfterCommit", "true")
			}
			if scenario == "exported Git paths" {
				t.Setenv("GIT_DIR", installGitPath(t, directory, "."))
				t.Setenv("GIT_WORK_TREE", directory)
			}
			writeStatusFile(t, directory, "secret.env", "staged edit\n")
			cleanGit(t, directory, "add", "secret.env")
			if scenario == "partial staging" {
				writeStatusFile(t, directory, "secret.env", "staged edit\nunstaged edit\n")
			}
			if scenario == "commit only" {
				writeStatusFile(t, directory, "other.env", "another staged file\n")
				cleanGit(t, directory, "add", "other.env")
				cleanGit(t, directory, "commit", "-qm", "only secret", "--only", "secret.env")
				if output := cleanGit(t, directory, "show", ":other.env"); string(output) != "another staged file\n" {
					t.Fatal("partial commit changed another staged file")
				}
				if err := exec.Command("git", "-C", directory, "cat-file", "-e", "HEAD:other.env").Run(); err == nil {
					t.Fatal("partial commit included another staged file")
				}
			} else {
				cleanGit(t, directory, "commit", "-qm", "encrypted edit")
			}
			assertCleanDecrypts(t, cleanGit(t, directory, "show", "HEAD:secret.env"), identity, []byte("staged edit\n"))
			working, err := os.ReadFile(filepath.Join(directory, "secret.env"))
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "partial staging" {
				if string(working) != "staged edit\nunstaged edit\n" {
					t.Fatal("commit overwrote unstaged edits")
				}
			} else if scenario == "post-commit unlock" {
				if string(working) != "staged edit\n" {
					t.Fatal("post-commit did not unlock")
				}
				if status := cleanGit(t, directory, "status", "--porcelain", "--", "secret.env"); len(status) != 0 {
					t.Fatalf("unchanged unlocked file shows modified: %s", status)
				}
			} else {
				assertCleanDecrypts(t, working, identity, []byte("staged edit\n"))
			}
			if scenario == "lock unlock status" {
				for _, command := range []string{"unlock", "lock"} {
					var stdout, stderr bytes.Buffer
					if code := Run([]string{"-C", directory, command}, &stdout, &stderr); code != 0 {
						t.Fatalf("%s: exit %d, %s", command, code, &stderr)
					}
					if status := cleanGit(t, directory, "status", "--porcelain", "--", "secret.env"); len(status) != 0 {
						t.Fatalf("%s left unchanged file modified: %s", command, status)
					}
				}
			}
		})
	}
}

func TestPromptHookChoice(t *testing.T) {
	for _, test := range []struct{ input, want, diagnostic string }{
		{"a\n", "abort", ""}, {"\n", "abort", ""}, {"", "abort", ""},
		{"e\n", "encrypt", ""}, {"invalid\nE\n", "encrypt", ""},
		{"c\ncommit\n", "commit", "Type \"commit\""},
		{"c\nno\n", "abort", "not confirmed"}, {"c\n", "abort", "not confirmed"},
	} {
		var output bytes.Buffer
		choice, err := promptHookChoice(strings.NewReader(test.input), &output)
		if err != nil || choice != test.want || !strings.Contains(output.String(), test.diagnostic) {
			t.Fatalf("input %q: %q, %v, output %q", test.input, choice, err, &output)
		}
	}
}
