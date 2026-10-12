package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/arthurmartelli/git-age/internal/repository"
)

func TestPrePushGitHook(t *testing.T) {
	t.Setenv("GIT_AGE_KEY_FILE", "")
	t.Setenv("GIT_AGE_RECIPIENT", "")
	t.Setenv("GIT_AGE_HOOK_MODE", "")
	t.Setenv("GIT_AGE_UNLOCK_AFTER_COMMIT", "0")
	t.Setenv("GIT_AGE_ALLOW_PLAINTEXT_PUSH", "")
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
	directory, _, _ := cleanFixture(t, []byte("original\n"), false)
	remote := filepath.Join(t.TempDir(), "remote.git")
	runGit(t, directory, "init", "--bare", "-q", remote)
	runGit(t, directory, "remote", "add", "origin", remote)
	if _, err := runCommand(directory, "install", "--hook-mode", "always-lock"); err != nil {
		t.Fatal(err)
	}
	runGit(t, directory, "push", "-q", "origin", "HEAD:refs/heads/main")
	remoteHead := func() string {
		t.Helper()
		output, err := exec.Command("git", "--git-dir="+remote, "rev-parse", "refs/heads/main").Output()
		if err != nil {
			t.Fatal(err)
		}
		return string(output)
	}
	initial := remoteHead()
	refuse := func(refspec, message string) {
		t.Helper()
		output, err := exec.Command("git", "-C", directory, "push", "-q", "origin", refspec).CombinedOutput()
		if err == nil || !bytes.Contains(output, []byte(message)) || !bytes.Contains(output, []byte("push aborted")) {
			t.Fatalf("push %s: %v, %s", refspec, err, output)
		}
		if !bytes.Contains(output, []byte("GIT_AGE_ALLOW_PLAINTEXT_PUSH=1 git push")) {
			t.Fatalf("push refusal omitted override advice: %s", output)
		}
	}
	writeFile(t, directory, "secret.env", "leaked\n")
	runGit(t, directory, "add", "secret.env")
	runGit(t, directory, "commit", "--no-verify", "-qm", "plaintext")
	refuse("HEAD:refs/heads/main", "secret.env")
	if remoteHead() != initial {
		t.Fatal("refused push changed the remote")
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"-C", directory, "lock"}, &stdout, &stderr); code != 0 {
		t.Fatalf("lock: exit %d, %s", code, &stderr)
	}
	runGit(t, directory, "add", "secret.env")
	runGit(t, directory, "commit", "-qm", "encrypt again")
	refuse("HEAD:refs/heads/main", "secret.env") // Removing plaintext at the tip does not erase its history.
	t.Setenv("GIT_AGE_ALLOW_PLAINTEXT_PUSH", "yes")
	output := runGit(t, directory, "push", "-q", "origin", "HEAD:refs/heads/main")
	if !bytes.Contains(output, []byte("by explicit choice (GIT_AGE_ALLOW_PLAINTEXT_PUSH)")) {
		t.Fatalf("override was not reported: %s", output)
	}
	t.Setenv("GIT_AGE_ALLOW_PLAINTEXT_PUSH", "")
	writeFile(t, directory, "secret.env", "new safe edit\n")
	runGit(t, directory, "add", "secret.env")
	runGit(t, directory, "commit", "-qm", "safe edit")
	runGit(t, directory, "push", "-q", "origin", "HEAD:refs/heads/main")
	// Already published plaintext does not block an unrelated new branch.
	runGit(t, directory, "push", "-q", "origin", "HEAD:refs/heads/safe-copy")
	runGit(t, directory, "checkout", "-qb", "leak")
	writeFile(t, directory, "secret.env", "branch leak\n")
	runGit(t, directory, "add", "secret.env")
	runGit(t, directory, "commit", "--no-verify", "-qm", "branch leak")
	refuse("leak:refs/heads/leak", "secret.env")
	runGit(t, directory, "tag", "-a", "leaky-tag", "-m", "leaky annotated tag")
	refuse("refs/tags/leaky-tag:refs/tags/leaky-tag", "secret.env")
	runGit(t, directory, "push", "--no-verify", "-q", "origin", "leak:refs/heads/leak")
	runGit(t, directory, "push", "-q", "origin", ":refs/heads/leak")
	refuse("leak:refs/heads/leak", "secret.env")
	runGit(t, directory, "checkout", "-qb", "replayed", "origin/main")
	runGit(t, directory, "cherry-pick", "leak")
	refuse("replayed:refs/heads/replayed", "secret.env")
	runGit(t, directory, "checkout", "-qb", "keys", "origin/main")
	writeFile(t, directory, "k.txt", newIdentity(t).String()+"\n")
	runGit(t, directory, "add", "k.txt")
	runGit(t, directory, "commit", "--no-verify", "-qm", "private key")
	refuse("keys:refs/heads/keys", "Private age keys in the commits being pushed")
	runGit(t, directory, "rm", "k.txt")
	runGit(t, directory, "commit", "-qm", "remove key")
	refuse("keys:refs/heads/keys", "k.txt")
	runGit(t, directory, "switch", "--orphan", "no-rules")
	writeFile(t, directory, "notes.txt", "AGE-SECRET-KEY-1 is a marker\n")
	runGit(t, directory, "add", "notes.txt")
	runGit(t, directory, "commit", "-qm", "no rules")
	if output := runGit(t, directory, "push", "-q", "origin", "no-rules:refs/heads/no-rules"); len(output) != 0 {
		t.Fatalf("no-rules push should be silent: %s", output)
	}
	refuse("leak:refs/heads/leak", "secret.env") // Uses the pushed branch's rules, not this checkout's.
	output, err := exec.Command("git", "-C", directory, "push", "-q", "origin", "origin/main:refs/heads/multi-safe", "leak:refs/heads/multi-leak").CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte("push aborted")) {
		t.Fatalf("multiple-ref push allowed a leak: %v, %s", err, output)
	}
	if refs := runGit(t, directory, "ls-remote", "origin", "refs/heads/multi-safe", "refs/heads/multi-leak"); len(refs) != 0 {
		t.Fatalf("refused push partially updated remote: %s", refs)
	}
}

func TestCheckPushUsesCurrentAndHistoricalRules(t *testing.T) {
	for _, scenario := range []string{"before rules", "removed rules", "negation", "empty", "local key", "SHA256"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			if scenario == "SHA256" {
				directory = t.TempDir()
				if output, err := exec.Command("git", "-C", directory, "-c", "init.templateDir=", "init", "-q", "--object-format=sha256").CombinedOutput(); err != nil {
					t.Skipf("SHA256 repositories unavailable: %v, %s", err, output)
				}
			}
			runGit(t, directory, "config", "user.name", "Test")
			runGit(t, directory, "config", "user.email", "test@example.invalid")
			runGit(t, directory, "config", "commit.gpgsign", "false")
			content := "plaintext\n"
			if scenario == "empty" {
				content = ""
			}
			writeFile(t, directory, "secret.env", content)
			if scenario != "before rules" && scenario != "local key" {
				writeFile(t, directory, ".gitage", "[files]\n*.env\n")
			}
			if scenario == "local key" {
				writeFile(t, directory, ".gitage.key", "not a key")
			}
			runGit(t, directory, "add", "-f", ".")
			runGit(t, directory, "commit", "-qm", "plaintext version")
			if scenario == "before rules" {
				writeFile(t, directory, ".gitage", "[files]\n*.env\n")
			} else if scenario == "removed rules" {
				runGit(t, directory, "rm", ".gitage")
				runGit(t, directory, "commit", "-qm", "remove rules")
			} else if scenario == "negation" {
				writeFile(t, directory, ".gitage", "[files]\n*.env\n!secret.env\n")
			}
			tip := strings.TrimSpace(string(runGit(t, directory, "rev-parse", "HEAD")))
			input := "refs/heads/main " + tip + " refs/heads/main " + strings.Repeat("0", len(tip)) + "\n"
			before := installSnapshot(t, directory)
			check, err := repository.CheckPush(directory, "origin", strings.NewReader(input))
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "empty" || scenario == "local key" {
				if len(check.Plaintext) != 0 {
					t.Fatalf("unexpected plaintext: %v", check.Plaintext)
				}
			} else if !reflect.DeepEqual(check.Plaintext, []string{"secret.env"}) {
				t.Fatalf("missed historical or current protection: %+v", check)
			}
			if scenario == "local key" && !reflect.DeepEqual(check.PrivateKeys, []string{".gitage.key"}) {
				t.Fatalf("missed local key: %+v", check)
			}
			if !reflect.DeepEqual(before, installSnapshot(t, directory)) {
				t.Fatal("pre-push scan changed repository files")
			}
		})
	}
}

func TestPrePushProtocol(t *testing.T) {
	directory, _, _ := cleanFixture(t, []byte("encrypted\n"), false)
	for _, input := range []string{"", "(delete) " + strings.Repeat("0", 40) + " refs/heads/main " + strings.Repeat("1", 40) + "\n"} {
		check, err := repository.CheckPush(directory, "origin", strings.NewReader(input))
		if err != nil || len(check.Plaintext) != 0 || len(check.PrivateKeys) != 0 {
			t.Fatalf("empty or deletion update: %+v, %v", check, err)
		}
	}
	for _, input := range []string{"broken\n", "refs/heads/main --all refs/heads/main " + strings.Repeat("0", 40) + "\n"} {
		root := newRootCommand()
		root.SetIn(strings.NewReader(input))
		root.SetArgs([]string{"-C", directory, "hook", "pre-push", "origin", "unused-url"})
		if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "invalid pre-push") {
			t.Fatalf("malformed update accepted: %v", err)
		}
	}
	broken := errors.New("broken stream")
	if _, err := repository.CheckPush(directory, "origin", cleanBrokenReader{broken}); !errors.Is(err, broken) {
		t.Fatalf("read error lost: %v", err)
	}
}

func TestCheckPushMergeResolution(t *testing.T) {
	directory, identity, _ := cleanFixture(t, []byte("base\n"), false)
	writeFile(t, directory, ".gitattributes", "secret.env -merge\n")
	runGit(t, directory, "add", ".gitattributes")
	runGit(t, directory, "commit", "-qm", "binary merge")
	runGit(t, directory, "branch", "ours")
	runGit(t, directory, "checkout", "-qb", "theirs")
	writeFile(t, directory, "secret.env", string(encryptFixture(t, identity.Recipient(), "theirs\n", false)))
	runGit(t, directory, "add", "secret.env")
	runGit(t, directory, "commit", "-qm", "theirs")
	runGit(t, directory, "update-ref", "refs/remotes/origin/theirs", "HEAD")
	runGit(t, directory, "checkout", "-q", "ours")
	writeFile(t, directory, "secret.env", string(encryptFixture(t, identity.Recipient(), "ours\n", false)))
	runGit(t, directory, "add", "secret.env")
	runGit(t, directory, "commit", "-qm", "ours")
	previous := strings.TrimSpace(string(runGit(t, directory, "rev-parse", "HEAD")))
	if err := exec.Command("git", "-C", directory, "merge", "--no-edit", "theirs").Run(); err == nil {
		t.Fatal("expected a merge conflict")
	}
	writeFile(t, directory, "secret.env", "plaintext resolution\n")
	runGit(t, directory, "add", "secret.env")
	runGit(t, directory, "commit", "--no-verify", "-qm", "plaintext merge resolution")
	tip := strings.TrimSpace(string(runGit(t, directory, "rev-parse", "HEAD")))
	input := "refs/heads/ours " + tip + " refs/heads/ours " + previous + "\n"
	check, err := repository.CheckPush(directory, "origin", strings.NewReader(input))
	if err != nil || !reflect.DeepEqual(check.Plaintext, []string{"secret.env"}) {
		t.Fatalf("missed merge's introduced plaintext: %+v, %v", check, err)
	}
}
