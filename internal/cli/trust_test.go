package cli

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arthurmartelli/git-age/internal/repository"
)

func trustFixture(t *testing.T) (directory, alice, bob string) {
	t.Helper()
	directory = t.TempDir()
	initKeygenRepo(t, directory)
	t.Setenv("GIT_AGE_TRUSTED_RECIPIENTS", "")
	t.Setenv("GIT_AGE_RECIPIENT", "")
	t.Setenv("GIT_AGE_KEY_FILE", "")
	alice, bob = newIdentity(t).Recipient().String(), newIdentity(t).Recipient().String()
	writeFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+alice+"\n")
	writeFile(t, directory, "a.env", "secret")
	runGit(t, directory, "add", ".gitage")
	runGit(t, directory, "-c", "user.name=Alice", "-c", "user.email=alice@example.com", "-c", "commit.gpgsign=false", "commit", "-qm", "rules")
	return directory, alice, bob
}

func assertUnpinned(t *testing.T, directory string) {
	t.Helper()
	if output, err := exec.Command("git", "-C", directory, "config", "age.trustedRecipients").Output(); err == nil {
		t.Fatalf("pinned %q", output)
	}
}

func trustShow(t *testing.T, directory string) string {
	t.Helper()
	output, err := runCommand(directory, "trust", "--show")
	if err != nil {
		t.Fatalf("trust --show: %q, %v", output, err)
	}
	return strings.TrimSpace(output)
}

func TestTrustHashIgnoresOrderAndComments(t *testing.T) {
	directory, alice, bob := trustFixture(t)
	writeFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+alice+"\n"+bob+"\n")
	hash := trustShow(t, directory)
	if len(hash) != 64 {
		t.Fatalf("hash: %q", hash)
	}
	writeFile(t, directory, ".gitage", "# team\n[recipients]\n"+bob+"\n\n  "+alice+"\n"+bob+"\n[files]\n*.env\n")
	if got := trustShow(t, directory); got != hash {
		t.Fatalf("reordered lists hash %q, want %q", got, hash)
	}
	writeFile(t, directory, "sub/.gitage", "[recipients]\n"+alice+"\n")
	if got := trustShow(t, directory); got == hash {
		t.Fatal("a nested list did not change the hash")
	}
	if got := trustShow(t, filepath.Join(directory, "sub")); got == hash {
		t.Fatal("-C subdir must hash every list in the worktree")
	}
	assertUnpinned(t, directory)
}

func TestTrustPinsAndLockRefusesChanges(t *testing.T) {
	directory, alice, bob := trustFixture(t)
	output, err := runCommand(directory, "-n", "trust")
	if err != nil || !strings.Contains(output, "trusting these [recipients] lists:\n\n  .gitage\n    "+alice+"\n") || !strings.Contains(output, "would set git config age.trustedRecipients") {
		t.Fatalf("dry run: %q, %v", output, err)
	}
	assertUnpinned(t, directory)
	if output, err := runCommand(directory, "trust"); err != nil || !strings.Contains(output, "pinned ") {
		t.Fatalf("trust: %q, %v", output, err)
	}
	if pinned := strings.TrimSpace(string(runGit(t, directory, "config", "age.trustedRecipients"))); pinned != trustShow(t, directory) {
		t.Fatalf("pinned %q", pinned)
	}
	if output, err := runCommand(directory, "trust"); err != nil || !strings.Contains(output, "already trusted") {
		t.Fatalf("second trust: %q, %v", output, err)
	}

	writeFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+alice+"\n"+bob+"\n")
	runGit(t, directory, "add", ".gitage")
	runGit(t, directory, "-c", "user.name=Mallory", "-c", "user.email=mallory@example.com", "-c", "commit.gpgsign=false", "commit", "-qm", "widen access")
	output, err = runCommand(directory, "lock")
	if err == nil || !strings.Contains(err.Error(), "untrusted [recipients]") || !strings.Contains(err.Error(), "    + "+bob) ||
		!strings.Contains(err.Error(), "Mallory <mallory@example.com>  widen access") || strings.Contains(err.Error(), "uncommitted") {
		t.Fatalf("lock: %q, %v", output, err)
	}
	if got := string(readFile(t, directory, "a.env")); got != "secret" {
		t.Fatalf("refused lock changed a.env: %q", got)
	}
	if output, err := runCommand(directory, "status"); err != nil || !strings.Contains(output, "differ from the ones you trusted") {
		t.Fatalf("status: %q, %v", output, err)
	}
	if output, err := runCommand(directory, "status", "--porcelain"); err != nil || output != "U. a.env\n" {
		t.Fatalf("porcelain status: %q, %v", output, err)
	}

	writeFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+bob+"\n")
	if _, err := runCommand(directory, "lock"); err == nil || !strings.Contains(err.Error(), "    - "+alice) || !strings.Contains(err.Error(), "  (uncommitted changes)") {
		t.Fatalf("uncommitted change: %v", err)
	}
	output, err = runCommand(directory, "trust")
	if err != nil || !strings.Contains(output, "changed since you trusted them") || !strings.Contains(output, "    - "+alice) {
		t.Fatalf("trust change: %q, %v", output, err)
	}
	if output, err := runCommand(directory, "lock"); err != nil {
		t.Fatalf("lock after trust: %q, %v", output, err)
	}
}

func TestTrustPinMissingFromHistory(t *testing.T) {
	directory, alice, _ := trustFixture(t)
	runGit(t, directory, "config", "age.trustedRecipients", "DEADBEEF")
	_, err := runCommand(directory, "lock")
	if err == nil || !strings.Contains(err.Error(), "not in the last 200 commits") || !strings.Contains(err.Error(), "    "+alice) {
		t.Fatalf("lock: %v", err)
	}
}

func TestTrustEnvironmentOverride(t *testing.T) {
	directory, _, _ := trustFixture(t)
	hash := trustShow(t, directory)
	t.Setenv("GIT_AGE_TRUSTED_RECIPIENTS", strings.ToUpper(hash))
	runGit(t, directory, "config", "age.trustedRecipients", "deadbeef")
	if output, err := runCommand(directory, "lock"); err != nil {
		t.Fatalf("environment pin: %q, %v", output, err)
	}
	if output, err := runCommand(directory, "trust"); err != nil || !strings.Contains(output, "already trusted") {
		t.Fatalf("trust: %q, %v", output, err)
	}

	t.Setenv("GIT_AGE_TRUSTED_RECIPIENTS", "deadbeef")
	writeFile(t, directory, "a.env", "secret")
	if _, err := runCommand(directory, "status"); err != nil {
		t.Fatal(err)
	}
	if _, err := runCommand(directory, "lock"); err == nil || !strings.Contains(err.Error(), "(GIT_AGE_TRUSTED_RECIPIENTS)") {
		t.Fatalf("lock: %v", err)
	}
	if output, err := runCommand(directory, "trust"); err != nil || !strings.Contains(output, "takes precedence") {
		t.Fatalf("trust: %q, %v", output, err)
	}
}

func TestTrustRequiresWorktree(t *testing.T) {
	directory := t.TempDir()
	writeFile(t, directory, ".gitage", "[files]\n*.env\n")
	if _, err := runCommand(directory, "trust"); err == nil || !strings.Contains(err.Error(), "trust requires a Git worktree") {
		t.Fatalf("trust outside Git: %v", err)
	}
	if untrusted, err := repository.RecipientsUntrusted(directory); err != nil || untrusted {
		t.Fatalf("outside Git: %v, %v", untrusted, err)
	}
}
