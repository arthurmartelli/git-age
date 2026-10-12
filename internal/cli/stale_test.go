package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestStagedStaleRecipientHistory(t *testing.T) {
	for _, scenario := range []string{"staged change", "older committed change", "unstaged change", "unstaged rekey", "staged rekey", "reintroduced old blob"} {
		t.Run(scenario, func(t *testing.T) {
			isolateHookEnvironment(t)
			directory, identity, ciphertext := cleanFixture(t, []byte("original\n"), false)
			originalBlob := strings.TrimSpace(string(runGit(t, directory, "rev-parse", "HEAD:secret.env")))
			rules := "[files]\n*.env\n[recipients]\n" + identity.Recipient().String() + "\n" + newIdentity(t).Recipient().String() + "\n"
			writeFile(t, directory, ".gitage", rules)
			if scenario != "unstaged change" {
				runGit(t, directory, "add", ".gitage")
			}
			if scenario == "older committed change" {
				runGit(t, directory, "commit", "-qm", "bypass rekey")
				writeFile(t, directory, "note.txt", "later commit\n")
				runGit(t, directory, "add", "note.txt")
				runGit(t, directory, "commit", "-qm", "unrelated history")
			}
			if strings.Contains(scenario, "rekey") || scenario == "reintroduced old blob" {
				mustCommand(t, directory, "rekey")
				if scenario != "unstaged rekey" {
					runGit(t, directory, "add", "secret.env")
				}
			}
			if scenario == "reintroduced old blob" {
				runGit(t, directory, "commit", "-qm", "rekeyed")
				runGit(t, directory, "update-index", "--cacheinfo", "100644,"+originalBlob+",secret.env")
			}
			want := 1
			if scenario == "unstaged change" || scenario == "staged rekey" {
				want = 0
			}
			before := installSnapshot(t, directory)
			code, stdout, stderr := runCheck(directory, "--staged")
			if code != want || stdout != "" {
				t.Fatalf("staged check: exit %d, stdout %q, stderr %q", code, stdout, stderr)
			}
			if want == 1 && (!strings.Contains(stderr, "secret.env") || !strings.Contains(stderr, "git-age rekey -- secret.env") || !strings.Contains(stderr, "git add -- secret.env")) {
				t.Fatalf("missing stale-repair advice: %q", stderr)
			}
			assertSnapshotUnchanged(t, directory, before)
			if want == 1 {
				if output, err := runCommand(directory, "hook", "pre-commit"); err == nil || !strings.Contains(output, "previous list of [recipients]") {
					t.Fatalf("pre-commit missed stale file: %v, %q", err, output)
				}
				t.Setenv("GIT_AGE_ALLOW_STALE_RECIPIENTS", "yes")
				if code, _, stderr := runCheck(directory, "--staged"); code != 0 || stderr != "" {
					t.Fatalf("explicit override: exit %d, stderr %q", code, stderr)
				}
			}
			if scenario == "older committed change" && !bytes.Equal(ciphertext, readFile(t, directory, "secret.env")) {
				t.Fatal("read-only check changed ciphertext")
			}
		})
	}
}

func TestStagedStaleSelectionFromSubdirectory(t *testing.T) {
	isolateHookEnvironment(t)
	directory, identity, _ := cleanFixture(t, []byte("original\n"), false)
	writeFile(t, directory, "sub/a.env", string(readFile(t, directory, "secret.env")))
	writeFile(t, directory, "sub/b.env", string(readFile(t, directory, "secret.env")))
	runGit(t, directory, "add", "sub")
	runGit(t, directory, "commit", "-qm", "nested secrets")
	writeFile(t, directory, "sub/.gitage", "[recipients]\n"+identity.Recipient().String()+"\n"+newIdentity(t).Recipient().String()+"\n")
	runGit(t, directory, "add", "sub/.gitage")
	code, _, stderr := runCheck(filepath.Join(directory, "sub"), "--staged", "./a.env")
	if code != 1 || !strings.Contains(stderr, "  a.env\n") || strings.Contains(stderr, "b.env") || strings.Contains(stderr, "secret.env") {
		t.Fatalf("stale selection: exit %d, stderr %q", code, stderr)
	}
}

func TestLockWarnsAboutStaleFiles(t *testing.T) {
	isolateHookEnvironment(t)
	directory, identity, ciphertext := cleanFixture(t, []byte("original\n"), false)
	writeFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+identity.Recipient().String()+"\n"+newIdentity(t).Recipient().String()+"\n")
	runGit(t, directory, "add", ".gitage")
	runGit(t, directory, "commit", "-qm", "recipients changed earlier")
	output := mustCommand(t, directory, "lock")
	if !strings.Contains(output, "already locked") || !strings.Contains(output, "warning: these files are still encrypted") || !strings.Contains(output, "git-age rekey -- secret.env") || !strings.Contains(output, "git add -- secret.env") {
		t.Fatalf("lock omitted stale warning: %s", output)
	}
	if !bytes.Equal(ciphertext, readFile(t, directory, "secret.env")) {
		t.Fatal("lock rewrote an already locked file")
	}
	mustCommand(t, directory, "rekey")
	if output := mustCommand(t, directory, "lock"); strings.Contains(output, "warning: these files are still encrypted") {
		t.Fatalf("rekeyed file still warned as stale: %s", output)
	}
}
