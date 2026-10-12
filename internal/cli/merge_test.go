package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestMerge(t *testing.T) {
	for _, scenario := range []string{
		"clean", "armored", "mixed", "plaintext", "empty base", "identical",
		"unchanged ours", "unchanged theirs", "subdirectory", "symlink inputs", "nested recipients",
		"recipient edit", "external recipients", "conflict", "diff3", "custom markers",
	} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("GIT_AGE_KEY_FILE", "")
			t.Setenv("GIT_AGE_RECIPIENT", "")
			baseText, oursText, theirsText := "A=1\nB=1\nC=1\n", "A=2\nB=1\nC=1\n", "A=1\nB=1\nC=2\n"
			want := []byte("A=2\nB=1\nC=2\n")
			conflict := scenario == "conflict" || scenario == "diff3" || scenario == "custom markers"
			switch scenario {
			case "empty base":
				baseText, oursText, theirsText = "", "", "new\n"
				want = []byte(theirsText)
			case "identical":
				theirsText, want = oursText, []byte(oursText)
			case "unchanged ours":
				oursText, want = baseText, []byte(theirsText)
			case "unchanged theirs":
				theirsText, want = baseText, []byte(oursText)
			}
			if conflict {
				oursText, theirsText = "ours\n", "theirs\n"
			}
			directory, identity, _ := cleanFixture(t, []byte(baseText), false)
			workingDirectory, path := directory, "secret.env"
			if scenario == "subdirectory" {
				workingDirectory, path = filepath.Join(directory, "sub"), "secret.env"
			}
			var extra *age.X25519Identity
			switch scenario {
			case "nested recipients":
				path = "sub/secret.env"
				extra = newIdentity(t)
				writeFile(t, directory, "sub/.gitage", "[recipients]\n"+extra.Recipient().String()+"\n")
			case "recipient edit":
				extra = newIdentity(t)
				writeFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+extra.Recipient().String()+"\n")
			case "external recipients":
				extra = newIdentity(t)
				t.Setenv("GIT_AGE_RECIPIENT", extra.Recipient().String())
			case "diff3":
				runGit(t, directory, "config", "merge.conflictStyle", "diff3")
			case "plaintext":
				for _, name := range []string{".gitage", ".gitage.key"} {
					if err := os.Remove(filepath.Join(directory, name)); err != nil {
						t.Fatal(err)
					}
				}
			}
			contents := make([][]byte, 3)
			for i, text := range []string{baseText, oursText, theirsText} {
				contents[i] = encryptFixture(t, identity.Recipient(), text, scenario == "armored")
				if scenario == "plaintext" || scenario == "mixed" && i == 0 || scenario == "empty base" && i == 0 {
					contents[i] = []byte(text)
				}
			}
			if scenario == "identical" || scenario == "recipient edit" || scenario == "external recipients" {
				// Reuse must succeed for identical changes but respect new recipients.
				contents[2] = encryptFixture(t, identity.Recipient(), oursText, false)
				want = []byte(oursText)
				writeFile(t, directory, "secret.env", string(contents[1]))
				runGit(t, directory, "add", "secret.env")
				runGit(t, directory, "commit", "-qm", "ours")
			}
			inputs := mergeInputs(t, workingDirectory, contents)
			if scenario == "symlink inputs" {
				alias := filepath.Join(t.TempDir(), "repo")
				if err := os.Symlink(directory, alias); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
				inputs = []string{filepath.Join(alias, ".merge/base"), filepath.Join(alias, ".merge/ours"), filepath.Join(alias, ".merge/theirs")}
			}
			indexBefore := runGit(t, directory, "ls-files", "--stage", "-z")
			workingBefore := readFile(t, directory, "secret.env")
			markerSize := 7
			if scenario == "custom markers" {
				markerSize = 11
			}
			temporary := t.TempDir()
			for _, variable := range []string{"TMPDIR", "TMP", "TEMP"} {
				t.Setenv(variable, temporary)
			}
			args := []string{"-C", workingDirectory, "merge", "--path", path}
			if markerSize == 11 {
				args = append(args, "--marker-size", "11")
			}
			var stdout, stderr bytes.Buffer
			inputArgs := inputs
			if scenario == "subdirectory" {
				inputArgs = []string{".merge/base", ".merge/ours", ".merge/theirs"}
			}
			code := Run(append(args, inputArgs...), &stdout, &stderr)
			merged, err := os.ReadFile(inputs[1])
			if err != nil || stdout.Len() != 0 {
				t.Fatalf("output: %v, %q", err, &stdout)
			}
			if conflict {
				if code != 1 || !strings.Contains(stderr.String(), "is now UNLOCKED") || !bytes.Contains(merged, []byte(strings.Repeat("<", markerSize)+" ours\n")) || !bytes.Contains(merged, []byte(strings.Repeat(">", markerSize)+" theirs\n")) {
					t.Fatalf("conflict: exit %d, stderr %q, result %q", code, &stderr, merged)
				}
				if scenario == "diff3" && !bytes.Contains(merged, []byte("||||||| base\n"+baseText)) {
					t.Fatalf("missing base: %q", merged)
				}
			} else {
				if code != 0 || stderr.Len() != 0 {
					t.Fatalf("merge: exit %d, %s", code, &stderr)
				}
				if scenario == "plaintext" {
					if !bytes.Equal(merged, want) {
						t.Fatalf("plaintext merge: %q", merged)
					}
				} else {
					decrypting := identity
					if scenario == "recipient edit" || scenario == "external recipients" {
						decrypting = extra
						if _, err := age.Decrypt(bytes.NewReader(merged), identity); err == nil {
							t.Fatal("reused ciphertext for a removed recipient")
						}
					}
					assertDecrypts(t, merged, decrypting, want)
					if scenario == "nested recipients" {
						assertDecrypts(t, merged, extra, want)
					}
					if scenario == "identical" && !bytes.Equal(merged, contents[1]) {
						t.Fatal("identical merge did not reuse our ciphertext")
					}
				}
			}
			assertMergeInputs(t, inputs, contents, false)
			workingAfter, err := os.ReadFile(filepath.Join(directory, "secret.env"))
			if err != nil || !bytes.Equal(workingBefore, workingAfter) || !bytes.Equal(indexBefore, runGit(t, directory, "ls-files", "--stage", "-z")) {
				t.Fatal("driver changed the working file or index directly")
			}
			entries, err := os.ReadDir(temporary)
			if err != nil || len(entries) != 0 {
				t.Fatalf("temporary files left behind: %v, %v", entries, err)
			}
		})
	}
}

func TestMergeRefusesWithoutChangingOurs(t *testing.T) {
	for _, scenario := range []string{
		"no identity", "wrong identity", "missing identity", "invalid identity",
		"corrupt base", "corrupt ours", "corrupt theirs", "binary", "unprotected",
		"malformed rules", "invalid recipients", "trust refusal", "missing input", "outside repository", "merge-file failure",
	} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("GIT_AGE_KEY_FILE", "")
			t.Setenv("GIT_AGE_RECIPIENT", "")
			directory, identity, _ := cleanFixture(t, []byte("A=1\nB=1\nC=1\n"), false)
			texts := []string{"A=1\nB=1\nC=1\n", "A=2\nB=1\nC=1\n", "A=1\nB=1\nC=2\n"}
			if scenario == "binary" {
				texts[1] += "\x00binary"
			}
			contents := make([][]byte, 3)
			for i, text := range texts {
				contents[i] = encryptFixture(t, identity.Recipient(), text, false)
				if scenario == []string{"corrupt base", "corrupt ours", "corrupt theirs"}[i] {
					contents[i][len(contents[i])-1] ^= 1
				}
			}
			path := "secret.env"
			switch scenario {
			case "no identity":
				if err := os.Remove(filepath.Join(directory, ".gitage.key")); err != nil {
					t.Fatal(err)
				}
			case "wrong identity":
				writeFile(t, directory, ".gitage.key", newIdentity(t).String()+"\n")
			case "missing identity", "invalid identity":
				t.Setenv("GIT_AGE_KEY_FILE", filepath.Join(directory, "invalid.key"))
				if scenario == "invalid identity" {
					writeFile(t, directory, "invalid.key", "invalid key")
				}
			case "unprotected":
				writeFile(t, directory, ".gitage", "[files]\n!secret.env\n")
			case "malformed rules":
				writeFile(t, directory, ".gitage", "[unknown]\n")
			case "invalid recipients":
				writeFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\nage1invalid\n")
			case "trust refusal":
				runGit(t, directory, "config", "age.trustedRecipients", "deadbeef")
			case "outside repository":
				path = filepath.Join(t.TempDir(), "secret.env")
			case "merge-file failure":
				runGit(t, directory, "config", "merge.conflictStyle", "invalid")
			}
			inputs := mergeInputs(t, directory, contents)
			if scenario == "missing input" {
				inputs[0] = filepath.Join(directory, "absent")
			}
			temporary := t.TempDir()
			for _, variable := range []string{"TMPDIR", "TMP", "TEMP"} {
				t.Setenv(variable, temporary)
			}
			var stdout, stderr bytes.Buffer
			code := Run(append([]string{"-C", directory, "merge", "--path", path}, inputs...), &stdout, &stderr)
			if code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "keeping our version") || strings.Contains(stderr.String(), "is now UNLOCKED") {
				t.Fatalf("refusal: exit %d, stdout %q, stderr %q", code, &stdout, &stderr)
			}
			if scenario == "no identity" && stderr.String() != "git-age: cannot merge secret.env: no identity configured; use -i or generate a key with git-age keygen; keeping our version\n" {
				t.Fatalf("missing identity guidance: %q", &stderr)
			}
			if scenario != "missing input" {
				assertMergeInputs(t, inputs, contents, true)
			} else {
				got, err := os.ReadFile(inputs[1])
				if err != nil || !bytes.Equal(got, contents[1]) {
					t.Fatal("changed ours on read failure")
				}
			}
			entries, err := os.ReadDir(temporary)
			if err != nil || len(entries) != 0 {
				t.Fatalf("temporary files left behind: %v, %v", entries, err)
			}
		})
	}
}

func TestMergeArgumentsAndDryRun(t *testing.T) {
	for _, args := range [][]string{
		{}, {"--path", "secret.env"}, {"base", "ours", "theirs"},
		{"--path=", "base", "ours", "theirs"},
		{"--path", "secret.env", "--marker-size", "0", "base", "ours", "theirs"},
		{"--path", "secret.env", "--marker-size", "-1", "base", "ours", "theirs"},
	} {
		var stdout, stderr bytes.Buffer
		if code := Run(append([]string{"merge"}, args...), &stdout, &stderr); code != 2 || stdout.Len() != 0 {
			t.Fatalf("args %v: exit %d, stdout %q", args, code, &stdout)
		}
	}
	directory := t.TempDir()
	contents := [][]byte{[]byte("base"), []byte("ours"), []byte("theirs")}
	inputs := mergeInputs(t, directory, contents)
	var stdout, stderr bytes.Buffer
	if code := Run(append([]string{"-C", directory, "-n", "merge", "--path", "secret.env"}, inputs...), &stdout, &stderr); code != 0 || stdout.String() != "would merge: secret.env\n" || stderr.Len() != 0 {
		t.Fatalf("dry run: exit %d, stdout %q, stderr %q", code, &stdout, &stderr)
	}
	assertMergeInputs(t, inputs, contents, true)
}

func TestMergeGitDriver(t *testing.T) {
	executable := buildGitAge(t)
	for _, scenario := range []string{"clean", "identical", "conflict", "rebase", "cherry-pick", "no identity"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("GIT_AGE_KEY_FILE", "")
			t.Setenv("GIT_AGE_RECIPIENT", "")
			t.Setenv("GIT_EDITOR", "true")
			directory, identity, _ := cleanFixture(t, []byte("A=1\nB=1\nC=1\n"), false)
			program := "\"" + filepath.ToSlash(executable) + "\""
			writeFile(t, directory, ".gitattributes", "*.env merge=age filter=age conflict-marker-size=11\n")
			runGit(t, directory, "config", "merge.age.driver", program+" merge %O %A %B --path %P --marker-size %L")
			runGit(t, directory, "config", "filter.age.clean", program+" clean %f")
			runGit(t, directory, "config", "filter.age.smudge", "cat")
			runGit(t, directory, "config", "filter.age.required", "true")
			runGit(t, directory, "add", ".gitattributes")
			runGit(t, directory, "commit", "-qm", "driver")
			runGit(t, directory, "branch", "ours")
			runGit(t, directory, "checkout", "-qb", "theirs")
			oursText, theirsText := "A=2\nB=1\nC=1\n", "A=1\nB=1\nC=2\n"
			conflict := scenario == "conflict" || scenario == "rebase" || scenario == "cherry-pick"
			if conflict {
				oursText, theirsText = "ours\n", "theirs\n"
			} else if scenario == "identical" {
				theirsText = oursText
			}
			writeFile(t, directory, "secret.env", string(encryptFixture(t, identity.Recipient(), theirsText, false)))
			runGit(t, directory, "add", "secret.env")
			runGit(t, directory, "commit", "-qm", "theirs")
			runGit(t, directory, "checkout", "-q", "ours")
			ours := encryptFixture(t, identity.Recipient(), oursText, false)
			writeFile(t, directory, "secret.env", string(ours))
			runGit(t, directory, "add", "secret.env")
			runGit(t, directory, "commit", "-qm", "ours")
			operation := []string{"merge", "--no-edit", "theirs"}
			switch scenario {
			case "rebase":
				runGit(t, directory, "checkout", "-q", "theirs")
				operation = []string{"rebase", "ours"}
			case "cherry-pick":
				operation = []string{"cherry-pick", "theirs"}
			case "no identity":
				if err := os.Remove(filepath.Join(directory, ".gitage.key")); err != nil {
					t.Fatal(err)
				}
			}
			output, err := exec.Command("git", append([]string{"-C", directory}, operation...)...).CombinedOutput()
			if conflict {
				if err == nil || !strings.Contains(string(output), "is now UNLOCKED") || len(runGit(t, directory, "ls-files", "-u")) == 0 {
					t.Fatalf("conflict: %v, %s", err, output)
				}
				working, err := os.ReadFile(filepath.Join(directory, "secret.env"))
				if err != nil || !bytes.Contains(working, []byte("<<<<<<<<<<< ours\n")) {
					t.Fatalf("markers: %v, %q", err, working)
				}
				writeFile(t, directory, "secret.env", "resolved\n")
				runGit(t, directory, "config", "age.trustedRecipients", "deadbeef")
				output, err = exec.Command("git", "-C", directory, "add", "secret.env").CombinedOutput()
				if err == nil || !strings.Contains(string(output), "Refusing to stage it as plaintext") || len(runGit(t, directory, "ls-files", "-u")) == 0 {
					t.Fatalf("failed staging: %v, %s", err, output)
				}
				if scenario == "rebase" {
					head := gitRevision(t, directory, "HEAD")
					refuseGit(t, directory, "secret.env", "rebase", "--continue")
					if gitRevision(t, directory, "HEAD") != head || len(runGit(t, directory, "ls-files", "-u")) == 0 {
						t.Fatal("failed rebase continuation committed plaintext")
					}
				}
				runGit(t, directory, "config", "--unset", "age.trustedRecipients")
				runGit(t, directory, "add", "secret.env")
				assertDecrypts(t, runGit(t, directory, "show", ":secret.env"), identity, []byte("resolved\n"))
				if scenario == "rebase" || scenario == "cherry-pick" {
					runGit(t, directory, scenario, "--continue")
				} else {
					runGit(t, directory, "commit", "-qm", "resolved")
				}
				assertDecrypts(t, runGit(t, directory, "show", "HEAD:secret.env"), identity, []byte("resolved\n"))
			} else if scenario == "no identity" {
				working, readErr := os.ReadFile(filepath.Join(directory, "secret.env"))
				if err == nil || !strings.Contains(string(output), "keeping our version") || readErr != nil || !bytes.Equal(working, ours) {
					t.Fatalf("missing key: %v, %v, %s", err, readErr, output)
				}
			} else {
				if err != nil {
					t.Fatalf("merge: %v, %s", err, output)
				}
				merged := runGit(t, directory, "show", "HEAD:secret.env")
				want := []byte("A=2\nB=1\nC=2\n")
				if scenario == "identical" {
					want = []byte(oursText)
					if !bytes.Equal(merged, ours) {
						t.Fatal("merge did not reuse ciphertext")
					}
				}
				assertDecrypts(t, merged, identity, want)
			}
		})
	}
}

func mergeInputs(t *testing.T, directory string, contents [][]byte) []string {
	t.Helper()
	paths := []string{filepath.Join(directory, ".merge/base"), filepath.Join(directory, ".merge/ours"), filepath.Join(directory, ".merge/theirs")}
	for i, name := range []string{"base", "ours", "theirs"} {
		writeFile(t, directory, ".merge/"+name, string(contents[i]))
	}
	return paths
}

func assertMergeInputs(t *testing.T, paths []string, contents [][]byte, includeOurs bool) {
	t.Helper()
	for i, path := range paths {
		if i == 1 && !includeOurs {
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, contents[i]) {
			t.Fatalf("input %d changed: %v", i, err)
		}
	}
}
