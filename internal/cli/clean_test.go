package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestClean(t *testing.T) {
	for _, scenario := range []string{
		"unchanged", "changed", "ciphertext", "armored", "binary", "empty",
		"index preferred", "HEAD fallback", "missing working file", "subdirectory",
		"no identity", "wrong identity", "missing identity", "invalid identity", "corrupt ciphertext",
		"unprotected", "negated", "missing rules", "malformed rules", "unrelated malformed rules",
		"recipient edit", "staged recipient edit", "committed recipient edit", "external recipients",
		"outside Git", "outside repository",
	} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("GIT_AGE_KEY_FILE", "")
			t.Setenv("GIT_AGE_RECIPIENT", "")
			plaintext := []byte("secret\r\nwithout final newline")
			if scenario == "binary" {
				plaintext = []byte("secret\x00bytes\xff")
			} else if scenario == "empty" {
				plaintext = nil
			}
			directory, identity, ciphertext := cleanFixture(t, plaintext, scenario == "armored")
			workingDirectory, path := directory, "secret.env"
			input, want := plaintext, ciphertext
			passThrough := false
			switch scenario {
			case "changed":
				input, passThrough = []byte("edited secret"), true
			case "ciphertext":
				input, passThrough = ciphertext, true
			case "index preferred":
				want = encryptFixture(t, identity.Recipient(), string(plaintext), false)
				writeFile(t, directory, path, string(want))
				runGit(t, directory, "add", path)
			case "HEAD fallback":
				writeFile(t, directory, path, "staged edit")
				runGit(t, directory, "add", path)
			case "missing working file":
				if err := os.Remove(filepath.Join(directory, path)); err != nil {
					t.Fatal(err)
				}
			case "subdirectory":
				runGit(t, directory, "mv", path, "sub/nested.env")
				runGit(t, directory, "commit", "-qm", "move secret")
				workingDirectory, path = filepath.Join(directory, "sub"), "nested.env"
			case "no identity":
				if err := os.Remove(filepath.Join(directory, ".gitage.key")); err != nil {
					t.Fatal(err)
				}
				passThrough = true
			case "wrong identity":
				writeFile(t, directory, ".gitage.key", newIdentity(t).String()+"\n")
				passThrough = true
			case "missing identity", "invalid identity":
				t.Setenv("GIT_AGE_KEY_FILE", filepath.Join(directory, "other.key"))
				if scenario == "invalid identity" {
					writeFile(t, directory, "other.key", "invalid key")
				}
				passThrough = true
			case "corrupt ciphertext":
				corrupt := bytes.Clone(ciphertext)
				corrupt[len(corrupt)-1] ^= 1
				writeFile(t, directory, path, string(corrupt))
				runGit(t, directory, "add", path)
				runGit(t, directory, "commit", "-qm", "corrupt ciphertext")
				passThrough = true
			case "unprotected", "negated", "missing rules", "malformed rules":
				if scenario == "missing rules" {
					if err := os.Remove(filepath.Join(directory, ".gitage")); err != nil {
						t.Fatal(err)
					}
				} else {
					rules := "[files]\nother.env\n"
					if scenario == "negated" {
						rules = "[files]\n*.env\n!secret.env\n"
					} else if scenario == "malformed rules" {
						rules = "[unknown]\n"
					}
					writeFile(t, directory, ".gitage", rules)
					runGit(t, directory, "add", ".gitage")
					runGit(t, directory, "commit", "-qm", "change protection")
				}
				passThrough = true
			case "unrelated malformed rules":
				writeFile(t, directory, "sub/.gitage", "[unknown]\n")
			case "recipient edit", "staged recipient edit", "committed recipient edit":
				extra := newIdentity(t)
				writeFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+identity.Recipient().String()+"\n"+extra.Recipient().String()+"\n")
				if scenario != "recipient edit" {
					runGit(t, directory, "add", ".gitage")
				}
				if scenario == "committed recipient edit" {
					runGit(t, directory, "commit", "-qm", "add recipient")
				}
				passThrough = true
			case "external recipients":
				t.Setenv("GIT_AGE_RECIPIENT", identity.Recipient().String())
				passThrough = true
			case "outside Git":
				workingDirectory, passThrough = t.TempDir(), true
			case "outside repository":
				path, passThrough = filepath.Join(t.TempDir(), "secret.env"), true
			}
			if passThrough {
				want = input
			}
			// The filter must consume stdin, even if the working file differs.
			if scenario != "missing working file" && !passThrough {
				writeFile(t, workingDirectory, path, "different working contents")
			}
			output, stderr, err := runClean(workingDirectory, path, input)
			if err != nil || stderr != "" || !bytes.Equal(output, want) {
				t.Fatalf("clean: %v, stderr %q, output %q; want %q", err, stderr, output, want)
			}
		})
	}
}

func TestCleanConflict(t *testing.T) {
	for _, scenario := range []string{"ours encrypted", "theirs encrypted", "armored side", "reuse ours", "reuse theirs", "plaintext sides", "base only encrypted", "unprotected", "nested recipients", "no identity", "no recipients", "invalid recipients", "malformed rules", "trust refusal"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("GIT_AGE_KEY_FILE", "")
			t.Setenv("GIT_AGE_RECIPIENT", "")
			directory, identity, ciphertext := cleanFixture(t, []byte("original"), false)
			path := "secret.env"
			base, ours, theirs := ciphertext, ciphertext, []byte("their plaintext")
			input := []byte("resolved\x00secret\r\n")
			var reused []byte
			wantEncrypted, wantError := true, false
			var extra *age.X25519Identity
			switch scenario {
			case "theirs encrypted":
				ours, theirs = theirs, ours
			case "armored side":
				ours = encryptFixture(t, identity.Recipient(), "original", true)
			case "reuse ours", "reuse theirs":
				reused = encryptFixture(t, identity.Recipient(), string(input), scenario == "reuse theirs")
				ours = reused
				if scenario == "reuse theirs" {
					ours, theirs = theirs, reused
				}
			case "plaintext sides", "base only encrypted":
				ours, theirs, wantEncrypted = []byte("ours"), []byte("theirs"), false
				if scenario == "plaintext sides" {
					base = []byte("base")
				}
			case "unprotected":
				writeFile(t, directory, ".gitage", "[files]\n*.env\n!secret.env\n")
				wantEncrypted = false
			case "nested recipients":
				path = "sub/secret.env"
				extra = newIdentity(t)
				writeFile(t, directory, "sub/.gitage", "[recipients]\n"+extra.Recipient().String()+"\n")
			case "no identity", "no recipients":
				if err := os.Remove(filepath.Join(directory, ".gitage.key")); err != nil {
					t.Fatal(err)
				}
				if scenario == "no recipients" {
					writeFile(t, directory, ".gitage", "[files]\n*.env\n")
					wantError = true
				}
			case "invalid recipients":
				writeFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\nage1invalid\n")
				wantError = true
			case "malformed rules":
				writeFile(t, directory, ".gitage", "[unknown]\n")
				wantError = true
			case "trust refusal":
				runGit(t, directory, "config", "age.trustedRecipients", "deadbeef")
				wantError = true
			}
			cleanConflictIndex(t, directory, path, base, ours, theirs)
			writeFile(t, directory, path, string(input))
			indexBefore := runGit(t, directory, "ls-files", "--stage", "-z")
			output, stderr, err := runClean(directory, path, input)
			if wantError {
				if err == nil || !strings.Contains(err.Error(), "Refusing to stage it as plaintext") || len(output) != 0 {
					t.Fatalf("expected refusal with no output: %v, %q", err, output)
				}
			} else {
				if err != nil || stderr != "" {
					t.Fatalf("clean: %v, %q", err, stderr)
				}
				if wantEncrypted {
					assertDecrypts(t, output, identity, input)
					if reused != nil && !bytes.Equal(output, reused) {
						t.Fatal("matching conflict side was not reused")
					}
					if extra != nil {
						assertDecrypts(t, output, extra, input)
					}
				} else if !bytes.Equal(output, input) {
					t.Fatalf("plaintext changed: %q", output)
				}
			}
			after, err := os.ReadFile(filepath.Join(directory, path))
			if err != nil || !bytes.Equal(after, input) || !bytes.Equal(indexBefore, runGit(t, directory, "ls-files", "--stage", "-z")) {
				t.Fatalf("clean changed the working file or index: %v", err)
			}
		})
	}
}

func TestCleanStreamsAndArguments(t *testing.T) {
	for _, args := range [][]string{{}, {"one", "two"}} {
		var output, stderr bytes.Buffer
		if code := Run(append([]string{"clean"}, args...), &output, &stderr); code != 2 || output.Len() != 0 {
			t.Fatalf("args %v: exit %d, output %q", args, code, &output)
		}
	}
	streamErr := errors.New("broken stream")
	for _, reading := range []bool{true, false} {
		root := newRootCommand()
		root.SetArgs([]string{"-C", t.TempDir(), "clean", "secret.env"})
		var output bytes.Buffer
		root.SetOut(&output)
		root.SetIn(bytes.NewReader([]byte("plaintext")))
		if reading {
			root.SetIn(cleanBrokenReader{streamErr})
		} else {
			root.SetOut(cleanBrokenWriter{streamErr})
		}
		if err := root.Execute(); !errors.Is(err, streamErr) || output.Len() != 0 {
			t.Fatalf("stream error: %v, output %q", err, &output)
		}
	}
}

func TestCleanGitFilter(t *testing.T) {
	t.Setenv("GIT_AGE_KEY_FILE", "")
	t.Setenv("GIT_AGE_RECIPIENT", "")
	directory, identity, ciphertext := cleanFixture(t, []byte("original\n"), false)
	executable := buildGitAge(t)
	writeFile(t, directory, ".gitattributes", "*.env filter=age\n")
	runGit(t, directory, "config", "filter.age.clean", "\""+filepath.ToSlash(executable)+"\" clean %f")
	runGit(t, directory, "config", "filter.age.smudge", "cat")
	runGit(t, directory, "config", "filter.age.required", "true")
	runGit(t, directory, "add", ".gitattributes")
	runGit(t, directory, "commit", "-qm", "enable filter")
	writeFile(t, directory, "secret.env", "original\n")
	// Clear the encrypted file's cached size so Git asks the filter to compare.
	oid := strings.TrimSpace(string(runGit(t, directory, "rev-parse", "HEAD:secret.env")))
	runGit(t, directory, "update-index", "--cacheinfo", "100644,"+oid+",secret.env")
	if output := runGit(t, directory, "status", "--porcelain", "--", "secret.env"); len(output) != 0 {
		t.Fatalf("unchanged unlocked file shows as modified: %s", output)
	}
	runGit(t, directory, "add", "secret.env")
	if output := runGit(t, directory, "show", ":secret.env"); !bytes.Equal(output, ciphertext) {
		t.Fatal("git add did not reuse ciphertext")
	}
	writeFile(t, directory, "secret.env", "changed\n")
	if output := runGit(t, directory, "status", "--porcelain", "--", "secret.env"); string(output) != " M secret.env\n" {
		t.Fatalf("edit not visible: %q", output)
	}
	runGit(t, directory, "add", "secret.env")
	if output := runGit(t, directory, "show", ":secret.env"); string(output) != "changed\n" {
		t.Fatal("ordinary edits must pass through to the commit hook")
	}
	for _, refusing := range []bool{true, false} {
		cleanConflictIndex(t, directory, "secret.env", ciphertext, ciphertext, ciphertext)
		writeFile(t, directory, "secret.env", "resolved\n")
		if refusing {
			runGit(t, directory, "config", "age.trustedRecipients", "deadbeef")
		} else {
			runGit(t, directory, "config", "--unset", "age.trustedRecipients")
		}
		output, err := exec.Command("git", "-C", directory, "add", "secret.env").CombinedOutput()
		if refusing {
			if err == nil || !strings.Contains(string(output), "Refusing to stage it as plaintext") || len(runGit(t, directory, "ls-files", "-u", "--", "secret.env")) == 0 {
				t.Fatalf("failed encryption did not keep conflict unmerged: %v, %s", err, output)
			}
		} else {
			if err != nil {
				t.Fatalf("stage resolution: %v, %s", err, output)
			}
			assertDecrypts(t, runGit(t, directory, "show", ":secret.env"), identity, []byte("resolved\n"))
		}
	}
}

func cleanFixture(t *testing.T, plaintext []byte, armored bool) (string, *age.X25519Identity, []byte) {
	t.Helper()
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	identity := newIdentity(t)
	writeFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+identity.Recipient().String()+"\n")
	writeFile(t, directory, ".gitage.key", identity.String()+"\n")
	writeFile(t, directory, "sub/.keep", "")
	ciphertext := encryptFixture(t, identity.Recipient(), string(plaintext), armored)
	writeFile(t, directory, "secret.env", string(ciphertext))
	runGit(t, directory, "config", "user.name", "Test")
	runGit(t, directory, "config", "user.email", "test@example.com")
	runGit(t, directory, "config", "commit.gpgsign", "false")
	runGit(t, directory, "add", ".gitage", "secret.env")
	runGit(t, directory, "commit", "-qm", "encrypted")
	return directory, identity, ciphertext
}

func cleanConflictIndex(t *testing.T, directory, path string, sides ...[]byte) {
	t.Helper()
	runGit(t, directory, "update-index", "--force-remove", "--", path)
	var records strings.Builder
	for i, content := range sides {
		command := exec.Command("git", "-C", directory, "hash-object", "-w", "--stdin")
		command.Stdin = bytes.NewReader(content)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("hash conflict: %v, %s", err, output)
		}
		records.WriteString("100644 " + strings.TrimSpace(string(output)) + " " + string(rune('1'+i)) + "\t" + path + "\n")
	}
	command := exec.Command("git", "-C", directory, "update-index", "--index-info")
	command.Stdin = strings.NewReader(records.String())
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("create conflict: %v, %s", err, output)
	}
}

func runClean(directory, path string, content []byte) ([]byte, string, error) {
	root := newRootCommand()
	var output, stderr bytes.Buffer
	root.SetIn(bytes.NewReader(content))
	root.SetOut(&output)
	root.SetErr(&stderr)
	root.SetArgs([]string{"-C", directory, "clean", "--", path})
	err := root.Execute()
	return output.Bytes(), stderr.String(), err
}

type cleanBrokenReader struct{ err error }

func (r cleanBrokenReader) Read([]byte) (int, error) { return 0, r.err }

type cleanBrokenWriter struct{ err error }

func (w cleanBrokenWriter) Write([]byte) (int, error) { return 0, w.err }
