package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestEdit(t *testing.T) {
	for _, action := range []string{"change", "unchanged", "fail", "concurrent", "replace", "delete", "unlocked", "recipient override", "identity flag", "subdirectory", "wrong key", "corrupt ciphertext", "dry run", "unprotected", "directory"} {
		t.Run(action, func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			t.Setenv("GIT_AGE_KEY_FILE", "")
			t.Setenv("GIT_AGE_RECIPIENT", "")
			identity := newIdentity(t)
			writeFile(t, directory, ".gitage.key", identity.String()+"\n")
			writeFile(t, directory, ".gitage", "[files]\n*.env\n")
			name := "sub/a ' $ file.env"
			before := encryptFixture(t, identity.Recipient(), "secret\r\nwithout final newline", false)
			if action == "unlocked" {
				before = []byte("plaintext")
			}
			if action == "wrong key" {
				before = encryptFixture(t, newIdentity(t).Recipient(), "secret", false)
			}
			if action == "corrupt ciphertext" {
				before[len(before)-1] ^= 1
			}
			writeFile(t, directory, name, string(before))
			source := filepath.Join(directory, filepath.FromSlash(name))
			scratch := t.TempDir()
			for _, variable := range []string{"TMPDIR", "TMP", "TEMP"} {
				t.Setenv(variable, scratch)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			executable = strings.ReplaceAll(filepath.ToSlash(executable), "'", `'"'"'`)
			t.Setenv("GIT_EDITOR", "'"+executable+"' -test.run=^TestEditEditor$ --")
			t.Setenv("GIT_AGE_TEST_EDITOR", action)
			t.Setenv("GIT_AGE_TEST_SOURCE", source)
			var args []string
			recipient := identity
			if action == "recipient override" {
				recipient = newIdentity(t)
				args = []string{"-r", recipient.Recipient().String()}
			}
			if action == "identity flag" {
				if err := os.Rename(filepath.Join(directory, ".gitage.key"), filepath.Join(directory, "identity file.key")); err != nil {
					t.Fatal(err)
				}
				args = []string{"-i", "identity file.key"}
			}
			if action == "dry run" {
				args = []string{"-n"}
			}
			if action == "unprotected" {
				name = "public.txt"
				writeFile(t, directory, name, "public")
			}
			if action == "directory" {
				name = "sub"
			}
			var output bytes.Buffer
			root := newRootCommand()
			root.SetOut(&output)
			root.SetErr(&output)
			workingDirectory := directory
			if action == "subdirectory" {
				workingDirectory = filepath.Join(directory, "sub")
				name = filepath.Base(name)
			}
			root.SetArgs(append(append([]string{"-C", workingDirectory, "edit"}, args...), name))
			err = root.Execute()
			wantError := action == "fail" || action == "concurrent" || action == "delete" || action == "wrong key" || action == "corrupt ciphertext" || action == "unprotected" || action == "directory"
			if (err != nil) != wantError {
				t.Fatalf("edit: %v, output: %s", err, &output)
			}
			after := readFile(t, directory, "sub/a ' $ file.env")
			switch action {
			case "change", "replace", "recipient override", "identity flag", "subdirectory":
				assertDecrypts(t, after, recipient, []byte("edited\n"))
				if action == "recipient override" {
					if _, err := age.Decrypt(bytes.NewReader(after), identity); err == nil {
						t.Fatal("old recipient can still decrypt")
					}
				}
			case "unlocked":
				if string(after) != "edited\n" || !strings.Contains(output.String(), "is unlocked") {
					t.Fatal("unlocked edit did not stay plaintext with a warning")
				}
			case "concurrent":
				if string(after) != "concurrent edit" || !strings.Contains(err.Error(), "changed while preparing replacement") {
					t.Fatal("concurrent edit was overwritten")
				}
			default:
				if !bytes.Equal(before, after) {
					t.Fatal("original ciphertext changed")
				}
			}
			if action == "dry run" && output.String() != "would edit: sub/a ' $ file.env\n" {
				t.Fatalf("dry run: %s", &output)
			}
			entries, err := os.ReadDir(scratch)
			if err != nil || len(entries) != 0 {
				t.Fatalf("temporary files left behind: %v, %v", entries, err)
			}
			info, err := os.Stat(source)
			if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
				t.Fatalf("original permissions: %v, %v", info, err)
			}
		})
	}
}

func TestEditDryRun(t *testing.T) {
	for _, scenario := range []string{"locked", "armored", "unlocked", "wrong key", "corrupt ciphertext", "missing key", "missing identity", "invalid recipient"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			t.Setenv("GIT_AGE_KEY_FILE", "")
			t.Setenv("GIT_AGE_RECIPIENT", "")
			t.Setenv("GIT_EDITOR", "git-age-editor-that-does-not-exist")
			scratch := t.TempDir()
			for _, variable := range []string{"TMPDIR", "TMP", "TEMP"} {
				t.Setenv(variable, scratch)
			}
			identity := newIdentity(t)
			writeFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+identity.Recipient().String()+"\n")
			if scenario != "missing key" {
				writeFile(t, directory, ".gitage.key", identity.String()+"\n")
			}
			content := encryptFixture(t, identity.Recipient(), "secret", scenario == "armored")
			var flags []string
			wantError := ""
			switch scenario {
			case "unlocked":
				content = []byte("plaintext")
				flags = []string{"-i", "missing.key", "-r", "invalid"}
			case "wrong key":
				content = encryptFixture(t, newIdentity(t).Recipient(), "secret", false)
				wantError = "cannot decrypt secret.env"
			case "corrupt ciphertext":
				content[len(content)-1] ^= 1
				wantError = "cannot decrypt secret.env"
			case "missing key":
				wantError = "no identity configured"
			case "missing identity":
				flags = []string{"-i", "missing.key"}
				wantError = "missing.key"
			case "invalid recipient":
				flags = []string{"-r", "invalid"}
				wantError = "invalid recipient"
			}
			writeFile(t, directory, "secret.env", string(content))
			before := installSnapshot(t, directory)
			args := append([]string{"-n"}, flags...)
			output, err := runCommand(directory, "edit", append(args, "secret.env")...)
			if wantError == "" {
				if err != nil || output != "would edit: secret.env\n" {
					t.Fatalf("dry run: %q, %v", output, err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), wantError) || output != "" {
					t.Fatalf("dry run: %q, %v; want %q", output, err, wantError)
				}
				_, realErr := runCommand(directory, "edit", append(flags, "secret.env")...)
				if realErr == nil || realErr.Error() != err.Error() {
					t.Fatalf("validation differs: dry run %v, real edit %v", err, realErr)
				}
			}
			assertSnapshotUnchanged(t, directory, before)
			if entries, err := os.ReadDir(scratch); err != nil || len(entries) != 0 {
				t.Fatalf("temporary files left behind: %v, %v", entries, err)
			}
		})
	}
}

func TestEditEditor(t *testing.T) {
	action := os.Getenv("GIT_AGE_TEST_EDITOR")
	if action == "" {
		return
	}
	fail := func(err error) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	path := os.Args[len(os.Args)-1]
	source := os.Getenv("GIT_AGE_TEST_SOURCE")
	if action != "unlocked" {
		original, err := os.ReadFile(source)
		if err != nil || !bytes.HasPrefix(original, []byte("age-encryption.org/v1\n")) {
			fail(fmt.Errorf("original is not encrypted during editing: %v", err))
		}
		if path == source {
			fail(fmt.Errorf("editor was given the original ciphertext"))
		}
		for _, private := range []string{path, filepath.Dir(path)} {
			info, err := os.Stat(private)
			if err != nil || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
				fail(fmt.Errorf("editor copy is not private: %v", err))
			}
		}
		plaintext, err := os.ReadFile(path)
		if err != nil || string(plaintext) != "secret\r\nwithout final newline" {
			fail(fmt.Errorf("editor did not receive the decrypted content: %v", err))
		}
	}
	if action == "unchanged" {
		os.Exit(0)
	}
	if action == "delete" {
		if err := os.Remove(path); err != nil {
			fail(err)
		}
		os.Exit(0)
	}
	if action == "concurrent" {
		if err := os.WriteFile(source, []byte("concurrent edit"), 0600); err != nil {
			fail(err)
		}
	}
	if action == "replace" {
		if err := os.WriteFile(path+".new", []byte("edited\n"), 0600); err != nil {
			fail(err)
		}
		if err := os.Rename(path+".new", path); err != nil {
			fail(err)
		}
	} else if err := os.WriteFile(path, []byte("edited\n"), 0600); err != nil {
		fail(err)
	}
	if action == "fail" {
		os.Exit(7)
	}
	os.Exit(0)
}
