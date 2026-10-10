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
			identity := rekeyIdentity(t)
			writeStatusFile(t, directory, ".gitage.key", identity.String()+"\n")
			writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n")
			name := "sub/a ' $ file.env"
			before := encryptUnlockFixture(t, identity, "secret\r\nwithout final newline", false)
			if action == "unlocked" {
				before = []byte("plaintext")
			}
			if action == "wrong key" {
				before = encryptUnlockFixture(t, rekeyIdentity(t), "secret", false)
			}
			if action == "corrupt ciphertext" {
				before[len(before)-1] ^= 1
			}
			writeStatusFile(t, directory, name, string(before))
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
				recipient = rekeyIdentity(t)
				args = []string{"-r", recipient.Recipient().String()}
			}
			if action == "identity flag" {
				if err := os.Rename(filepath.Join(directory, ".gitage.key"), filepath.Join(directory, "identity file.key")); err != nil {
					t.Fatal(err)
				}
				args = []string{"-i", "identity file.key"}
			}
			if action == "dry run" {
				args = []string{"-n", "-i", "missing.key"}
			}
			if action == "unprotected" {
				name = "public.txt"
				writeStatusFile(t, directory, name, "public")
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
			after := readRekeyFile(t, directory, "sub/a ' $ file.env")
			switch action {
			case "change", "replace", "recipient override", "identity flag", "subdirectory":
				assertRekeyPlaintext(t, after, recipient, "edited\n")
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
