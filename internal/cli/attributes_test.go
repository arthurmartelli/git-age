package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCommandsRefreshAttributes(t *testing.T) {
	for _, command := range []string{"unlock", "rekey", "edit"} {
		for _, scenario := range []string{"enabled", "disabled", "dry run", "failure"} {
			t.Run(command+"/"+scenario, func(t *testing.T) {
				isolateHookEnvironment(t)
				directory := t.TempDir()
				initKeygenRepo(t, directory)
				identity := newIdentity(t)
				writeFile(t, directory, ".gitage.key", identity.String()+"\n")
				writeFile(t, directory, ".gitage", "[files]\n*.env\n")
				writeFile(t, directory, "secret.env", string(encryptFixture(t, identity.Recipient(), "secret\r\nwithout final newline", false)))
				attributes := installGitPath(t, directory, "info/attributes")
				writeFile(t, filepath.Dir(attributes), "attributes", "# user attributes\n*.txt -diff\n")
				installArgs := []string{}
				if scenario == "disabled" {
					installArgs = []string{"--no-filter"}
				}
				mustCommand(t, directory, "install", installArgs...)
				if err := os.Chmod(attributes, 0640); err != nil {
					t.Fatal(err)
				}
				before := readFile(t, filepath.Dir(attributes), "attributes")
				writeFile(t, directory, ".gitage", "[files]\n*.env\n*.secret\n")
				args := []string{"secret.env"}
				if scenario == "dry run" {
					args = append([]string{"-n"}, args...)
				}
				if command == "edit" {
					executable, err := os.Executable()
					if err != nil {
						t.Fatal(err)
					}
					t.Setenv("GIT_EDITOR", "'"+strings.ReplaceAll(filepath.ToSlash(executable), "'", `'"'"'`)+"' -test.run=^TestEditEditor$ --")
					t.Setenv("GIT_AGE_TEST_EDITOR", "unchanged")
					t.Setenv("GIT_AGE_TEST_SOURCE", filepath.Join(directory, "secret.env"))
					if scenario == "failure" {
						t.Setenv("GIT_AGE_TEST_EDITOR", "fail")
					}
				} else if scenario == "failure" {
					writeFile(t, directory, ".gitage.key", newIdentity(t).String()+"\n")
				}
				output, err := runCommand(directory, command, args...)
				if (err != nil) != (scenario == "failure") {
					t.Fatalf("%s: %v, %s", command, err, output)
				}
				after := readFile(t, filepath.Dir(attributes), "attributes")
				if scenario == "failure" || scenario == "dry run" {
					if !bytes.Equal(before, after) {
						t.Fatal("failed operation or dry run refreshed attributes")
					}
					return
				}
				if !bytes.HasPrefix(after, []byte("# user attributes\n*.txt -diff\n")) || !bytes.Contains(after, []byte("*.secret")) {
					t.Fatalf("missing refreshed patterns or user attributes: %s", after)
				}
				for _, attribute := range []string{"diff", "filter", "merge"} {
					want := "age"
					if scenario == "disabled" && attribute == "filter" {
						want = "unset"
					}
					if got := runGit(t, directory, "check-attr", attribute, "--", "new.secret"); !bytes.Contains(got, []byte(": "+attribute+": "+want+"\n")) {
						t.Fatalf("%s: %s", attribute, got)
					}
				}
				if info, err := os.Stat(attributes); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0640 {
					t.Fatalf("attributes permissions: %v, %v", info, err)
				}
			})
		}
	}
}

func TestRulesLineEndingsPreserveCiphertext(t *testing.T) {
	for _, ending := range []string{"\n", "\r\n", "\r"} {
		t.Run(strings.ReplaceAll(strings.ReplaceAll(ending, "\r", "CR"), "\n", "LF"), func(t *testing.T) {
			isolateHookEnvironment(t)
			directory, identity, ciphertext := cleanFixture(t, []byte("original\n"), false)
			mustCommand(t, directory, "unlock")
			writeFile(t, directory, ".gitage", strings.ReplaceAll("[files]\n*.env\n[recipients]\n"+identity.Recipient().String()+"\n", "\n", ending))
			mustCommand(t, directory, "lock")
			if !bytes.Equal(ciphertext, readFile(t, directory, "secret.env")) {
				t.Fatal("equivalent line endings prevented ciphertext reuse")
			}
		})
	}
}
