package cli

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestTextconv(t *testing.T) {
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	t.Setenv("GIT_AGE_KEY_FILE", "")
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	writeStatusFile(t, directory, ".gitage.key", identity.String()+"\n")
	corrupt := encryptUnlockFixture(t, identity, "secret", false)
	corrupt[len(corrupt)-1] ^= 1

	for _, test := range []struct {
		name    string
		content []byte
		want    string
	}{
		{"plaintext", []byte("plain\r\ntext"), "plain\r\ntext"},
		{"empty", nil, ""},
		{"encrypted", encryptUnlockFixture(t, identity, "secret\n", false), "secret\n"},
		{"armored", encryptUnlockFixture(t, identity, "secret\n", true), "secret\n"},
		{"binary", []byte("binary\x00data"), binaryPlaceholder([]byte("binary\x00data"))},
		{"encrypted binary", encryptUnlockFixture(t, identity, "binary\x00data", false), binaryPlaceholder([]byte("binary\x00data"))},
		{"wrong key", encryptUnlockFixture(t, other, "secret", false), "cannot decrypt with configured identities"},
		{"corrupt", corrupt, "cannot decrypt with configured identities"},
	} {
		t.Run(test.name, func(t *testing.T) {
			writeStatusFile(t, directory, "blob", string(test.content))
			var output, stderr bytes.Buffer
			code := Run([]string{"-C", directory, "textconv", "blob"}, &output, &stderr)
			want := test.want
			if test.name == "wrong key" || test.name == "corrupt" {
				want = fmt.Sprintf("[git-age: encrypted, %s; sha256 %x]\n", want, sha256.Sum256(test.content))
			}
			if code != 0 || output.String() != want || stderr.Len() != 0 {
				t.Fatalf("exit %d, output %q, stderr %q; want %q", code, &output, &stderr, want)
			}
			after, err := os.ReadFile(filepath.Join(directory, "blob"))
			if err != nil || !bytes.Equal(after, test.content) {
				t.Fatalf("input changed: %v", err)
			}
		})
	}

	for _, key := range []string{"missing", "invalid"} {
		t.Run(key+" identity", func(t *testing.T) {
			t.Setenv("GIT_AGE_KEY_FILE", filepath.Join(directory, key))
			if key == "invalid" {
				writeStatusFile(t, directory, key, "invalid key\n")
			}
			writeStatusFile(t, directory, "blob", string(corrupt))
			var output, stderr bytes.Buffer
			if code := Run([]string{"-C", directory, "textconv", "blob"}, &output, &stderr); code != 0 || !strings.HasPrefix(output.String(), "[git-age: encrypted, ") || stderr.Len() != 0 {
				t.Fatalf("exit %d, output %q, stderr %q", code, &output, &stderr)
			}
		})
	}
	t.Run("no identity", func(t *testing.T) {
		directory := t.TempDir()
		initKeygenRepo(t, directory)
		writeStatusFile(t, directory, "blob", string(corrupt))
		var output, stderr bytes.Buffer
		if code := Run([]string{"-C", directory, "textconv", "blob"}, &output, &stderr); code != 0 || !strings.Contains(output.String(), "encrypted, no identity configured; sha256 ") {
			t.Fatalf("exit %d, output %q, stderr %q", code, &output, &stderr)
		}
	})
	for _, args := range [][]string{{}, {"blob", "extra"}, {"absent"}} {
		var output, stderr bytes.Buffer
		if code := Run(append([]string{"-C", directory, "textconv"}, args...), &output, &stderr); code != 2 || output.Len() != 0 {
			t.Fatalf("args %v: exit %d, output %q", args, code, &output)
		}
	}
}

func binaryPlaceholder(content []byte) string {
	return fmt.Sprintf("[git-age: binary content, %d bytes; sha256 %x]\n", len(content), sha256.Sum256(content))
}

func TestTextconvGitDiff(t *testing.T) {
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	t.Setenv("GIT_AGE_KEY_FILE", "")
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	writeStatusFile(t, directory, ".gitage.key", identity.String()+"\n")
	writeStatusFile(t, directory, ".gitattributes", "secret.env diff=age\n")
	writeStatusFile(t, directory, "secret.env", string(encryptUnlockFixture(t, identity, "TOKEN=before\n", false)))

	name := "git-age"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	executable := filepath.Join(t.TempDir(), name)
	build := exec.Command("go", "build", "-o", executable, "./cmd/git-age")
	build.Dir = "../.."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	git := func(args ...string) string {
		t.Helper()
		output, err := exec.Command("git", append([]string{"-C", directory}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, output)
		}
		return string(output)
	}
	git("config", "diff.age.textconv", "\""+filepath.ToSlash(executable)+"\" textconv")
	git("add", ".gitattributes", "secret.env")
	writeStatusFile(t, directory, "secret.env", string(encryptUnlockFixture(t, identity, "TOKEN=after\n", true)))
	output := git("diff", "--no-ext-diff", "--", "secret.env")
	if !strings.Contains(output, "-TOKEN=before\n+TOKEN=after\n") || strings.Contains(output, "AGE ENCRYPTED") {
		t.Fatalf("unexpected diff:\n%s", output)
	}
}
