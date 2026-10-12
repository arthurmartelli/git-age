package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestLockUnlockMetadata(t *testing.T) {
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	t.Setenv("GIT_AGE_KEY_FILE", "")
	t.Setenv("GIT_AGE_RECIPIENT", "")
	t.Setenv("GIT_AGE_TRUSTED_RECIPIENTS", "")
	identity := newIdentity(t)
	writeFile(t, directory, ".gitage", "[files]\nsecret.env\nconfig/*.yaml\n[recipients]\n"+identity.Recipient().String()+"\n")
	writeFile(t, directory, ".gitage.key", identity.String()+"\n")
	originals := map[string]string{"secret.env": "API_TOKEN=s3cr3t\n", "config/credentials.yaml": "password: hunter2\n"}
	for path, text := range originals {
		writeFile(t, directory, path, text)
	}
	tool := func(name string, args ...string) string {
		t.Helper()
		command := exec.Command(name, args...)
		command.Dir = directory
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, output)
		}
		return string(output)
	}
	// Optional filesystem support matches the former shell suite's skips.
	setup := func(name string, args ...string) {
		t.Helper()
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("metadata tool unavailable: %s", name)
		}
		command := exec.Command(name, args...)
		command.Dir = directory
		if output, err := command.CombinedOutput(); err != nil {
			t.Skipf("filesystem metadata unavailable: %s: %v\n%s", name, err, output)
		}
	}
	var metadata func() string
	switch runtime.GOOS {
	case "linux":
		for _, name := range []string{"getfacl", "getfattr"} {
			if _, err := exec.LookPath(name); err != nil {
				t.Skipf("metadata tool unavailable: %s", name)
			}
		}
		setup("setfacl", "-m", "u:65534:r", "secret.env")
		setup("setfattr", "-n", "user.test", "-v", "kept", "secret.env")
		if err := os.Chmod(filepath.Join(directory, "secret.env"), 0640); err != nil {
			t.Fatal(err)
		}
		setup("setfacl", "-d", "-m", "u:65534:rw", "config")
		metadata = func() string {
			secret := tool("getfacl", "-cn", "secret.env")
			if !strings.Contains(secret, "user:65534:r--") {
				t.Fatalf("missing file ACL: %s", secret)
			}
			credentials := tool("getfacl", "-cn", "config/credentials.yaml")
			if strings.Contains(credentials, "user:65534:") {
				t.Fatalf("replacement inherited directory ACL: %s", credentials)
			}
			attribute := tool("getfattr", "--only-values", "-n", "user.test", "secret.env")
			if strings.TrimSpace(attribute) != "kept" {
				t.Fatalf("lost xattr: %q", attribute)
			}
			return secret + credentials + attribute
		}
	case "darwin":
		if err := os.Chmod(filepath.Join(directory, "secret.env"), 0640); err != nil {
			t.Fatal(err)
		}
		setup("chmod", "+a", "everyone allow read", "secret.env")
		setup("xattr", "-w", "user.test", "kept", "secret.env")
		setup("chmod", "+a", "everyone allow write,file_inherit,directory_inherit", "config")
		metadata = func() string {
			secret := tool("ls", "-le", "secret.env")
			if !strings.Contains(secret, "group:everyone allow read") {
				t.Fatalf("missing file ACL: %s", secret)
			}
			credentials := tool("ls", "-le", "config/credentials.yaml")
			if strings.Contains(credentials, "group:everyone") {
				t.Fatalf("replacement inherited directory ACL: %s", credentials)
			}
			attribute := tool("xattr", "-p", "user.test", "secret.env")
			if strings.TrimSpace(attribute) != "kept" {
				t.Fatalf("lost xattr: %q", attribute)
			}
			// ls also prints file sizes and timestamps, which change during encryption.
			return secret[strings.Index(secret, "\n")+1:] + credentials[strings.Index(credentials, "\n")+1:] + attribute
		}
	case "windows":
		setup("icacls", "secret.env", "/grant", "*S-1-1-0:(R)")
		setup("powershell", "-NoProfile", "-NonInteractive", "-Command", "Set-Content -LiteralPath secret.env -Stream test -Value kept -NoNewline -ErrorAction Stop")
		setup("attrib", "+R", "+H", "secret.env")
		t.Cleanup(func() { exec.Command("attrib", "-R", "-H", filepath.Join(directory, "secret.env")).Run() })
		metadata = func() string {
			attributes := tool("powershell", "-NoProfile", "-NonInteractive", "-Command", "$a = [IO.File]::GetAttributes('secret.env'); if (-not ($a.HasFlag([IO.FileAttributes]::ReadOnly) -and $a.HasFlag([IO.FileAttributes]::Hidden))) { exit 1 }; [int]$a")
			acl := tool("icacls", "secret.env")
			if !strings.Contains(acl, "S-1-1-0") && !strings.Contains(acl, "Everyone:(R)") {
				t.Fatalf("missing explicit Everyone ACL: %s", acl)
			}
			stream := tool("powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-Content -LiteralPath secret.env -Stream test -Raw -Force -ErrorAction Stop")
			if strings.TrimSpace(stream) != "kept" {
				t.Fatalf("lost alternate stream: %q", stream)
			}
			return attributes + acl + stream
		}
	default:
		t.Skip("metadata checks support Linux, macOS and Windows")
	}
	before := metadata()
	// Compare all files outside .git so no leftover replacement files go unnoticed.
	beforePaths := workingFiles(t, directory)
	for _, command := range []string{"lock", "unlock"} {
		mustCommand(t, directory, command)
		if got := metadata(); got != before {
			t.Fatalf("%s changed metadata:\n%s\nwant:\n%s", command, got, before)
		}
		if !reflect.DeepEqual(beforePaths, workingFiles(t, directory)) {
			t.Fatalf("%s left stray files", command)
		}
		for path, plaintext := range originals {
			content := readFile(t, directory, path)
			if command == "lock" {
				assertDecrypts(t, content, identity, []byte(plaintext))
			} else if string(content) != plaintext {
				t.Fatalf("unlock %s: %q", path, content)
			}
			if runtime.GOOS != "windows" {
				info, err := os.Stat(filepath.Join(directory, path))
				want := os.FileMode(0600)
				if path == "secret.env" {
					want = 0640
				}
				if err != nil || info.Mode().Perm() != want {
					t.Fatalf("%s permissions: %v, %v", path, info, err)
				}
			}
		}
	}
}

func workingFiles(t *testing.T, directory string) []string {
	t.Helper()
	var paths []string
	err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && entry.Name() == ".git" {
			return filepath.SkipDir
		}
		relative, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		paths = append(paths, relative)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return paths
}

func TestLockUnreadableChangesNothing(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires Unix permission enforcement")
	}
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	t.Setenv("GIT_AGE_KEY_FILE", "")
	t.Setenv("GIT_AGE_RECIPIENT", "")
	t.Setenv("GIT_AGE_TRUSTED_RECIPIENTS", "")
	identity := newIdentity(t)
	writeFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\n"+identity.Recipient().String()+"\n")
	writeFile(t, directory, "a.env", "first secret\n")
	writeFile(t, directory, "z.env", "unreadable secret\n")
	before := workingFiles(t, directory)
	unreadable := filepath.Join(directory, "z.env")
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(unreadable, 0600) })
	if _, err := runCommand(directory, "lock"); err == nil || !strings.Contains(err.Error(), "z.env") {
		t.Fatalf("unreadable lock: %v", err)
	}
	if err := os.Chmod(unreadable, 0600); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, directory, "a.env"), []byte("first secret\n")) || !bytes.Equal(readFile(t, directory, "z.env"), []byte("unreadable secret\n")) || !reflect.DeepEqual(before, workingFiles(t, directory)) {
		t.Fatal("failed lock changed files or left temporary files")
	}
}
