package repository

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestForgetStatWindowsShortPath(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	name, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, 32768)
	n, err := syscall.GetShortPathName(name, &buffer[0], uint32(len(buffer)))
	if err != nil || n == 0 || n >= uint32(len(buffer)) {
		t.Fatalf("short path: length %d, %v", n, err)
	}
	short := syscall.UTF16ToString(buffer[:n])
	if strings.EqualFold(root, short) {
		t.Skip("filesystem does not provide a short path alias")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	if output, err := exec.Command("git", "-C", root, "-c", "init.templateDir=", "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("init: %v, %s", err, output)
	}
	path := filepath.Join(short, "ours")
	if err := os.WriteFile(path, []byte("merged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := forgetStat([]replacement{{path: path}}); err != nil {
		t.Fatalf("refresh through short path: %v", err)
	}
}

func TestWriteExistingPreservesWindowsMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.env")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(path, 0600) })
	stream := path + ":test"
	if err := os.WriteFile(stream, []byte("kept"), 0600); err != nil {
		t.Fatal(err)
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	attributes, err := syscall.GetFileAttributes(name)
	if err != nil {
		t.Fatal(err)
	}
	attributes |= syscall.FILE_ATTRIBUTE_READONLY | syscall.FILE_ATTRIBUTE_HIDDEN
	if err := syscall.SetFileAttributes(name, attributes); err != nil {
		t.Fatal(err)
	}

	for _, content := range []string{"longer encrypted content", "short"} {
		if err := writeExisting(path, []byte(content)); err != nil {
			t.Fatal(err)
		}
		after, err := os.ReadFile(path)
		if err != nil || string(after) != content {
			t.Fatalf("file content: %q, %v", after, err)
		}
		afterAttributes, err := syscall.GetFileAttributes(name)
		if err != nil || afterAttributes != attributes {
			t.Fatalf("attributes: got %#x, want %#x: %v", afterAttributes, attributes, err)
		}
		afterStream, err := os.ReadFile(stream)
		if err != nil || string(afterStream) != "kept" {
			t.Fatalf("alternate stream: %q, %v", afterStream, err)
		}
	}
}
