package repository

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

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
