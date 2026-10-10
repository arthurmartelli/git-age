package repository

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestWipeEditCopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.env")
	secret := bytes.Repeat([]byte("secret"), 10000)
	if err := os.WriteFile(path, secret, 0600); err != nil {
		t.Fatal(err)
	}
	if err := wipeEditCopy(path); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(content, make([]byte, len(secret))) {
		t.Fatalf("copy was not overwritten before removal: %v", err)
	}
}
