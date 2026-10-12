package cli

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestAgeCLIInteroperability(t *testing.T) {
	directory := t.TempDir()
	key := filepath.Join(directory, "identity")
	if output, err := exec.Command("age-keygen", "-o", key).CombinedOutput(); err != nil {
		t.Fatalf("age-keygen: %v\n%s", err, output)
	}
	public, err := exec.Command("age-keygen", "-y", key).Output()
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := age.ParseX25519Recipient(strings.TrimSpace(string(public)))
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("API_TOKEN=secret\x00\xff\n")
	encrypted := encryptFixture(t, recipient, string(plaintext), false)
	decrypt := exec.Command("age", "-d", "-i", key)
	decrypt.Stdin = bytes.NewReader(encrypted)
	output, err := decrypt.Output()
	if err != nil || !bytes.Equal(output, plaintext) {
		t.Fatalf("age CLI could not decrypt Go ciphertext: %v, %q", err, output)
	}
	encrypt := exec.Command("age", "-r", recipient.String())
	encrypt.Stdin = bytes.NewReader(plaintext)
	ciphertext, err := encrypt.Output()
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, directory, ".gitage", "[files]\nsecret.env\n")
	writeFile(t, directory, "secret.env", string(ciphertext))
	mustCommand(t, directory, "unlock", "-i", key)
	if got := readFile(t, directory, "secret.env"); !bytes.Equal(got, plaintext) {
		t.Fatalf("Go unlock of age CLI ciphertext: %q", got)
	}
}
