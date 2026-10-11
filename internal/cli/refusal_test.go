package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
)

func TestMalformedPatternsRefusedBeforeChanges(t *testing.T) {
	for _, test := range []struct{ pattern, diagnostic string }{
		{"secret[.env", "pattern has an unterminated ["},
		{"secret[].env", "pattern has an unterminated ["},
		{"secret[!].env", "pattern has an unterminated ["},
		{"secret[a\\", "pattern has an unterminated ["},
		{"secret[[:digit:].env", "pattern has an unterminated ["},
		{"secret\\", "pattern ends with an unescaped backslash"},
		{"secret[[:unknown:]].env", "unknown character class [:unknown:]"},
	} {
		t.Run(test.pattern, func(t *testing.T) {
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			writeStatusFile(t, directory, ".gitage", "[files]\n"+test.pattern+"\n")
			writeStatusFile(t, directory, "secret.env", "plaintext\n")
			runGit(t, directory, "add", ".gitage", "secret.env")
			before := installSnapshot(t, directory)
			for _, args := range [][]string{{"status"}, {"lock"}, {"check", "--cached"}, {"install"}} {
				var stdout, stderr bytes.Buffer
				code := Run(append([]string{"-C", directory}, args...), &stdout, &stderr)
				if code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), ".gitage:2: "+test.diagnostic) {
					t.Fatalf("%v: exit %d, stdout %q, stderr %q", args, code, &stdout, &stderr)
				}
				if !reflect.DeepEqual(before, installSnapshot(t, directory)) {
					t.Fatalf("%v modified files on invalid rules", args)
				}
			}
		})
	}
}

func TestValidPatternSyntaxStillMatchesGit(t *testing.T) {
	for _, test := range []struct{ pattern, name string }{
		{`literal\[.env`, "literal[.env"},
		{`file[[]x.env`, "file[x.env"},
		{`file[]]x.env`, "file]x.env"},
		{`file[\]].env`, "file].env"},
		{`file[!a].env`, "fileb.env"},
		{`file[^a].env`, "fileb.env"},
		{`file[a-c].env`, "fileb.env"},
		{`file[[:digit:]].env`, "file7.env"},
		{`[[:digit:]]`, "7"},
		{`file[[:alpha:]0].env`, "filea.env"},
		{`\[files]`, "[files]"},
		{"space\\ ", "space "},
		{"space\\   ", "space "},
	} {
		t.Run(test.pattern, func(t *testing.T) {
			if runtime.GOOS == "windows" && strings.HasSuffix(test.name, " ") {
				t.Skip("Windows removes trailing spaces from ordinary file paths")
			}
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			writeStatusFile(t, directory, ".gitage", "[files]\r\n"+test.pattern+"\r\n")
			writeStatusFile(t, directory, test.name, "plaintext\n")
			output, err := runCommand(directory, "status")
			if err != nil || output != "UNLOCKED   "+test.name+"\n" {
				t.Fatalf("valid pattern: %v, %q", err, output)
			}
		})
	}
}

func TestInvalidRecipientDiagnostic(t *testing.T) {
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	writeStatusFile(t, directory, ".gitage", "[files]\n*.env\n[recipients]\nnot-a-key\n")
	writeStatusFile(t, directory, "secret.env", "secret\n")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-C", directory, "status"}, &stdout, &stderr)
	if code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), ".gitage:4: is not an age recipient") {
		t.Fatalf("invalid recipient: exit %d, stdout %q, stderr %q", code, &stdout, &stderr)
	}
}

func TestProtectedIdentityRefusalChangesNothing(t *testing.T) {
	for _, format := range []string{"recipient", "recipient armored", "scrypt", "scrypt armored", "SSH", "PEM"} {
		t.Run(format, func(t *testing.T) {
			t.Setenv("GIT_AGE_KEY_FILE", "")
			directory, identity, _ := cleanFixture(t, []byte("secret\n"), false)
			var protected []byte
			diagnostic := "encrypted age identity"
			switch format {
			case "recipient", "recipient armored":
				protected = encryptUnlockFixture(t, identity, identity.String()+"\n", format == "recipient armored")
			case "scrypt", "scrypt armored":
				recipient, err := age.NewScryptRecipient("test passphrase")
				if err != nil {
					t.Fatal(err)
				}
				recipient.SetWorkFactor(1)
				protected = encryptRecipientFixture(t, recipient, identity.String()+"\n", format == "scrypt armored")
			case "SSH", "PEM":
				diagnostic = "passphrase-protected"
				_, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				var block *pem.Block
				if format == "SSH" {
					block, err = ssh.MarshalPrivateKeyWithPassphrase(key, "test", []byte("test passphrase"))
				} else {
					der, marshalErr := x509.MarshalPKCS8PrivateKey(key)
					if marshalErr != nil {
						t.Fatal(marshalErr)
					}
					block, err = x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", der, []byte("test passphrase"), x509.PEMCipherAES256)
				}
				if err != nil {
					t.Fatal(err)
				}
				protected = pem.EncodeToMemory(block)
			}
			writeStatusFile(t, directory, "protected.key", string(protected))
			before := installSnapshot(t, directory)
			var stdout, stderr bytes.Buffer
			code := Run([]string{"-C", directory, "unlock", "-i", "protected.key"}, &stdout, &stderr)
			if code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), diagnostic) || !strings.Contains(stderr.String(), "protected.key") {
				t.Fatalf("protected identity: exit %d, stdout %q, stderr %q", code, &stdout, &stderr)
			}
			if !reflect.DeepEqual(before, installSnapshot(t, directory)) {
				t.Fatal("rejected identity changed files")
			}
		})
	}
}

func TestLockWarnsForExcludedIdentity(t *testing.T) {
	for _, scenario := range []string{"excluded", "included", "multiple identities", "nested recipient", "no identity", "SSH comments"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("GIT_AGE_KEY_FILE", "")
			t.Setenv("GIT_AGE_RECIPIENT", "")
			directory := t.TempDir()
			initKeygenRepo(t, directory)
			own, other := rekeyIdentity(t), rekeyIdentity(t)
			writeStatusFile(t, directory, ".gitage.key", own.String()+"\n")
			rules := "[files]\n*.env\n[recipients]\n" + other.Recipient().String() + "\n"
			path := "secret.env"
			var decrypting age.Identity = other
			switch scenario {
			case "included":
				rules += own.Recipient().String() + "\n"
			case "multiple identities":
				writeStatusFile(t, directory, ".gitage.key", own.String()+"\n"+other.String()+"\n")
			case "nested recipient":
				path = "sub/secret.env"
				writeStatusFile(t, directory, "sub/.gitage", "[recipients]\n"+own.Recipient().String()+"\n")
			case "no identity":
				if err := os.Remove(filepath.Join(directory, ".gitage.key")); err != nil {
					t.Fatal(err)
				}
			case "SSH comments":
				_, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				block, err := ssh.MarshalPrivateKey(key, "test")
				if err != nil {
					t.Fatal(err)
				}
				writeStatusFile(t, directory, ".gitage.key", string(pem.EncodeToMemory(block)))
				signer, err := ssh.NewSignerFromKey(key)
				if err != nil {
					t.Fatal(err)
				}
				rules = "[files]\n*.env\n[recipients]\n" + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + " custom comment\n"
				decrypting, err = agessh.NewEd25519Identity(key)
				if err != nil {
					t.Fatal(err)
				}
			}
			writeStatusFile(t, directory, ".gitage", rules)
			writeStatusFile(t, directory, path, "secret\n")
			var stdout, stderr bytes.Buffer
			code := Run([]string{"-C", directory, "lock"}, &stdout, &stderr)
			if code != 0 || stdout.Len() != 0 {
				t.Fatalf("lock: exit %d, stdout %q, stderr %q", code, &stdout, &stderr)
			}
			if scenario == "excluded" {
				if !strings.Contains(stderr.String(), "is not among the recipients") || !strings.Contains(stderr.String(), path) {
					t.Fatalf("missing warning: %q", &stderr)
				}
			} else if stderr.Len() != 0 {
				t.Fatalf("unnecessary warning: %q", &stderr)
			}
			ciphertext, err := os.ReadFile(filepath.Join(directory, path))
			if err != nil {
				t.Fatal(err)
			}
			assertCleanDecrypts(t, ciphertext, decrypting, []byte("secret\n"))
			if scenario == "excluded" {
				if _, err := age.Decrypt(bytes.NewReader(ciphertext), own); err == nil {
					t.Fatal("warning must not silently add the excluded identity")
				}
			}
		})
	}
}
