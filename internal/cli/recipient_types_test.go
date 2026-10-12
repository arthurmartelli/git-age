package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// The test executable doubles as an age plugin, exercising the real protocol.
func TestMain(m *testing.M) {
	if strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe") != "age-plugin-gitagetest" {
		os.Exit(m.Run())
	}
	p, err := plugin.New("gitagetest")
	if err != nil {
		panic(err)
	}
	p.HandleRecipient(func(data []byte) (age.Recipient, error) {
		recipients, err := age.ParseRecipients(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		return recipients[0], nil
	})
	parseIdentity := func(data []byte) (age.Identity, error) {
		identities, err := age.ParseIdentities(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		return identities[0], nil
	}
	p.HandleIdentity(parseIdentity)
	p.HandleIdentityAsRecipient(func(data []byte) (age.Recipient, error) {
		identity, err := parseIdentity(data)
		if err != nil {
			return nil, err
		}
		switch identity := identity.(type) {
		case *age.X25519Identity:
			return identity.Recipient(), nil
		case *age.HybridIdentity:
			return identity.Recipient(), nil
		}
		return nil, fmt.Errorf("unexpected identity type %T", identity)
	})
	os.Exit(p.Main())
}

func installTestPlugin(t *testing.T) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	name := "age-plugin-gitagetest" + filepath.Ext(executable)
	if filepath.Ext(executable) != ".exe" {
		name = "age-plugin-gitagetest"
	}
	path := filepath.Join(bin, name)
	if err := os.Link(executable, path); err != nil {
		content, err := os.ReadFile(executable)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestLockRecipientTypes(t *testing.T) {
	installTestPlugin(t)
	hybrid, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	native := newIdentity(t)
	for _, kind := range []struct {
		name, key, recipient string
		identity             age.Identity
	}{
		{"post-quantum", hybrid.String(), hybrid.Recipient().String(), hybrid},
		{"plugin", plugin.EncodeIdentity("gitagetest", []byte(native.String())), plugin.EncodeRecipient("gitagetest", []byte(native.Recipient().String())), native},
	} {
		for _, source := range []string{"rules", "flag", "environment", "config", "own identity"} {
			t.Run(kind.name+"/"+source, func(t *testing.T) {
				directory := t.TempDir()
				initKeygenRepo(t, directory)
				t.Setenv("GIT_AGE_RECIPIENT", "")
				t.Setenv("GIT_AGE_KEY_FILE", "")
				writeFile(t, directory, ".gitage.key", "# identity\r\n"+kind.key+"\r\n")
				rules := "[files]\nsecret.env\n"
				var args []string
				switch source {
				case "rules":
					rules += "[recipients]\n" + kind.recipient + "\n"
				case "flag":
					args = []string{"-r", kind.recipient}
				case "environment":
					t.Setenv("GIT_AGE_RECIPIENT", kind.recipient)
				case "config":
					runGit(t, directory, "config", "age.recipient", kind.recipient)
				}
				writeFile(t, directory, ".gitage", rules)
				writeFile(t, directory, "secret.env", "secret\n")
				output := mustCommand(t, directory, "lock", args...)
				if strings.Contains(output, "not among the recipients") {
					t.Fatalf("did not recognize own recipient: %s", output)
				}
				assertDecrypts(t, readFile(t, directory, "secret.env"), kind.identity, []byte("secret\n"))
				if status := mustCommand(t, directory, "status", "--porcelain"); status != "L. secret.env\n" {
					t.Fatalf("own recipient status: %q", status)
				}
				mustCommand(t, directory, "unlock")
				if got := string(readFile(t, directory, "secret.env")); got != "secret\n" {
					t.Fatalf("unlock: %q", got)
				}
			})
		}
	}
}

func TestPluginExcludedIdentity(t *testing.T) {
	installTestPlugin(t)
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	t.Setenv("GIT_AGE_KEY_FILE", "")
	t.Setenv("GIT_AGE_RECIPIENT", "")
	own, other := newIdentity(t), newIdentity(t)
	writeFile(t, directory, ".gitage.key", plugin.EncodeIdentity("gitagetest", []byte(own.String()))+"\n")
	writeFile(t, directory, ".gitage", "[files]\nsecret.env\n[recipients]\n"+plugin.EncodeRecipient("gitagetest", []byte(other.Recipient().String()))+"\n")
	writeFile(t, directory, "secret.env", "secret\n")
	output := mustCommand(t, directory, "lock")
	if !strings.Contains(output, "not among the recipients") {
		t.Fatalf("missing excluded-identity warning: %s", output)
	}
	ciphertext := readFile(t, directory, "secret.env")
	assertDecrypts(t, ciphertext, other, []byte("secret\n"))
	assertCannotDecrypt(t, ciphertext, own)
	if status := mustCommand(t, directory, "status", "--porcelain"); status != "LN secret.env\n" {
		t.Fatalf("excluded plugin identity status: %q", status)
	}
}
