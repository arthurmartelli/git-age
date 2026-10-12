package repository

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"filippo.io/age/tag"
)

func identityTestRepo(t *testing.T) string {
	t.Helper()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_AGE_KEY_FILE", "")
	directory := t.TempDir()
	if output, err := exec.Command("git", "-C", directory, "-c", "init.templateDir=", "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("init: %v, %s", err, output)
	}
	return directory
}

func TestIdentityPathNormalization(t *testing.T) {
	for _, source := range []string{"flags", "environment", "config"} {
		t.Run(source, func(t *testing.T) {
			directory := identityTestRepo(t)
			homeDirectory := t.TempDir()
			t.Setenv("HOME", homeDirectory)
			t.Setenv("USERPROFILE", homeDirectory)
			for _, name := range []string{"a.key", "b.key"} {
				identity, err := age.GenerateX25519Identity()
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(homeDirectory, name), []byte(identity.String()+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			paths := []string{"~/a.key", filepath.Join(homeDirectory, "a.key"), "~/b.key"}
			alias := filepath.Join(homeDirectory, "alias.key")
			if err := os.Symlink(filepath.Join(homeDirectory, "a.key"), alias); err == nil {
				paths = append(paths, alias)
			}
			var flags []string
			switch source {
			case "flags":
				flags = paths
			case "environment":
				separator := string(os.PathListSeparator)
				t.Setenv("GIT_AGE_KEY_FILE", separator+strings.Join(paths, separator+separator)+separator+" \t "+separator)
			case "config":
				for _, path := range paths {
					if output, err := exec.Command("git", "-C", directory, "config", "--add", "age.keyFile", path).CombinedOutput(); err != nil {
						t.Fatalf("config: %v, %s", err, output)
					}
				}
			}
			set, err := loadIdentities(directory, directory, flags)
			if err != nil || len(set.identities) != 2 || len(set.paths) != 2 {
				t.Fatalf("identity paths: %v, %v", set.paths, err)
			}
		})
	}
}

func TestBlankConfigValuesClearEarlierSettings(t *testing.T) {
	for _, key := range []string{"age.keyFile", "age.recipient", "age.hookMode", "age.trustedRecipients", "age.unlockAfterCommit"} {
		t.Run(key, func(t *testing.T) {
			directory := identityTestRepo(t)
			for _, value := range []string{"true", " \t "} {
				if output, err := exec.Command("git", "-C", directory, "config", "--add", key, value).CombinedOutput(); err != nil {
					t.Fatalf("config: %v, %s", err, output)
				}
			}
			values, err := configValues(directory, key)
			if err != nil || len(values) != 0 {
				t.Fatalf("blank did not clear %s: %v, %v", key, values, err)
			}
			if key == "age.unlockAfterCommit" {
				t.Setenv("GIT_AGE_UNLOCK_AFTER_COMMIT", "false")
				if err := os.Unsetenv("GIT_AGE_UNLOCK_AFTER_COMMIT"); err != nil {
					t.Fatal(err)
				}
				if enabled, err := UnlockAfterCommit(directory); err != nil || enabled {
					t.Fatalf("blank boolean setting: %v, %v", enabled, err)
				}
			}
			if output, err := exec.Command("git", "-C", directory, "config", "--add", key, "false").CombinedOutput(); err != nil {
				t.Fatalf("config: %v, %s", err, output)
			}
			values, err = configValues(directory, key)
			if err != nil || len(values) != 1 || values[0] != "false" {
				t.Fatalf("value after reset: %v, %v", values, err)
			}
		})
	}
}

func TestParseMixedIdentities(t *testing.T) {
	native, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	hybrid, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	encoded := plugin.EncodeIdentity("yubikey", []byte("test identity"))
	identities, err := parseIdentityFile([]byte("# keys\r\n\r\n" + native.String() + "\r\n" + encoded + "\r\n" + hybrid.String() + "\r\n"))
	if err != nil || len(identities) != 3 {
		t.Fatalf("mixed identities: %v, %v", identities, err)
	}
	if _, ok := identities[1].(*plugin.Identity); !ok {
		t.Fatalf("plugin identity: %T", identities[1])
	}
	if _, ok := identities[2].(*age.HybridIdentity); !ok {
		t.Fatalf("hybrid identity: %T", identities[2])
	}
	invalid := encoded[:len(encoded)-1] + "!"
	if _, err := parseIdentityFile([]byte(invalid)); err == nil || strings.Contains(err.Error(), invalid) {
		t.Fatalf("invalid identity error leaked key material: %v", err)
	}
}

func TestParsePluginRecipients(t *testing.T) {
	for _, name := range []string{"yubikey", "se", "tpm"} {
		value := plugin.EncodeRecipient(name, []byte("test public key"))
		recipients, err := parseRecipients([]string{value, value})
		if err != nil || len(recipients) != 1 {
			t.Fatalf("%s: %v, %v", name, recipients, err)
		}
		if r, ok := recipients[0].(*plugin.Recipient); !ok || r.Name() != name {
			t.Fatalf("%s: unexpected recipient %v", name, recipients[0])
		}
	}
}

func TestTaggedAndHybridRecipients(t *testing.T) {
	p256, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), p256.PublicKey().Bytes())
	compressed := elliptic.MarshalCompressed(elliptic.P256(), x, y)
	mlkemKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	hybridKey := append(mlkemKey.EncapsulationKey().Bytes(), p256.PublicKey().Bytes()...)
	for _, value := range []string{plugin.EncodeRecipient("tag", compressed), plugin.EncodeRecipient("tagpq", hybridKey)} {
		recipients, err := parseRecipients([]string{value})
		if err != nil || len(recipients) != 1 {
			t.Fatalf("tagged recipient: %v", err)
		}
		if _, ok := recipients[0].(*tag.Recipient); !ok {
			t.Fatalf("tagged recipient parsed as %T", recipients[0])
		}
		if _, err := encryptContent([]byte("secret"), recipients); err != nil {
			t.Fatalf("tagged encryption: %v", err)
		}
	}
	classic, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	hybrid, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := encryptContent(nil, []age.Recipient{classic.Recipient(), hybrid.Recipient()}); err == nil {
		t.Fatal("mixed classical and post-quantum recipients were accepted")
	}
}
