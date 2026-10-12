package repository

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"filippo.io/age/tag"
)

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
