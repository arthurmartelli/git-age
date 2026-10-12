package repository

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"filippo.io/age/plugin"
)

func ciphertextHash(ciphertext []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(ciphertext))
}

// recipientFingerprint records the effective set, without writing keys or
// plaintext. Plugin identity-based recipients have no public string encoding.
func (k keys) recipientFingerprint(target fileTarget) string {
	values := slices.Clone(target.values)
	if k.toIdentities {
		for _, identity := range k.identities {
			if identity, ok := identity.(*plugin.Identity); ok {
				values = append(values, "plugin-identity:"+fmt.Sprintf("%x", sha256.Sum256([]byte(identity.String()))))
			}
		}
	}
	return recipientSetFingerprint(values)
}

func recipientSetFingerprint(values []string) string {
	values = slices.Clone(values)
	for i, value := range values {
		if fields := strings.Fields(value); strings.HasPrefix(value, "ssh-") && len(fields) >= 2 {
			values[i] = strings.Join(fields[:2], " ")
		}
	}
	slices.Sort(values)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(slices.Compact(values), "\n"))))
}

// rememberCiphertext lets later lock and clean operations verify that a blob
// uses the current recipients, even when their source isn't tracked in Git.
func (k keys) rememberCiphertext(root string, target fileTarget, ciphertext []byte) error {
	directory, err := gitPath(root, "git-age/recipients")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	record := k.recipientFingerprint(target)
	if k.toIdentities {
		// With identity fallback, the original encryptor is an implicit
		// recipient. Another listed team member needn't replace that owner.
		record += "\n" + recipientSetFingerprint(target.listed)
	}
	if err := os.WriteFile(filepath.Join(directory, ciphertextHash(ciphertext)), []byte(record), 0600); err != nil {
		return fmt.Errorf("record ciphertext recipients: %w", err)
	}
	return nil
}
