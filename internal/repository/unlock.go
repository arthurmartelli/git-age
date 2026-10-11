package repository

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
	"filippo.io/age/armor"
)

func Unlock(directory string, files []ProtectedFile, identityPaths []string) error {
	if err := CheckKnown(files); err != nil {
		return err
	}
	var pending []ProtectedFile
	for _, file := range files {
		if file.State == Locked {
			pending = append(pending, file)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	directory, root, _, err := resolveDirectory(directory)
	if err != nil {
		return err
	}
	identities, _, err := loadIdentities(directory, root, identityPaths)
	if err != nil {
		return err
	}
	if len(identities) == 0 {
		return errNoIdentity
	}

	// Authenticate all ciphertexts first so a bad file cannot leave a partial unlock.
	var replacements []replacement
	for _, file := range pending {
		path := nativePath(directory, file.Path)
		original, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		plaintext, err := decryptContent(original, identities)
		if err != nil {
			return fmt.Errorf("cannot decrypt %s: %w", file.Path, err)
		}
		replacements = append(replacements, replacement{path, original, plaintext})
	}
	return replaceFiles(replacements)
}

func decryptContent(content []byte, identities []age.Identity) ([]byte, error) {
	var input io.Reader = bytes.NewReader(content)
	if bytes.HasPrefix(content, []byte("-----BEGIN AGE ENCRYPTED FILE-----")) {
		input = armor.NewReader(input)
	}
	reader, err := age.Decrypt(input, identities...)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(reader)
}
