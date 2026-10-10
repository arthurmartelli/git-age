package repository

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func Textconv(directory, path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		path = filepath.Join(directory, path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if bytes.HasPrefix(content, []byte("age-encryption.org/v1\n")) || bytes.HasPrefix(content, []byte("-----BEGIN AGE ENCRYPTED FILE-----\n")) {
		plaintext, err := textconvDecrypt(directory, content)
		if err != nil {
			// Git must still show ciphertext changes when decryption fails.
			reason := strings.SplitN(err.Error(), "\n", 2)[0]
			return []byte(fmt.Sprintf("[git-age: encrypted, %s; sha256 %x]\n", reason, sha256.Sum256(content))), nil
		}
		content = plaintext
	}

	if bytes.Contains(content[:min(len(content), 8000)], []byte{0}) {
		return []byte(fmt.Sprintf("[git-age: binary content, %d bytes; sha256 %x]\n", len(content), sha256.Sum256(content))), nil
	}
	return content, nil
}

func textconvDecrypt(directory string, content []byte) ([]byte, error) {
	directory, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		return nil, err
	}
	root, err := gitRoot(directory)
	if err != nil {
		return nil, err
	}
	if root == "" {
		root = directory
	}
	identities, _, err := loadIdentities(directory, root, nil)
	if err != nil {
		return nil, err
	}
	if len(identities) == 0 {
		return nil, fmt.Errorf("no identity configured")
	}
	plaintext, err := decryptContent(content, identities)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt with configured identities")
	}
	return plaintext, nil
}
