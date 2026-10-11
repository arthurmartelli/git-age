package repository

import (
	"crypto/sha256"
	"fmt"
	"os"
)

func Textconv(directory, path string) ([]byte, error) {
	content, err := os.ReadFile(absolutePath(directory, path))
	if err != nil {
		return nil, err
	}

	if contentState(content) == Locked {
		plaintext, err := textconvDecrypt(directory, content)
		if err != nil {
			// Git must still show ciphertext changes when decryption fails.
			return []byte(fmt.Sprintf("[git-age: encrypted, %s; sha256 %x]\n", FirstLine(err), sha256.Sum256(content))), nil
		}
		content = plaintext
	}

	if isBinary(content) {
		return []byte(fmt.Sprintf("[git-age: binary content, %d bytes; sha256 %x]\n", len(content), sha256.Sum256(content))), nil
	}
	return content, nil
}

func textconvDecrypt(directory string, content []byte) ([]byte, error) {
	directory, root, _, err := resolveDirectory(directory)
	if err != nil {
		return nil, err
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
