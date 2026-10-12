package repository

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// UnlockSkips lists the locked files Unlock leaves alone.
type UnlockSkips struct {
	NoAccess   []ProtectedFile // Not encrypted to the user.
	NotRekeyed []ProtectedFile // Still encrypted to recipients from before the user was added.
}

// Unlock decrypts the locked files, all or none of those it does not skip.
func Unlock(directory string, files []ProtectedFile, identityPaths []string, dryRun bool) (UnlockSkips, error) {
	var skips UnlockSkips
	if err := CheckKnown(files); err != nil {
		return skips, err
	}
	var pending []ProtectedFile
	for _, file := range files {
		if file.State == Locked {
			pending = append(pending, file)
		}
	}
	if len(pending) == 0 {
		return skips, nil
	}
	directory, root, inGit, err := resolveDirectory(directory)
	if err != nil {
		return skips, err
	}
	identities, err := loadIdentities(directory, root, identityPaths)
	if err != nil {
		return skips, err
	}
	var userKeys *keys
	history := newRecipientHistory(root, inGit)
	defer history.objects.close()

	// Authenticate all ciphertexts first so a bad file cannot leave a partial unlock.
	var replacements []replacement
	for _, file := range pending {
		path := nativePath(directory, file.Path)
		original, err := os.ReadFile(path)
		if err != nil {
			return skips, err
		}
		plaintext, err := decryptContent(original, identities.identities)
		if errors.Is(err, errNoIdentity) {
			return skips, err
		}
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			if userKeys == nil {
				resolved, err := resolveKeys(directory, root, nil, identities, nil)
				if err != nil {
					return skips, err
				}
				userKeys = &resolved
			}
			target, err := userKeys.describeTarget(root, path, nil)
			if err != nil {
				return skips, err
			}
			mine, err := userKeys.encryptedToUser(target)
			if err != nil {
				return skips, err
			}
			if !mine {
				skips.NoAccess = append(skips.NoAccess, file)
				continue
			}
			if history.stale(path) {
				skips.NotRekeyed = append(skips.NotRekeyed, file)
				continue
			}
		}
		if err != nil {
			return skips, fmt.Errorf("cannot decrypt %s: %w", file.Path, err)
		}
		replacements = append(replacements, replacement{path, original, plaintext})
	}
	if dryRun {
		return skips, nil
	}
	return skips, replaceFiles(replacements)
}

func decryptContent(content []byte, identities []age.Identity) ([]byte, error) {
	if len(identities) == 0 {
		return nil, errNoIdentity
	}
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
