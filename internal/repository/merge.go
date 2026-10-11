package repository

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Merge replaces Git's OURS file only after decryption and merge preparation
// succeed. Conflicts contain plaintext; clean results use current recipients.
func Merge(directory, path, base, ours, theirs string, markerSize int) (bool, error) {
	directory, root, inGit, err := resolveDirectory(directory)
	if err != nil {
		return false, err
	}
	path = absolutePath(directory, path)
	if !inside(root, path) {
		return false, fmt.Errorf("path is outside %s", root)
	}
	inputs := []string{base, ours, theirs}
	contents := make([][]byte, len(inputs))
	locked := false
	for i, input := range inputs {
		inputs[i] = absolutePath(directory, input)
		contents[i], err = os.ReadFile(inputs[i])
		if err != nil {
			return false, err
		}
		locked = locked || contentState(contents[i]) == Locked
	}
	original := contents[1]
	if locked {
		identities, err := loadIdentities(directory, root, nil)
		if err != nil {
			return false, err
		}
		for i, content := range contents {
			if contentState(content) == Locked {
				contents[i], err = decryptContent(content, identities.identities)
				if errors.Is(err, errNoIdentity) {
					return false, err
				}
				if err != nil {
					return false, fmt.Errorf("cannot decrypt %s: %w", []string{"base", "ours", "theirs"}[i], err)
				}
			}
		}
	}
	for _, content := range contents {
		if isBinary(content) {
			return false, fmt.Errorf("binary content")
		}
	}
	merged, conflicted, err := mergePlaintext(directory, contents, markerSize)
	if err != nil {
		return false, err
	}
	if !conflicted && locked {
		protected, err := protectedPath(root, path)
		if err != nil {
			return false, err
		}
		if !protected {
			return false, fmt.Errorf("not protected by .gitage, but encrypted")
		}
		if inGit {
			if err := checkRecipientTrust(root, nil); err != nil {
				return false, err
			}
		}
		keys, err := loadKeys(directory, root, nil, nil, nil)
		if err != nil {
			return false, err
		}
		target, err := keys.target(root, path, nil)
		if err != nil {
			return false, err
		}
		merged, err = keys.encrypt(root, path, target, merged, inGit)
		if err != nil {
			return false, err
		}
	}
	return conflicted, replaceFiles([]replacement{{inputs[1], original, merged}})
}

func mergePlaintext(directory string, contents [][]byte, markerSize int) (merged []byte, conflicted bool, err error) {
	// Identical changes and an unchanged side need no text diff.
	if bytes.Equal(contents[1], contents[2]) || bytes.Equal(contents[0], contents[2]) {
		return contents[1], false, nil
	}
	if bytes.Equal(contents[0], contents[1]) {
		return contents[2], false, nil
	}
	scratch, err := os.MkdirTemp("", "git-age-merge-")
	if err != nil {
		return nil, false, err
	}
	paths := []string{filepath.Join(scratch, "base"), filepath.Join(scratch, "ours"), filepath.Join(scratch, "theirs")}
	defer func() {
		for _, path := range paths {
			err = errors.Join(err, wipePlaintextCopy(path))
		}
		err = errors.Join(err, os.RemoveAll(scratch))
	}()
	for i, path := range paths {
		if err := os.WriteFile(path, contents[i], 0600); err != nil {
			return nil, false, err
		}
	}
	command := exec.Command("git", "-C", directory, "merge-file", "-p", "--marker-size="+strconv.Itoa(markerSize), "-L", "ours", "-L", "base", "-L", "theirs", "--", paths[1], paths[0], paths[2])
	var stderr bytes.Buffer
	command.Stderr = &stderr
	merged, err = command.Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() > 0 && exit.ExitCode() <= 127 {
		return merged, true, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("merge-file: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return merged, false, nil
}
