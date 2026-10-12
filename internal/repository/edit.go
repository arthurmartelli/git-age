package repository

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func Edit(directory string, file ProtectedFile, recipients, identities []string, dryRun bool, edit func(string) error) error {
	if file.State == Unlocked {
		if dryRun {
			return nil
		}
		path, err := filepath.Abs(nativePath(directory, file.Path))
		if err != nil {
			return err
		}
		return edit(path)
	}
	_, _, err := encryptFiles(directory, []ProtectedFile{file}, recipients, identities, encryptionOptions{edit: edit, dryRun: dryRun})
	return err
}

func editPlaintext(root, path string, plaintext []byte, edit func(string) error) (content []byte, err error) {
	parent := filepath.Dir(path)
	worktree, err := gitRoot(root)
	if err != nil {
		return nil, err
	}
	if worktree != "" {
		parent, err = gitPath(worktree, "")
		if err != nil {
			return nil, err
		}
	}
	directory, err := os.MkdirTemp(parent, "git-age-edit-")
	if err != nil {
		return nil, err
	}
	copyPath := filepath.Join(directory, filepath.Base(path))
	defer func() {
		wipeErr := wipePlaintextCopy(copyPath)
		err = errors.Join(err, wipeErr, os.RemoveAll(directory))
	}()
	if err := os.WriteFile(copyPath, plaintext, 0600); err != nil {
		return nil, err
	}
	if err := edit(copyPath); err != nil {
		return nil, err
	}
	info, err := os.Lstat(copyPath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("editor copy is no longer a regular file: %s", copyPath)
	}
	return os.ReadFile(copyPath)
}

func wipePlaintextCopy(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("cannot overwrite plaintext copy: %s", path)
	}
	// one overwrite cannot erase snapshots, SSD remnants or editor backups.
	if err := writeExisting(path, make([]byte, info.Size())); err != nil {
		return fmt.Errorf("overwrite plaintext copy: %w", err)
	}
	return nil
}
