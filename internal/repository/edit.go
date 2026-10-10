package repository

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func Edit(directory string, file ProtectedFile, recipients, identities []string, edit func(string) error) error {
	if file.State == "UNLOCKED" {
		path, err := filepath.Abs(filepath.Join(directory, filepath.FromSlash(file.Path)))
		if err != nil {
			return err
		}
		return edit(path)
	}
	_, err := encryptFiles(directory, []ProtectedFile{file}, recipients, identities, false, false, edit)
	return err
}

func editPlaintext(path string, plaintext []byte, edit func(string) error) (content []byte, err error) {
	directory, err := os.MkdirTemp("", "git-age-edit-")
	if err != nil {
		return nil, err
	}
	copyPath := filepath.Join(directory, filepath.Base(path))
	defer func() {
		wipeErr := wipeEditCopy(copyPath)
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

func wipeEditCopy(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("cannot overwrite editor copy: %s", path)
	}
	// ponytail: one overwrite cannot erase snapshots, SSD remnants or editor backups.
	if err := writeExisting(path, make([]byte, info.Size())); err != nil {
		return fmt.Errorf("overwrite editor copy: %w", err)
	}
	return nil
}
