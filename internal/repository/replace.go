package repository

import (
	"bytes"
	"errors"
	"fmt"
	"os"
)

type replacement struct {
	path              string
	original, content []byte
}

// replaceFiles preserves file metadata and rolls back writes when a replacement fails.
func replaceFiles(replacements []replacement) error {
	// Detect edits made while replacements were being prepared before changing any file.
	for _, change := range replacements {
		info, err := os.Lstat(change.path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s: no longer a regular file", change.path)
		}
		content, err := os.ReadFile(change.path)
		if err != nil {
			return err
		}
		if !bytes.Equal(content, change.original) {
			return fmt.Errorf("%s: changed while preparing replacement", change.path)
		}
	}
	for i, change := range replacements {
		if err := writeExisting(change.path, change.content); err != nil {
			for _, previous := range replacements[:i+1] {
				if restoreErr := writeExisting(previous.path, previous.original); restoreErr != nil {
					err = errors.Join(err, fmt.Errorf("restore %s: %w", previous.path, restoreErr))
				}
			}
			return err
		}
	}
	return nil
}

func writeExisting(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(content)
	if writeErr == nil {
		writeErr = file.Truncate(int64(len(content)))
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	return errors.Join(writeErr, file.Close())
}
