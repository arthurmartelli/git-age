package repository

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

type replacement struct {
	path              string
	original, content []byte
}

func replaceFiles(replacements []replacement) error {
	// Refuse concurrent edits so replacements do not overwrite the user's changes.
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
			// The failed write may have changed its file too.
			for _, previous := range replacements[:i+1] {
				if restoreErr := writeExisting(previous.path, previous.original); restoreErr != nil {
					err = errors.Join(err, fmt.Errorf("restore %s: %w", previous.path, restoreErr))
				}
			}
			return err
		}
	}
	return forgetStat(replacements)
}

func forgetStat(replacements []replacement) error {
	byRoot := map[string][]string{}
	roots := map[string]string{}
	for _, change := range replacements {
		// Match Git's canonical root when a parent uses a symlink or a Windows
		// short name, while leaving the file itself subject to regular-file checks.
		directory, err := filepath.EvalSymlinks(filepath.Dir(change.path))
		if err != nil {
			return err
		}
		root, known := roots[directory]
		if !known {
			root, err = gitRoot(directory)
			if err != nil {
				return err
			}
			roots[directory] = root
		}
		if root == "" {
			continue
		}
		relative, err := filepath.Rel(root, filepath.Join(directory, filepath.Base(change.path)))
		if err != nil {
			return err
		}
		byRoot[root] = append(byRoot[root], filepath.ToSlash(relative))
	}
	for root, paths := range byRoot {
		output, err := git(root, append([]string{"--literal-pathspecs", "ls-files", "--stage", "-z", "--"}, paths...)...)
		if err != nil {
			return err
		}
		staged, err := stageEntries(output)
		if err != nil {
			return err
		}
		var entries bytes.Buffer
		for _, entry := range staged {
			if entry.stage == "0" && regularMode(entry.mode) {
				fmt.Fprintf(&entries, "%s %s\t%s%c", entry.mode, entry.oid, entry.path, 0)
			}
		}
		if entries.Len() == 0 {
			continue
		}
		// A size change can bypass Git's clean filter. Rewriting each stage-zero
		// entry with the same blob clears its stat cache without staging edits.
		if _, err := gitWithInput(root, entries.Bytes(), "update-index", "-z", "--index-info"); err != nil {
			return fmt.Errorf("files changed but Git stat cache refresh failed: %w", err)
		}
	}
	return nil
}

func writeExisting(path string, content []byte) (err error) {
	// Keeping the existing file preserves its permissions, ACLs and extended attributes.
	if runtime.GOOS == "windows" {
		info, statErr := os.Stat(path)
		if statErr != nil {
			return statErr
		}
		if info.Mode().Perm()&0200 == 0 {
			// On Windows, Chmod changes only the read-only attribute.
			if err := os.Chmod(path, info.Mode()|0200); err != nil {
				return err
			}
			defer func() {
				err = errors.Join(err, os.Chmod(path, info.Mode()))
			}()
		}
	}
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
