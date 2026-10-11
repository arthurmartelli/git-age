package repository

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

func KeyPath(directory, output string) (string, error) {
	directory, root, _, err := resolveDirectory(directory)
	if err != nil {
		return "", err
	}
	if info, err := os.Stat(directory); err != nil || !info.IsDir() {
		return "", fmt.Errorf("not a directory: %s", directory)
	}
	if output == "" {
		directory, output = root, ".gitage.key"
	}
	output = absolutePath(directory, output)

	if _, err := os.Lstat(output); err == nil {
		return "", fmt.Errorf("refusing to overwrite existing key: %s", output)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	parent := filepath.Dir(output)
	if info, err := os.Stat(parent); err != nil || !info.IsDir() {
		return "", fmt.Errorf("output directory does not exist: %s", parent)
	}

	return output, nil
}

func GenerateKey(path string, exclude bool) (string, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return "", err
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return "", fmt.Errorf("refusing to overwrite existing key: %s", path)
	}
	if err != nil {
		return "", err
	}

	_, writeErr := file.WriteString(identity.String() + "\n")
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		os.Remove(path)
		return "", err
	}

	if exclude {
		if err := excludeKey(path); err != nil {
			return "", fmt.Errorf("identity generated at %s, but Git exclusion failed: %w", path, err)
		}
	}

	return identity.Recipient().String(), nil
}

func excludeKey(path string) error {
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	root, err := gitRoot(filepath.Dir(path))
	if err != nil || root == "" {
		return err
	}

	relative, err := filepath.Rel(root, path)
	if err != nil {
		return err
	}
	if strings.ContainsAny(relative, "\r\n") {
		return fmt.Errorf("key path cannot contain a newline")
	}
	escape := strings.NewReplacer("\\", "\\\\", "*", "\\*", "?", "\\?", "[", "\\[", "]", "\\]", " ", "\\ ")
	entry := "/" + escape.Replace(filepath.ToSlash(relative))

	output, err := git(root, "rev-parse", "--git-path", "info/exclude")
	if err != nil {
		return err
	}
	exclude := absolutePath(root, strings.TrimSpace(string(output)))

	content, err := os.ReadFile(exclude)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, line := range strings.Split(string(content), "\n") {
		if line == entry {
			return nil
		}
	}

	if err := os.MkdirAll(filepath.Dir(exclude), 0755); err != nil {
		return err
	}
	file, err := os.OpenFile(exclude, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	prefix := ""
	if len(content) > 0 && content[len(content)-1] != '\n' {
		prefix = "\n"
	}
	_, writeErr := fmt.Fprintf(file, "%s# git-age private key\n%s\n", prefix, entry)

	return errors.Join(writeErr, file.Close())
}
