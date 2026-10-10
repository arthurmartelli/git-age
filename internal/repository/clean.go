package repository

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Clean reuses ciphertext for unchanged plaintext. Ordinary edits pass through
// for the pre-commit hook; encrypted conflict resolutions must be encrypted here
// because rebase and cherry-pick can commit without running that hook.
func Clean(directory, path string, content []byte) ([]byte, error) {
	if contentState(content) == "LOCKED" {
		return content, nil
	}
	directory, err := filepath.Abs(directory)
	if err != nil {
		return content, nil
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		return content, nil
	}
	root, err := gitRoot(directory)
	if err != nil || root == "" {
		return content, nil
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(directory, path)
	}
	if !inside(root, path) {
		return content, nil
	}
	relative, _ := filepath.Rel(root, path)
	conflicted := conflictedCiphertext(root, filepath.ToSlash(relative))
	cleaned, err := cleanProtectedContent(directory, root, path, content, conflicted)
	if err != nil {
		if conflicted {
			return nil, fmt.Errorf("cannot encrypt resolved conflict %s: %s\n  Refusing to stage it as plaintext; fix the problem, then `git add` it again.", filepath.ToSlash(relative), strings.SplitN(err.Error(), "\n", 2)[0])
		}
		// A required filter must not break git status when identities or rules
		// are unavailable. Returning plaintext keeps the file visibly modified.
		return content, nil
	}
	return cleaned, nil
}

func cleanProtectedContent(directory, root, path string, content []byte, conflicted bool) ([]byte, error) {
	// Git attributes may over-match. Only rules above this path determine
	// protection, and unrelated malformed rule files must not block the filter.
	rules := map[string][]byte{}
	for parent := filepath.Dir(path); inside(root, parent); parent = filepath.Dir(parent) {
		rule := filepath.Join(parent, ".gitage")
		info, err := os.Lstat(rule)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err == nil && info.Mode().IsRegular() {
			rules[rule], err = os.ReadFile(rule)
			if err != nil {
				return nil, err
			}
		}
		if parent == root {
			break
		}
	}
	if len(rules) == 0 {
		return content, nil
	}
	files, err := matchProtectedFiles(root, root, []string{path}, rules, ruleIgnoreCase(root, true))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return content, nil
	}
	identities, _, base, external, err := encryptionKeys(directory, root, nil, nil)
	if err != nil {
		return nil, err
	}
	values, ruleFiles, err := fileRecipients(root, path, base)
	if err != nil {
		return nil, err
	}
	recipients, err := parseRecipients(values)
	if err != nil {
		return nil, err
	}
	if conflicted {
		if err := checkRecipientTrust(directory); err != nil {
			return nil, err
		}
	}
	if !external {
		if ciphertext := reusableCiphertext(root, path, ruleFiles, content, identities); ciphertext != nil {
			return ciphertext, nil
		}
	}
	if conflicted {
		return encryptContent(content, recipients)
	}
	return content, nil
}

func conflictedCiphertext(root, path string) bool {
	if _, err := exec.Command("git", "-C", root, "show", ":0:"+path).Output(); err == nil {
		return false
	}
	for _, stage := range []string{"2", "3"} {
		content, err := exec.Command("git", "-C", root, "show", ":"+stage+":"+path).Output()
		if err == nil && contentState(content) == "LOCKED" {
			return true
		}
	}
	return false
}
