package repository

import (
	"fmt"
	"path/filepath"
)

// Clean reuses ciphertext for unchanged plaintext. Ordinary edits pass through
// for the pre-commit hook; encrypted conflict resolutions must be encrypted here
// because rebase and cherry-pick can commit without running that hook.
func Clean(directory, path string, content []byte) ([]byte, error) {
	if contentState(content) == Locked {
		return content, nil
	}
	directory, root, inGit, err := resolveDirectory(directory)
	if err != nil || !inGit {
		return content, nil
	}
	path = absolutePath(directory, path)
	if !inside(root, path) {
		return content, nil
	}
	relative, _ := filepath.Rel(root, path)
	conflicted := conflictedCiphertext(root, filepath.ToSlash(relative))
	cleaned, err := cleanProtectedContent(directory, root, path, content, conflicted)
	if err != nil {
		if conflicted {
			return nil, fmt.Errorf("cannot encrypt resolved conflict %s: %s\n  Refusing to stage it as plaintext; fix the problem, then `git add` it again.", filepath.ToSlash(relative), FirstLine(err))
		}
		// A required filter must not break git status when identities or rules
		// are unavailable. Returning plaintext keeps the file visibly modified.
		return content, nil
	}
	return cleaned, nil
}

func cleanProtectedContent(directory, root, path string, content []byte, conflicted bool) ([]byte, error) {
	protected, err := protectedPath(root, path)
	if err != nil {
		return nil, err
	}
	if !protected {
		return content, nil
	}
	keys, err := loadKeys(directory, root, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	defer keys.cache.objects.close()
	target, err := keys.target(root, path, nil)
	if err != nil {
		return nil, err
	}
	if conflicted {
		if err := checkRecipientTrust(root, nil); err != nil {
			return nil, err
		}
		return keys.encrypt(root, path, target, content, true, true)
	}
	if ciphertext, _ := keys.reusableCiphertext(root, path, target, content); ciphertext != nil {
		return ciphertext, nil
	}
	return content, nil
}

func protectedPath(root, path string) (bool, error) {
	// Git attributes may over-match. Only rules above this path determine
	// protection, and unrelated malformed rule files must not block this path.
	rules := map[string][]byte{}
	for _, parent := range ancestorDirs(root, filepath.Dir(path)) {
		rule := filepath.Join(parent, ".gitage")
		content, err := readRuleFile(rule)
		if err != nil {
			return false, err
		}
		if content != nil {
			rules[rule] = content
		}
	}
	if len(rules) == 0 {
		return false, nil
	}
	files, err := matchProtectedFiles(root, root, []string{path}, rules, ruleIgnoreCase(root, true))
	if err != nil {
		return false, err
	}
	return len(files) != 0, nil
}

func conflictedCiphertext(root, path string) bool {
	if _, err := git(root, "show", ":0:"+path); err == nil {
		return false
	}
	for _, stage := range []string{"2", "3"} {
		content, err := git(root, "show", ":"+stage+":"+path)
		if err == nil && contentState(content) == Locked {
			return true
		}
	}
	return false
}
