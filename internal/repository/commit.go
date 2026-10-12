package repository

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
)

type CommitEncryption struct {
	LeftUnchanged []string
	MadeEmpty     bool
}

// EncryptStaged uses the checked index snapshot, preserving partial staging and
// using the recipients in staged rules. Working copies with other edits stay put.
func EncryptStaged(check IndexCheck) (CommitEncryption, error) {
	var result CommitEncryption
	root := check.root
	if root == "" {
		return result, fmt.Errorf("a checked Git index is required")
	}
	if err := checkRecipientTrust(root, check.rules); err != nil {
		return result, err
	}
	keys, err := loadKeys(root, root, nil, nil, check.rules)
	if err != nil {
		return result, err
	}
	defer keys.cache.objects.close()
	initial, err := git(root, "write-tree")
	if err != nil {
		return result, err
	}
	head, _ := git(root, "rev-parse", "--verify", "HEAD^{tree}")
	var updates bytes.Buffer
	var workingCopies []replacement
	for _, file := range check.Files {
		if file.State != Unlocked {
			continue
		}
		original, err := keys.cache.objects.read(check.blobs[file.Path])
		if err != nil {
			return result, err
		}
		path := nativePath(root, file.Path)
		target, err := keys.target(root, path, check.rules)
		if err != nil {
			return result, fmt.Errorf("%s: %w", file.Path, err)
		}
		ciphertext, err := keys.encrypt(root, path, target, original, true, true)
		if err != nil {
			return result, err
		}
		oid, err := gitWithInput(root, ciphertext, "hash-object", "-w", "--stdin")
		if err != nil {
			return result, err
		}
		fmt.Fprintf(&updates, "%s %s\t%s%c", check.modes[file.Path], strings.TrimSpace(string(oid)), file.Path, 0)
		workingCopies = append(workingCopies, replacement{path, original, ciphertext})
	}
	current, err := git(root, "ls-files", "--stage", "-z")
	if err != nil {
		return result, err
	}
	if !bytes.Equal(current, check.index) {
		return result, fmt.Errorf("index changed while preparing encryption; stage your files and retry")
	}
	if _, err := gitWithInput(root, updates.Bytes(), "update-index", "-z", "--index-info"); err != nil {
		return result, fmt.Errorf("update encrypted index: %w", err)
	}
	for _, change := range workingCopies {
		// Failure to lock a working copy must not discard unstaged changes or
		// prevent the correctly encrypted index from being committed.
		if err := replaceFiles([]replacement{change}); err != nil {
			relative, _ := filepath.Rel(root, change.path)
			result.LeftUnchanged = append(result.LeftUnchanged, filepath.ToSlash(relative))
		}
	}
	final, err := git(root, "write-tree")
	if err != nil {
		return result, err
	}
	result.MadeEmpty = len(head) != 0 && !bytes.Equal(initial, head) && bytes.Equal(final, head)
	return result, nil
}

func stagedStaleFiles(root string, blobs map[string]string, rules map[string][]byte) ([]string, error) {
	var candidates []string
	for path := range blobs {
		candidates = append(candidates, nativePath(root, path))
	}
	files, err := matchProtectedFiles(root, root, candidates, rules, ruleIgnoreCase(root, true))
	if err != nil {
		return nil, err
	}
	var stale []string
	history := newRecipientHistory(root, true)
	defer history.objects.close()
	history.rules = rules
	for _, file := range files {
		content, err := history.objects.read(blobs[file.Path])
		if err != nil {
			return nil, err
		}
		if history.staleContent(nativePath(root, file.Path), content) {
			stale = append(stale, file.Path)
		}
	}
	return stale, nil
}

func MergedRecipientChanges(directory string) ([]string, error) {
	root, err := gitRoot(directory)
	if err != nil || root == "" {
		return nil, err
	}
	output, err := git(root, "diff", "--name-only", "--no-renames", "-z", "ORIG_HEAD", "HEAD")
	if err != nil {
		return nil, nil // No merge range is available, for example on an unborn branch.
	}
	var changed []string
	for _, name := range bytes.Split(output, []byte{0}) {
		path := string(name)
		if filepath.Base(path) != ".gitage" {
			continue
		}
		var versions [][]string
		for _, revision := range []string{"ORIG_HEAD", "HEAD"} {
			content, err := git(root, "show", revision+":"+path)
			var recipients []string
			if err == nil {
				_, recipients, err = parseRules(path, content)
				if err != nil {
					return nil, err
				}
			}
			versions = append(versions, recipients)
		}
		if !sameRecipients(versions[0], versions[1]) {
			changed = append(changed, path)
		}
	}
	return changed, nil
}
