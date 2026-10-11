package repository

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
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
	if err := checkRecipientTrust(root); err != nil {
		return result, err
	}
	identities, _, base, external, err := encryptionKeysFromRules(root, root, nil, nil, check.rules)
	if err != nil {
		return result, err
	}
	git := func(args ...string) ([]byte, error) {
		return exec.Command("git", append([]string{"-C", root}, args...)...).Output()
	}
	initial, err := git("write-tree")
	if err != nil {
		return result, err
	}
	head, _ := git("rev-parse", "--verify", "HEAD^{tree}")
	var updates bytes.Buffer
	var workingCopies []replacement
	for _, file := range check.Files {
		if file.State != "UNLOCKED" {
			continue
		}
		original, err := git("cat-file", "blob", check.blobs[file.Path])
		if err != nil {
			return result, err
		}
		path := filepath.Join(root, filepath.FromSlash(file.Path))
		values, rules, err := fileRecipientsFromRules(root, path, base, check.rules)
		if err != nil {
			return result, err
		}
		recipients, err := parseRecipients(values)
		if err != nil {
			return result, fmt.Errorf("%s: %w", file.Path, err)
		}
		var ciphertext []byte
		if !external && workingRulesMatchIndex(rules, check.rules) {
			ciphertext = reusableCiphertext(root, path, rules, original, identities)
		}
		if ciphertext == nil {
			ciphertext, err = encryptContent(original, recipients)
			if err != nil {
				return result, err
			}
		}
		command := exec.Command("git", "-C", root, "hash-object", "-w", "--stdin")
		command.Stdin = bytes.NewReader(ciphertext)
		oid, err := command.Output()
		if err != nil {
			return result, err
		}
		fmt.Fprintf(&updates, "%s %s\t%s%c", check.modes[file.Path], strings.TrimSpace(string(oid)), file.Path, 0)
		workingCopies = append(workingCopies, replacement{path, original, ciphertext})
	}
	current, err := git("ls-files", "--stage", "-z")
	if err != nil {
		return result, err
	}
	if !bytes.Equal(current, check.index) {
		return result, fmt.Errorf("index changed while preparing encryption; stage your files and retry")
	}
	command := exec.Command("git", "-C", root, "update-index", "-z", "--index-info")
	command.Stdin = &updates
	if output, err := command.CombinedOutput(); err != nil {
		return result, fmt.Errorf("update encrypted index: %w: %s", err, output)
	}
	for _, change := range workingCopies {
		// Failure to lock a working copy must not discard unstaged changes or
		// prevent the correctly encrypted index from being committed.
		if err := replaceFiles([]replacement{change}); err != nil {
			relative, _ := filepath.Rel(root, change.path)
			result.LeftUnchanged = append(result.LeftUnchanged, filepath.ToSlash(relative))
		}
	}
	final, err := git("write-tree")
	if err != nil {
		return result, err
	}
	result.MadeEmpty = len(head) != 0 && !bytes.Equal(initial, head) && bytes.Equal(final, head)
	return result, nil
}

func workingRulesMatchIndex(paths []string, indexed map[string][]byte) bool {
	for _, path := range paths {
		info, err := os.Lstat(path)
		if os.IsNotExist(err) || err == nil && !info.Mode().IsRegular() {
			if _, exists := indexed[path]; exists {
				return false
			}
			continue
		}
		if err != nil {
			return false
		}
		content, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(content, indexed[path]) {
			return false
		}
	}
	return true
}

func stagedStaleFiles(root string, blobs map[string]string, rules map[string][]byte) ([]string, error) {
	var changed []string
	for path, content := range rules {
		_, current, err := parseRules(path, content)
		if err != nil {
			return nil, err
		}
		relative, _ := filepath.Rel(root, path)
		previous, gitErr := exec.Command("git", "-C", root, "show", "HEAD:"+filepath.ToSlash(relative)).Output()
		var old []string
		if gitErr == nil {
			_, old, err = parseRules(path, previous)
			if err != nil {
				return nil, err
			}
		}
		if !sameRecipients(current, old) {
			changed = append(changed, filepath.Dir(path))
		}
	}
	if len(changed) == 0 {
		return nil, nil
	}
	var candidates []string
	for path := range blobs {
		for _, parent := range changed {
			absolute := filepath.Join(root, filepath.FromSlash(path))
			if inside(parent, absolute) {
				candidates = append(candidates, absolute)
				break
			}
		}
	}
	files, err := matchProtectedFiles(root, root, candidates, rules, ruleIgnoreCase(root, true))
	if err != nil {
		return nil, err
	}
	var stale []string
	for _, file := range files {
		previous, err := exec.Command("git", "-C", root, "rev-parse", "--verify", "HEAD:"+file.Path).Output()
		if err != nil || strings.TrimSpace(string(previous)) != blobs[file.Path] {
			continue
		}
		content, err := exec.Command("git", "-C", root, "cat-file", "blob", blobs[file.Path]).Output()
		if err != nil {
			return nil, err
		}
		if contentState(content) == "LOCKED" {
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
	output, err := exec.Command("git", "-C", root, "diff", "--name-only", "--no-renames", "-z", "ORIG_HEAD", "HEAD").Output()
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
			content, err := exec.Command("git", "-C", root, "show", revision+":"+path).Output()
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
