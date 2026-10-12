package repository

import (
	"bytes"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

type IndexCheck struct {
	Files        []ProtectedFile
	RemovedRules []string
	PrivateKeys  []string
	StaleFiles   []string
	HasRules     bool
	root         string
	index        []byte
	blobs        map[string]string
	modes        map[string]string
	rules        map[string][]byte
}

func CheckIndex(directory string, paths []string) (IndexCheck, error) {
	result, err := checkIndex(directory, true)
	if err != nil {
		return result, err
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		return result, err
	}
	stalePaths := map[string]bool{}
	for _, path := range result.StaleFiles {
		stalePaths[path] = true
	}
	result.StaleFiles = nil
	for i := range result.Files {
		file := &result.Files[i]
		previous := file.Path
		path, err := filepath.Rel(directory, nativePath(result.root, file.Path))
		if err != nil {
			return result, err
		}
		file.Path = filepath.ToSlash(path)
		if stalePaths[previous] {
			result.StaleFiles = append(result.StaleFiles, file.Path)
		}
	}
	if len(paths) == 0 {
		return result, nil
	}
	result.Files, err = selectFiles(directory, result.Files, paths)
	selected := map[string]bool{}
	for _, file := range result.Files {
		selected[file.Path] = true
	}
	result.StaleFiles = slices.DeleteFunc(result.StaleFiles, func(path string) bool { return !selected[path] })
	return result, err
}

func CheckCommit(directory string) (IndexCheck, error) {
	return checkIndex(directory, false)
}

func checkIndex(directory string, requireRules bool) (IndexCheck, error) {
	var result IndexCheck
	// Use the Git root because staged paths are repository-relative.
	root, err := Root(directory, "check --staged")
	if err != nil {
		return result, err
	}
	result.root = root
	indexGit := func(args ...string) ([]byte, error) {
		output, err := git(root, args...)
		if err != nil {
			return nil, fmt.Errorf("read index: git %s: %w", args[0], err)
		}
		return output, nil
	}
	output, err := indexGit("ls-files", "--stage", "-z")
	if err != nil {
		return result, err
	}
	blobs := map[string]string{}
	modes := map[string]string{}
	result.index, result.blobs, result.modes = output, blobs, modes
	entries, err := stageEntries(output)
	if err != nil {
		return result, err
	}
	for _, entry := range entries {
		if entry.stage != "0" {
			return result, fmt.Errorf("unmerged index entry: %s", entry.path)
		}
		if regularMode(entry.mode) {
			blobs[entry.path] = entry.oid
			modes[entry.path] = entry.mode
		}
	}

	// Moving a rule file can unprotect files, so it must count as a removal.
	output, err = indexGit("diff", "--cached", "--raw", "--no-abbrev", "--no-renames", "-z", "--diff-filter=DT")
	if err != nil {
		return result, err
	}
	records := bytes.Split(bytes.TrimSuffix(output, []byte{0}), []byte{0})
	for i := 0; i+1 < len(records); i += 2 {
		fields := strings.Fields(string(records[i]))
		path := string(records[i+1])
		if len(fields) == 5 && regularMode(strings.TrimPrefix(fields[0], ":")) && filepath.Base(path) == ".gitage" && blobs[path] == "" {
			result.RemovedRules = append(result.RemovedRules, path)
		}
	}
	slices.Sort(result.RemovedRules)

	rules := map[string][]byte{}
	result.rules = rules
	for path, oid := range blobs {
		if filepath.Base(path) != ".gitage" {
			continue
		}
		content, err := indexGit("cat-file", "blob", oid)
		if err != nil {
			return result, err
		}
		rules[nativePath(root, path)] = content
	}
	result.HasRules = len(rules) != 0
	if !result.HasRules && requireRules {
		return result, fmt.Errorf("no .gitage files staged")
	}
	output, err = indexGit("diff", "--cached", "--name-only", "--no-renames", "-z", "--diff-filter=ACMRT")
	if err != nil {
		return result, err
	}
	changed := map[string][]byte{}
	for _, name := range bytes.Split(output, []byte{0}) {
		path := string(name)
		if blobs[path] == "" {
			continue
		}
		content, err := indexGit("cat-file", "blob", blobs[path])
		if err != nil {
			return result, err
		}
		changed[path] = content
	}
	// Public checks inspect the index snapshot; commit hooks inspect changes.
	var candidates []string
	if requireRules {
		for path := range blobs {
			candidates = append(candidates, nativePath(root, path))
		}
	} else {
		for path := range changed {
			candidates = append(candidates, nativePath(root, path))
		}
	}
	result.Files, err = matchProtectedFiles(root, root, candidates, rules, ruleIgnoreCase(root, true))
	if err != nil {
		return result, err
	}
	protected := map[string]bool{}
	for i := range result.Files {
		file := &result.Files[i]
		protected[file.Path] = true
		content, ok := changed[file.Path]
		if !ok {
			content, err = indexGit("cat-file", "blob", blobs[file.Path])
			if err != nil {
				return result, err
			}
		}
		file.State = contentState(content)
	}
	for path, content := range changed {
		if filepath.Base(path) == ".gitage.key" || (result.HasRules && !protected[path] && containsPrivateIdentity(content)) {
			result.PrivateKeys = append(result.PrivateKeys, path)
		}
	}
	slices.Sort(result.PrivateKeys)
	result.StaleFiles, err = stagedStaleFiles(root, blobs, rules)
	return result, err
}
