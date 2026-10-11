package repository

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
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

func CheckIndex(directory string) (IndexCheck, error) {
	return checkIndex(directory, true)
}

func CheckCommit(directory string) (IndexCheck, error) {
	return checkIndex(directory, false)
}

func checkIndex(directory string, requireRules bool) (IndexCheck, error) {
	var result IndexCheck
	// Use the Git root because staged paths are repository-relative.
	root, err := gitRoot(directory)
	if err != nil {
		return result, err
	}
	if root == "" {
		return result, fmt.Errorf("check --cached requires a Git repository")
	}
	result.root = root
	git := func(args ...string) ([]byte, error) {
		output, err := exec.Command("git", append([]string{"-C", root}, args...)...).Output()
		if err != nil {
			return nil, fmt.Errorf("read index: git %s: %w", args[0], err)
		}
		return output, nil
	}
	output, err := git("ls-files", "--stage", "-z")
	if err != nil {
		return result, err
	}
	blobs := map[string]string{}
	modes := map[string]string{}
	result.index, result.blobs, result.modes = output, blobs, modes
	for _, record := range bytes.Split(output, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		header, path, ok := strings.Cut(string(record), "\t")
		fields := strings.Fields(header)
		if !ok || len(fields) != 3 {
			return result, fmt.Errorf("invalid Git index record")
		}
		if fields[2] != "0" {
			return result, fmt.Errorf("unmerged index entry: %s", path)
		}
		if fields[0] == "100644" || fields[0] == "100755" {
			blobs[path] = fields[1]
			modes[path] = fields[0]
		}
	}

	// Moving a rule file can unprotect files, so it must count as a removal.
	output, err = git("diff", "--cached", "--raw", "--no-abbrev", "--no-renames", "-z", "--diff-filter=DT")
	if err != nil {
		return result, err
	}
	records := bytes.Split(bytes.TrimSuffix(output, []byte{0}), []byte{0})
	for i := 0; i+1 < len(records); i += 2 {
		fields := strings.Fields(string(records[i]))
		path := string(records[i+1])
		if len(fields) == 5 && (fields[0] == ":100644" || fields[0] == ":100755") && filepath.Base(path) == ".gitage" && blobs[path] == "" {
			result.RemovedRules = append(result.RemovedRules, path)
		}
	}
	sort.Strings(result.RemovedRules)

	rules := map[string][]byte{}
	result.rules = rules
	for path, oid := range blobs {
		if filepath.Base(path) != ".gitage" {
			continue
		}
		content, err := git("cat-file", "blob", oid)
		if err != nil {
			return result, err
		}
		rules[filepath.Join(root, filepath.FromSlash(path))] = content
	}
	result.HasRules = len(rules) != 0
	if !result.HasRules && requireRules {
		return result, fmt.Errorf("no .gitage files staged")
	}
	output, err = git("diff", "--cached", "--name-only", "--no-renames", "-z", "--diff-filter=ACMRT")
	if err != nil {
		return result, err
	}
	var candidates []string
	changed := map[string][]byte{}
	for _, name := range bytes.Split(output, []byte{0}) {
		path := string(name)
		if blobs[path] == "" {
			continue
		}
		content, err := git("cat-file", "blob", blobs[path])
		if err != nil {
			return result, err
		}
		changed[path] = content
		candidates = append(candidates, filepath.Join(root, filepath.FromSlash(path)))
	}
	result.Files, err = matchProtectedFiles(root, root, candidates, rules, ruleIgnoreCase(root, true))
	if err != nil {
		return result, err
	}
	protected := map[string]bool{}
	for i := range result.Files {
		file := &result.Files[i]
		protected[file.Path] = true
		file.State = contentState(changed[file.Path])
	}
	for path, content := range changed {
		if filepath.Base(path) == ".gitage.key" || (result.HasRules && !protected[path] && bytes.Contains(content, []byte("AGE-SECRET-KEY-"))) {
			result.PrivateKeys = append(result.PrivateKeys, path)
		}
	}
	sort.Strings(result.PrivateKeys)
	if !requireRules {
		result.StaleFiles, err = stagedStaleFiles(root, blobs, rules)
	}
	return result, err
}
