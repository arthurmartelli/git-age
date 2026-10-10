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
}

// CheckIndex reads staged rules and changed regular blobs without checking them out.
// Paths are relative to the Git root, even when invoked from a subdirectory.
func CheckIndex(directory string) (IndexCheck, error) {
	var result IndexCheck
	root, err := gitRoot(directory)
	if err != nil {
		return result, err
	}
	if root == "" {
		return result, fmt.Errorf("check --cached requires a Git repository")
	}
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
		}
	}

	// Disabling rename detection makes a moved rule file count as a removal.
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
	if len(rules) == 0 {
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
		if filepath.Base(path) == ".gitage.key" || (!protected[path] && bytes.Contains(content, []byte("AGE-SECRET-KEY-"))) {
			result.PrivateKeys = append(result.PrivateKeys, path)
		}
	}
	sort.Strings(result.PrivateKeys)
	return result, nil
}
