package repository

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
)

// HistoryPurgeOptions selects literal files or directories, or all protected paths.
type HistoryPurgeOptions struct {
	Paths  []string
	All    bool
	DryRun bool
}

// HistoryPurge removes every version of the selected paths from local history.
type HistoryPurge struct {
	*HistoryRewrite
	Paths []string // Repository-relative paths, sorted.
}

// PrepareHistoryPurge writes the rewritten trees, commits and tags, without moving refs.
// Purging requires no recipients or decryption identities.
func PrepareHistoryPurge(directory string, options HistoryPurgeOptions) (*HistoryPurge, error) {
	if options.All == (len(options.Paths) != 0) {
		return nil, errors.New("history purge requires PATH ... or --all, but not both")
	}
	directory, root, _, err := resolveDirectory(directory)
	if err != nil {
		return nil, err
	}
	var targets []string
	for _, name := range options.Paths {
		target := absolutePath(directory, name)
		if !inside(root, target) {
			return nil, fmt.Errorf("%s: outside %s", name, root)
		}
		relative, err := filepath.Rel(root, target)
		if err != nil {
			return nil, err
		}
		targets = append(targets, filepath.ToSlash(relative))
	}
	refs, err := rewritableRefs(root)
	if err != nil {
		return nil, err
	}
	result := &HistoryPurge{HistoryRewrite: &HistoryRewrite{root: root, directory: directory, operation: "purge"}}
	if len(refs) == 0 {
		if !options.All {
			return nil, fmt.Errorf("%s: no such path in local history", options.Paths[0])
		}
		return result, nil
	}
	tips := map[string]bool{}
	for _, ref := range refs {
		tips[ref.oid] = true
	}
	reader, err := newObjectReader(root)
	if err != nil {
		return nil, err
	}
	defer reader.close()
	h, err := newHistory(root, reader, slices.Sorted(maps.Keys(tips)))
	if err != nil {
		return nil, err
	}
	paths := map[string]bool{}
	if len(h.commits) != 0 {
		output, err := h.log([]string{"--full-history", "--diff-merges=separate"})
		if err != nil {
			return nil, err
		}
		for _, change := range rawChanges(output) {
			paths[change.path] = true
		}
	}
	purge := map[string]bool{}
	if options.All {
		if err := h.prepare(slices.Sorted(maps.Keys(paths))); err != nil {
			return nil, err
		}
		// Inspect whole trees, since adding a rule can protect an unchanged file.
		for _, commit := range h.commits {
			output, err := git(root, "ls-tree", "-r", "-z", "--full-tree", commit)
			if err != nil {
				return nil, fmt.Errorf("cannot read the tree of %s: %w", commit, gitError(err))
			}
			for _, record := range bytes.Split(output, []byte{0}) {
				header, name, ok := strings.Cut(string(record), "\t")
				fields := strings.Fields(header)
				if ok && len(fields) == 3 && regularMode(fields[0]) && h.protects(commit, name) {
					purge[name] = true
				}
			}
		}
		result.Warnings = h.Warnings
	} else {
		for i, target := range targets {
			matched := false
			for name := range paths {
				if target == "." || name == target || strings.HasPrefix(name, target+"/") {
					purge[name], matched = true, true
				}
			}
			if !matched {
				return nil, fmt.Errorf("%s: no such path in local history", options.Paths[i])
			}
		}
	}
	result.Paths = slices.Sorted(maps.Keys(purge))
	result.Commits = len(h.commits)
	if len(purge) == 0 {
		return result, nil
	}
	r := &rewriter{
		HistoryRewrite: result.HistoryRewrite, history: h,
		options: HistoryRekeyOptions{DryRun: options.DryRun}, oidLength: len(h.commits[0]) / 2,
		purge: purge, trees: map[string]string{}, commits: map[string]string{}, tags: map[string]string{},
	}
	if err := r.rewriteRefs(refs); err != nil {
		return nil, err
	}
	return result, nil
}
