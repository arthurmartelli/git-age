package repository

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
)

type PushCheck struct {
	Plaintext   []string
	PrivateKeys []string
}

// CheckPush scans versions introduced by the outgoing commits, excluding
// commits already known to the remote. It never changes the worktree or index.
func CheckPush(directory, remote string, input io.Reader) (PushCheck, error) {
	var result PushCheck
	root, err := gitRoot(directory)
	if err != nil {
		return result, err
	}
	if root == "" {
		return result, fmt.Errorf("pre-push requires a Git worktree")
	}
	historyGit := func(args ...string) ([]byte, error) {
		output, err := git(root, args...)
		if err != nil {
			return nil, fmt.Errorf("read push history: git %s: %w", args[0], err)
		}
		return output, nil
	}
	var tips, known []string
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 4 || !validObjectID(fields[1]) || !validObjectID(fields[3]) {
			return result, fmt.Errorf("invalid pre-push update record")
		}
		if strings.Trim(fields[1], "0") == "" {
			continue // Deleting a ref publishes no commits.
		}
		commit, err := historyGit("rev-parse", "--verify", "--quiet", fields[1]+"^{commit}")
		if err != nil {
			if _, existsErr := historyGit("cat-file", "-e", fields[1]); existsErr != nil {
				return result, err
			}
			continue // A tag of a blob or tree contains no commit history.
		}
		tips = append(tips, strings.TrimSpace(string(commit)))
		if strings.Trim(fields[3], "0") != "" {
			if commit, err := historyGit("rev-parse", "--verify", "--quiet", fields[3]+"^{commit}"); err == nil {
				known = append(known, strings.TrimSpace(string(commit)))
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return result, err
	}
	if len(tips) == 0 {
		return result, nil
	}
	tracking, err := historyGit("for-each-ref", "--format=%(refname) %(objectname)", "refs/remotes/")
	if err != nil {
		return result, err
	}
	for _, line := range strings.Split(string(tracking), "\n") {
		ref, oid, ok := strings.Cut(line, " ")
		if ok && strings.HasPrefix(ref, "refs/remotes/"+remote+"/") {
			known = append(known, oid)
		}
	}
	var revisions bytes.Buffer
	for _, oid := range tips {
		revisions.WriteString(oid + "\n")
	}
	for _, oid := range known {
		revisions.WriteString("^" + oid + "\n")
	}
	commits, err := gitWithInput(root, revisions.Bytes(), "rev-list", "--topo-order", "--reverse", "--stdin")
	if err != nil {
		return result, fmt.Errorf("list outgoing commits: %w", err)
	}
	if len(commits) == 0 {
		return result, nil
	}
	paths, err := regularFiles(root, true)
	if err != nil {
		return result, err
	}
	currentRules, err := readRules(paths)
	if err != nil {
		return result, err
	}
	type version struct{ path, oid string }
	introduced := map[version]bool{} // Value records whether any applicable rules protect the version.
	hasRules := len(currentRules) != 0
	for _, commit := range strings.Fields(string(commits)) {
		changes, err := historyGit("diff-tree", "--root", "-m", "-r", "--raw", "--no-commit-id", "--no-abbrev", "--no-renames", "--diff-filter=ACMRT", "-z", commit, "--")
		if err != nil {
			return result, err
		}
		var versions []version
		var candidates []string
		records := bytes.Split(bytes.TrimSuffix(changes, []byte{0}), []byte{0})
		for i := 0; i+1 < len(records); i += 2 {
			fields := strings.Fields(string(records[i]))
			if len(fields) != 5 {
				return result, fmt.Errorf("invalid Git history diff record")
			}
			if !regularMode(fields[1]) {
				continue
			}
			path := string(records[i+1])
			versions = append(versions, version{path, fields[3]})
			candidates = append(candidates, nativePath(root, path))
		}
		if len(versions) == 0 {
			continue
		}
		tree, err := historyGit("ls-tree", "-r", "-z", "--full-tree", commit)
		if err != nil {
			return result, err
		}
		ownRules := map[string][]byte{}
		for _, record := range bytes.Split(tree, []byte{0}) {
			header, path, ok := strings.Cut(string(record), "\t")
			if !ok || filepath.Base(path) != ".gitage" {
				continue
			}
			fields := strings.Fields(header)
			if len(fields) != 3 || !regularMode(fields[0]) {
				continue
			}
			content, err := historyGit("cat-file", "blob", fields[2])
			if err != nil {
				return result, err
			}
			ownRules[nativePath(root, path)] = content
		}
		hasRules = hasRules || len(ownRules) != 0
		protected := map[string]bool{}
		for _, rules := range []map[string][]byte{currentRules, ownRules} {
			if len(rules) == 0 {
				continue
			}
			files, err := matchProtectedFiles(root, root, candidates, rules, ruleIgnoreCase(root, true))
			if err != nil {
				return result, fmt.Errorf("check outgoing commit %s: %w", commit[:12], err)
			}
			for _, file := range files {
				protected[file.Path] = true
			}
		}
		for _, version := range versions {
			introduced[version] = introduced[version] || protected[version.path]
		}
	}
	type blobState struct{ empty, locked, privateKey bool }
	states := map[string]blobState{}
	plaintext, keys := map[string]bool{}, map[string]bool{}
	for version, protected := range introduced {
		state, exists := states[version.oid]
		if !exists {
			content, err := historyGit("cat-file", "blob", version.oid)
			if err != nil {
				return result, err
			}
			state = blobState{len(content) == 0, contentState(content) == Locked, bytes.Contains(content, []byte("AGE-SECRET-KEY-"))}
			states[version.oid] = state
		}
		if filepath.Base(version.path) == ".gitage.key" || hasRules && !state.locked && state.privateKey {
			keys[version.path] = true
		}
		if protected && !state.empty && !state.locked {
			plaintext[version.path] = true
		}
	}
	for path := range keys {
		result.PrivateKeys = append(result.PrivateKeys, path)
	}
	for path := range plaintext {
		result.Plaintext = append(result.Plaintext, path)
	}
	slices.Sort(result.PrivateKeys)
	slices.Sort(result.Plaintext)
	return result, nil
}

func validObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
