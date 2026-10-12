package repository

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"os/exec"
	"path"
	"slices"
	"strconv"
	"strings"
)

// originalRefs backs up the refs `history rekey` rewrote, so that it can be undone.
const originalRefs = "refs/git-age/original"

// DeleteOriginalRefs is the command that drops the backup of a history rekey.
const DeleteOriginalRefs = "git for-each-ref --format='delete %(refname)' " + originalRefs + " | git update-ref --stdin"

// objectReader reads Git objects through one long-running git cat-file --batch.
type objectReader struct {
	command *exec.Cmd
	input   io.WriteCloser
	output  *bufio.Reader
}

func newObjectReader(root string) (*objectReader, error) {
	command := exec.Command("git", "-C", root, "cat-file", "--batch")
	input, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	return &objectReader{command, input, bufio.NewReader(output)}, nil
}

func (r *objectReader) read(oid string) ([]byte, error) {
	if _, err := io.WriteString(r.input, oid+"\n"); err != nil {
		return nil, err
	}
	header, err := r.output.ReadString('\n')
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(header)
	if len(fields) != 3 {
		return nil, fmt.Errorf("cannot read Git object %s", oid)
	}
	size, err := strconv.Atoi(fields[2])
	if err != nil {
		return nil, fmt.Errorf("cannot read Git object %s", oid)
	}
	content := make([]byte, size+1) // With the newline after the object.
	if _, err := io.ReadFull(r.output, content); err != nil {
		return nil, err
	}
	return content[:size], nil
}

func (r *objectReader) close() error {
	r.input.Close()
	return r.command.Wait()
}

// rawChange is one record of git log --raw.
type rawChange struct {
	commit, mode, oid, status, path string
}

// rawChanges parses git log --format=%x00%H --raw -z --no-renames.
func rawChanges(output []byte) []rawChange {
	var changes []rawChange
	var commit string
	tokens := bytes.Split(output, []byte{0})
	for i := 0; i < len(tokens); i++ {
		token := bytes.TrimLeft(tokens[i], "\n")
		if bytes.HasPrefix(token, []byte(":")) && i+1 < len(tokens) {
			fields := strings.Fields(string(token[1:]))
			i++
			if len(fields) == 5 {
				changes = append(changes, rawChange{commit, fields[1], fields[3], fields[4], string(tokens[i])})
			}
		} else if len(token) != 0 {
			commit = string(token)
		}
	}
	return changes
}

// history holds the commits of some revisions and the .gitage rules in each;
// paths are slash-separated and relative to the Git root.
//
// A path counts as protected in a commit when the current .gitage files
// protect it or the commit's own did: a secret committed before its pattern
// was added leaked just the same.
type history struct {
	root       string
	reader     *objectReader
	revisions  []string
	commits    []string
	parents    map[string]string // First parents.
	states     map[string]string // Commit to its rule state: its .gitage paths and blobs.
	current    map[string][]byte // The working tree's .gitage files, by native path.
	ignoreCase string
	// protection holds, by rule state, whether those rules protect each path;
	// the current rules use the empty state.
	protection map[string]map[string]bool
	Warnings   []string
}

func newHistory(root string, reader *objectReader, revisions []string) (*history, error) {
	paths, err := regularFiles(root, true)
	if err != nil {
		return nil, err
	}
	current, err := readRules(paths)
	if err != nil {
		return nil, err
	}
	h := &history{
		root: root, reader: reader, revisions: revisions, parents: map[string]string{}, states: map[string]string{},
		current: current, ignoreCase: ruleIgnoreCase(root, true), protection: map[string]map[string]bool{},
	}
	// Parents first, since a commit's rules start from its parent's.
	output, err := git(root, append(append([]string{"rev-list", "--topo-order", "--reverse", "--parents"}, revisions...), "--")...)
	if err != nil {
		return nil, fmt.Errorf("cannot list the commits to audit: %w", gitError(err))
	}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		h.commits = append(h.commits, fields[0])
		if len(fields) > 1 {
			h.parents[fields[0]] = fields[1]
		}
	}
	return h, h.loadRuleStates()
}

func gitError(err error) error {
	var exit *exec.ExitError
	if errors.As(err, &exit) && len(exit.Stderr) != 0 {
		return fmt.Errorf("%s", bytes.TrimSpace(exit.Stderr))
	}
	return err
}

func (h *history) log(args []string, pathspecs ...string) ([]byte, error) {
	args = append([]string{"log", "--root", "--raw", "-z", "--no-abbrev", "--no-renames", "--format=%x00%H"}, args...)
	args = append(append(append(args, h.revisions...), "--"), pathspecs...)
	output, err := git(h.root, args...)
	if err != nil {
		return nil, fmt.Errorf("cannot read the history: %w", gitError(err))
	}
	return output, nil
}

// loadRuleStates tracks the .gitage files commit by commit: a commit has its
// first parent's, changed by its diff to that parent.
func (h *history) loadRuleStates() error {
	if len(h.commits) == 0 {
		return nil
	}
	output, err := h.log([]string{"--full-history", "--diff-merges=first-parent"}, ":(glob)**/.gitage")
	if err != nil {
		return err
	}
	changes := map[string][]rawChange{}
	for _, change := range rawChanges(output) {
		if path.Base(change.path) == ".gitage" {
			changes[change.commit] = append(changes[change.commit], change)
		}
	}
	for _, commit := range h.commits {
		state := ""
		if parent, ok := h.parents[commit]; ok {
			if state, err = h.ruleState(parent); err != nil {
				return err
			}
		}
		if len(changes[commit]) != 0 {
			files := parseRuleState(state)
			for _, change := range changes[commit] {
				if change.status == "D" || !regularMode(change.mode) {
					delete(files, change.path)
				} else {
					files[change.path] = change.oid
				}
			}
			state = formatRuleState(files)
		}
		h.states[commit] = state
	}
	return nil
}

// ruleState returns the rule state of commit, reading the tree of a commit
// outside the revisions, such as the one below a range.
func (h *history) ruleState(commit string) (string, error) {
	if state, ok := h.states[commit]; ok {
		return state, nil
	}
	output, err := git(h.root, "ls-tree", "-r", "-z", "--full-tree", commit)
	if err != nil {
		return "", fmt.Errorf("cannot read the tree of %s: %w", commit, gitError(err))
	}
	files := map[string]string{}
	for _, record := range bytes.Split(output, []byte{0}) {
		header, name, ok := strings.Cut(string(record), "\t")
		fields := strings.Fields(header)
		if ok && path.Base(name) == ".gitage" && len(fields) == 3 && regularMode(fields[0]) {
			files[name] = fields[2]
		}
	}
	h.states[commit] = formatRuleState(files)
	return h.states[commit], nil
}

func formatRuleState(files map[string]string) string {
	var lines []string
	for name, oid := range files {
		lines = append(lines, name+"\x00"+oid)
	}
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}

func parseRuleState(state string) map[string]string {
	files := map[string]string{}
	for _, line := range strings.Split(state, "\n") {
		if name, oid, ok := strings.Cut(line, "\x00"); ok {
			files[name] = oid
		}
	}
	return files
}

// prepare decides, for every rule state of the history and the current
// rules, which of paths they protect.
func (h *history) prepare(paths []string) error {
	states := map[string]bool{}
	for _, state := range h.states {
		if state != "" {
			states[state] = true
		}
	}
	if err := h.match("", h.current, paths); err != nil {
		return err
	}
	for state := range states {
		rules := map[string][]byte{}
		for name, oid := range parseRuleState(state) {
			content, err := h.reader.read(oid)
			if err != nil {
				return err
			}
			rules[nativePath(h.root, name)] = content
		}
		if err := h.match(state, rules, paths); err != nil {
			// Unparsable rules in old commits must not hide what the current rules find.
			h.Warnings = append(h.Warnings, fmt.Sprintf("%v; using only the current rules there", err))
			h.protection[state] = map[string]bool{}
		}
	}
	return nil
}

func (h *history) match(state string, rules map[string][]byte, paths []string) error {
	known := h.protection[state]
	if known == nil {
		known = map[string]bool{}
	}
	var candidates []string
	for _, name := range paths {
		if _, ok := known[name]; !ok {
			candidates = append(candidates, nativePath(h.root, name))
			known[name] = false
		}
	}
	if len(rules) != 0 && len(candidates) != 0 {
		for name, content := range rules {
			if _, _, err := parseRules(name, content); err != nil {
				return err
			}
		}
		files, err := matchProtectedFiles(h.root, h.root, candidates, rules, h.ignoreCase)
		if err != nil {
			return err
		}
		for _, file := range files {
			known[file.Path] = true
		}
	}
	h.protection[state] = known
	return nil
}

// protects reports whether path is protected in commit; prepare must have seen path.
func (h *history) protects(commit, path string) bool {
	return h.protection[""][path] || h.protection[h.states[commit]][path]
}

// version is a blob at a path.
type version struct{ path, oid string }

// introduced lists every regular-file blob a commit added or changed, with the
// commits that did, oldest first. Merges count with what they changed against
// each parent, which includes conflict resolutions.
func (h *history) introduced() (map[version][]string, error) {
	introduced := map[version][]string{}
	if len(h.commits) == 0 {
		return introduced, nil
	}
	output, err := h.log([]string{"--topo-order", "--reverse", "--diff-merges=separate"})
	if err != nil {
		return nil, err
	}
	for _, change := range rawChanges(output) {
		if change.status == "D" || !regularMode(change.mode) {
			continue
		}
		key := version{change.path, change.oid}
		if !slices.Contains(introduced[key], change.commit) {
			introduced[key] = append(introduced[key], change.commit)
		}
	}
	return introduced, nil
}

// Leak is a blob that should not be in history: plaintext at a protected
// path, or a private key.
type Leak struct {
	Path, OID string
	Commits   []string // Each as its abbreviated ID and subject.
}

// Leaks is what an audit finds.
type Leaks struct {
	Commits     int
	Plaintext   []Leak
	PrivateKeys []Leak
	Warnings    []string
}

// Audit searches the commits of revisions, or of every ref but the backup of
// a history rekey, for plaintext at protected paths and for private keys.
func Audit(directory string, revisions []string, reflog bool) (Leaks, error) {
	root, err := Root(directory, "history audit")
	if err != nil {
		return Leaks{}, err
	}
	if len(revisions) == 0 {
		// What a rekey backed up is the old history it replaced.
		revisions = []string{"--exclude=" + originalRefs + "/*", "--all"}
	}
	if reflog {
		revisions = append(slices.Clone(revisions), "--reflog")
	}
	reader, err := newObjectReader(root)
	if err != nil {
		return Leaks{}, err
	}
	defer reader.close()
	h, err := newHistory(root, reader, revisions)
	if err != nil {
		return Leaks{}, err
	}
	return findLeaks(h)
}

// findLeaks reads every blob once. Empty files hide nothing.
func findLeaks(h *history) (Leaks, error) {
	leaks := Leaks{Commits: len(h.commits)}
	introduced, err := h.introduced()
	if err != nil {
		return leaks, err
	}
	order := map[string]int{}
	for i, commit := range h.commits {
		order[commit] = i
	}
	versions := make([]version, 0, len(introduced))
	paths := map[string]bool{}
	for v := range introduced {
		versions = append(versions, v)
		paths[v.path] = true
	}
	slices.SortFunc(versions, func(a, b version) int {
		if c := strings.Compare(a.path, b.path); c != 0 {
			return c
		}
		return order[introduced[a][0]] - order[introduced[b][0]]
	})
	if err := h.prepare(slices.Sorted(maps.Keys(paths))); err != nil {
		return leaks, err
	}
	leaks.Warnings = h.Warnings

	type blobState struct{ plaintext, privateKey bool }
	blobs := map[string]blobState{}
	subjects := map[string]string{}
	describe := func(commits []string) ([]string, error) {
		var described []string
		for _, commit := range commits {
			if _, ok := subjects[commit]; !ok {
				content, err := h.reader.read(commit)
				if err != nil {
					return nil, err
				}
				_, message, _ := bytes.Cut(content, []byte("\n\n"))
				subject, _, _ := bytes.Cut(message, []byte("\n"))
				subjects[commit] = commit[:12] + "  " + string(subject)
			}
			described = append(described, subjects[commit])
		}
		return described, nil
	}
	for _, v := range versions {
		state, ok := blobs[v.oid]
		if !ok {
			content, err := h.reader.read(v.oid)
			if err != nil {
				return leaks, err
			}
			plaintext := len(content) != 0 && contentState(content) == Unlocked
			state = blobState{plaintext, plaintext && bytes.Contains(content, []byte("AGE-SECRET-KEY-"))}
			blobs[v.oid] = state
		}
		commits := introduced[v]
		if path.Base(v.path) == ".gitage.key" || state.privateKey {
			described, err := describe(commits)
			if err != nil {
				return leaks, err
			}
			leaks.PrivateKeys = append(leaks.PrivateKeys, Leak{v.path, v.oid, described})
		}
		var protecting []string
		for _, commit := range commits {
			if h.protects(commit, v.path) {
				protecting = append(protecting, commit)
			}
		}
		if len(protecting) != 0 && state.plaintext {
			described, err := describe(protecting)
			if err != nil {
				return leaks, err
			}
			leaks.Plaintext = append(leaks.Plaintext, Leak{v.path, v.oid, described})
		}
	}
	return leaks, nil
}
