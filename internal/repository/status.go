package repository

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

// FileStatus describes how a protected file is encrypted.
type FileStatus struct {
	Stale    bool   // Still encrypted to a previous [recipients] list.
	NoAccess bool   // Locked and not encrypted to the user.
	Target   string // What the file is encrypted to.
}

// Statuses describes files, as ProtectedFiles lists them for directory, and
// says what files are encrypted to without nested [recipients].
func Statuses(directory string, files []ProtectedFile) ([]FileStatus, string, error) {
	directory, root, inGit, err := resolveDirectory(directory)
	if err != nil {
		return nil, "", err
	}
	// Status works without a usable identity; it then assumes access.
	identities, _ := loadIdentities(directory, root, nil)
	keys, err := resolveKeys(directory, root, nil, identities, nil)
	if err != nil {
		return nil, "", err
	}
	history := newRecipientHistory(root, inGit)
	statuses := make([]FileStatus, len(files))
	for i, file := range files {
		path := nativePath(directory, file.Path)
		target, err := keys.describeTarget(root, path, nil)
		if err != nil {
			return nil, "", err
		}
		statuses[i].Target = target.source
		if file.State != Locked {
			continue
		}
		mine, err := keys.encryptedToUser(target)
		if err != nil {
			return nil, "", err
		}
		statuses[i].NoAccess = !mine
		statuses[i].Stale = history.stale(path)
	}
	return statuses, keys.describe(), nil
}

// recipientHistory finds locked files still encrypted to a previous
// [recipients] list: unchanged since before their recipients last changed.
type recipientHistory struct {
	root      string
	inGit     bool
	baselines map[string]string
}

func newRecipientHistory(root string, inGit bool) *recipientHistory {
	return &recipientHistory{root: root, inGit: inGit, baselines: map[string]string{}}
}

// stale reports whether the locked file at path needs `git-age rekey`.
func (h *recipientHistory) stale(path string) bool {
	if !h.inGit {
		return false
	}
	directory := filepath.Dir(path)
	revision, ok := h.baselines[directory]
	if !ok {
		revision = h.baseline(directory)
		h.baselines[directory] = revision
	}
	if revision == "" {
		return false
	}
	relative, _ := filepath.Rel(h.root, path)
	previous, err := git(h.root, "show", revision+":"+filepath.ToSlash(relative))
	if err != nil {
		return false
	}
	current, err := os.ReadFile(path)
	return err == nil && bytes.Equal(previous, current)
}

// baseline returns the newest revision whose [recipients] for files in
// directory differ from the working tree's, or "" when they never changed.
func (h *recipientHistory) baseline(directory string) string {
	if !hasCommit(h.root, "HEAD") {
		return ""
	}
	var rulePaths, current []string
	for _, parent := range ancestorDirs(h.root, directory) {
		rule := filepath.Join(parent, ".gitage")
		relative, _ := filepath.Rel(h.root, rule)
		rulePaths = append(rulePaths, filepath.ToSlash(relative))
		if recipients, err := ruleRecipients(rule, nil); err == nil {
			current = append(current, recipients...)
		}
	}
	if !sameRecipients(h.recipientsAt("HEAD", rulePaths), current) {
		return "HEAD"
	}
	// Recipients only change in commits touching these rule files.
	log, err := git(h.root, append([]string{"--literal-pathspecs", "log", "--format=%H", "HEAD", "--"}, rulePaths...)...)
	if err != nil {
		return ""
	}
	for _, commit := range strings.Fields(string(log)) {
		parent := commit + "^"
		if !hasCommit(h.root, parent) {
			return ""
		}
		if !sameRecipients(h.recipientsAt(parent, rulePaths), current) {
			return parent
		}
	}
	return ""
}

// recipientsAt combines the [recipients] of the rule files at revision,
// ignoring missing and malformed ones.
func (h *recipientHistory) recipientsAt(revision string, rulePaths []string) []string {
	var recipients []string
	for _, path := range rulePaths {
		content, err := git(h.root, "show", revision+":"+path)
		if err != nil {
			continue
		}
		if _, listed, err := parseRules(path, content); err == nil {
			recipients = append(recipients, listed...)
		}
	}
	return recipients
}

func hasCommit(root, revision string) bool {
	_, err := git(root, "rev-parse", "--verify", "--quiet", revision+"^{commit}")
	return err == nil
}
