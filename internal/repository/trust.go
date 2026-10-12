package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	trustedRecipientsEnv    = "GIT_AGE_TRUSTED_RECIPIENTS"
	trustedRecipientsConfig = "age.trustedRecipients"
	// trustHistoryLimit bounds the search for the pinned lists in history.
	trustHistoryLimit = 200
)

// recipientLists maps each rule file with [recipients], relative to the Git
// root with forward slashes, to its recipients, sorted and without duplicates.
type recipientLists map[string][]string

// Trust describes the current [recipients] lists and the pinned ones.
type Trust struct {
	Hash    string   // The hash of the current lists.
	Pinned  string   // The pinned hash, or "" when nothing is pinned.
	Source  string   // Where Pinned comes from, for messages.
	Lists   []string // The current recipient lists, formatted for display.
	Details []string // The current lists without a pin, or how they differ from it.
	root    string
}

// Trusted reports whether nothing is pinned or the current lists are.
func (t Trust) Trusted() bool {
	return t.Pinned == "" || t.Pinned == t.Hash
}

// RecipientTrust compares the working tree's [recipients] lists, in the
// whole worktree containing directory, with the pinned ones.
func RecipientTrust(directory string) (Trust, error) {
	root, err := Root(directory, "trust")
	if err != nil {
		return Trust{}, err
	}
	lists, err := workingRecipientLists(root)
	if err != nil {
		return Trust{}, err
	}
	return recipientTrust(root, lists)
}

func recipientTrust(root string, lists recipientLists) (Trust, error) {
	trust := Trust{Hash: trustHash(lists), Lists: describeLists(lists), root: root}
	var err error
	switch trust.Pinned, trust.Source, err = pinnedTrust(root); {
	case err != nil || trust.Pinned == trust.Hash:
	case trust.Pinned == "":
		trust.Details = describeLists(lists)
	default:
		trust.Details, err = trustedChanges(root, lists, trust.Pinned)
	}
	return trust, err
}

// RecipientsUntrusted reports whether the working tree's [recipients] lists
// differ from the pinned ones; never outside a Git worktree.
func RecipientsUntrusted(directory string) (bool, error) {
	root, err := gitRoot(directory)
	if err != nil || root == "" {
		return false, err
	}
	trust, err := RecipientTrust(root)
	return !trust.Trusted(), err
}

// Pin records the current lists in the repository's Git config.
func (t Trust) Pin() error {
	return setLocalConfig(t.root, trustedRecipientsConfig, t.Hash)
}

// PinOverridden reports whether GIT_AGE_TRUSTED_RECIPIENTS takes precedence over Pin.
func PinOverridden() bool {
	return strings.TrimSpace(os.Getenv(trustedRecipientsEnv)) != ""
}

// checkRecipientTrust refuses to encrypt when the [recipients] lists differ
// from the pinned ones. It reads rules, or the working tree when rules is nil.
func checkRecipientTrust(root string, rules map[string][]byte) error {
	var lists recipientLists
	var err error
	if rules == nil {
		lists, err = workingRecipientLists(root)
	} else {
		lists, err = rulesRecipientLists(root, rules)
	}
	if err != nil {
		return err
	}
	trust, err := recipientTrust(root, lists)
	if err != nil || trust.Trusted() {
		return err
	}
	return fmt.Errorf("refusing to encrypt to untrusted [recipients]; they differ from the ones you trusted (%s):\n\n%s\n\nReview the changes, then trust the current lists:\n\n  git-age trust",
		trust.Source, strings.Join(trust.Details, "\n"))
}

func workingRecipientLists(root string) (recipientLists, error) {
	paths, err := regularFiles(root, true)
	if err != nil {
		return nil, err
	}
	rules, err := readRules(paths)
	if err != nil {
		return nil, err
	}
	return rulesRecipientLists(root, rules)
}

// rulesRecipientLists reads the lists in rules, keyed by absolute path.
func rulesRecipientLists(root string, rules map[string][]byte) (recipientLists, error) {
	lists := recipientLists{}
	for path, content := range rules {
		_, recipients, err := parseRules(path, content)
		if err != nil {
			return nil, err
		}
		if len(recipients) != 0 {
			relative, _ := filepath.Rel(root, path)
			lists[filepath.ToSlash(relative)] = recipientKeys(recipients)
		}
	}
	return lists, nil
}

// recipientListsAt reads the lists in revision, skipping malformed rule files.
func recipientListsAt(root, revision string) (recipientLists, error) {
	lists := recipientLists{}
	if !hasCommit(root, revision) {
		return lists, nil
	}
	output, err := git(root, "ls-tree", "-r", "-z", revision)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", revision, err)
	}
	for _, record := range strings.Split(string(output), "\x00") {
		header, path, ok := strings.Cut(record, "\t")
		fields := strings.Fields(header)
		if !ok || len(fields) != 3 || !regularMode(fields[0]) || filepath.Base(path) != ".gitage" {
			continue
		}
		content, err := git(root, "cat-file", "blob", fields[2])
		if err != nil {
			return nil, err
		}
		if _, recipients, err := parseRules(path, content); err == nil && len(recipients) != 0 {
			lists[path] = recipientKeys(recipients)
		}
	}
	return lists, nil
}

// recipientKeys normalizes recipients for comparison: SSH keys lose their comments.
func recipientKeys(recipients []string) []string {
	keys := make([]string, len(recipients))
	for i, recipient := range recipients {
		if strings.HasPrefix(recipient, "ssh-") {
			recipient = strings.Join(strings.Fields(recipient)[:2], " ")
		}
		keys[i] = recipient
	}
	slices.Sort(keys)
	return slices.Compact(keys)
}

// trustHash is the SHA-256 that age.trustedRecipients pins; order, duplicates
// and comments do not count.
func trustHash(lists recipientLists) string {
	var text strings.Builder
	for _, path := range slices.Sorted(maps.Keys(lists)) {
		text.WriteString(path + "\n")
		for _, key := range lists[path] {
			text.WriteString("\t" + key + "\n")
		}
	}
	sum := sha256.Sum256([]byte(text.String()))
	return hex.EncodeToString(sum[:])
}

// pinnedTrust returns the pinned hash and where it comes from, if any.
func pinnedTrust(root string) (string, string, error) {
	if value := strings.TrimSpace(os.Getenv(trustedRecipientsEnv)); value != "" {
		return strings.ToLower(value), trustedRecipientsEnv, nil
	}
	values, err := configValues(root, trustedRecipientsConfig)
	if err != nil || len(values) == 0 {
		return "", "", err
	}
	if value := strings.TrimSpace(values[len(values)-1]); value != "" {
		return strings.ToLower(value), "git config " + trustedRecipientsConfig, nil
	}
	return "", "", nil
}

// trustedChanges describes how lists differ from the pinned ones: when
// history has them, a diff and the commits since; otherwise the lists.
func trustedChanges(root string, lists recipientLists, pinned string) ([]string, error) {
	head, err := recipientListsAt(root, "HEAD")
	if err != nil {
		return nil, err
	}
	var trusted recipientLists
	var newer []string
	if trustHash(head) == pinned {
		trusted = head
	} else {
		commits, err := gitageCommits(root, "HEAD")
		if err != nil {
			return nil, err
		}
		for _, commit := range commits {
			candidate, err := recipientListsAt(root, commit.id)
			if err != nil {
				return nil, err
			}
			if trustHash(candidate) == pinned {
				trusted = candidate
				break
			}
			newer = append(newer, "  "+commit.String())
		}
	}
	if trusted == nil {
		return append([]string{
			fmt.Sprintf("The trusted lists are not in the last %d commits that touch .gitage; these are the current ones:", trustHistoryLimit),
			"",
		}, describeLists(lists)...), nil
	}
	lines := describeListChanges(trusted, lists)
	lines = append(lines, "", "Commits that touched .gitage since:")
	lines = append(lines, newer...)
	if trustHash(lists) != trustHash(head) {
		lines = append(lines, "  (uncommitted changes)")
	}
	return lines, nil
}

type gitageCommit struct {
	id, author, email, subject string
}

func (c gitageCommit) String() string {
	return fmt.Sprintf("%s %s <%s>  %s", c.id[:12], c.author, c.email, c.subject)
}

// gitageCommits lists the newest commits in revision that touch a .gitage, newest first.
func gitageCommits(root, revision string) ([]gitageCommit, error) {
	if !hasCommit(root, revision) {
		return nil, nil
	}
	output, err := git(root, "log", "--format=%H%x00%an%x00%ae%x00%s", fmt.Sprintf("-n%d", trustHistoryLimit), revision, "--", ":(glob)**/.gitage")
	if err != nil {
		return nil, fmt.Errorf("read .gitage history: %w", err)
	}
	var commits []gitageCommit
	for _, line := range strings.Split(string(output), "\n") {
		if fields := strings.SplitN(line, "\x00", 4); len(fields) == 4 {
			commits = append(commits, gitageCommit{fields[0], fields[1], fields[2], fields[3]})
		}
	}
	return commits, nil
}

func describeListChanges(old, new recipientLists) []string {
	paths := slices.Sorted(maps.Keys(old))
	for path := range new {
		if _, ok := old[path]; !ok {
			paths = append(paths, path)
		}
	}
	slices.Sort(paths)
	var lines []string
	for _, path := range paths {
		before, after := old[path], new[path]
		if slices.Equal(before, after) {
			continue
		}
		lines = append(lines, "  "+path)
		for _, key := range after {
			if !slices.Contains(before, key) {
				lines = append(lines, "    + "+key)
			}
		}
		for _, key := range before {
			if !slices.Contains(after, key) {
				lines = append(lines, "    - "+key)
			}
		}
	}
	return lines
}

func describeLists(lists recipientLists) []string {
	var lines []string
	for _, path := range slices.Sorted(maps.Keys(lists)) {
		lines = append(lines, "  "+path)
		for _, key := range lists[path] {
			lines = append(lines, "    "+key)
		}
	}
	if len(lines) == 0 {
		return []string{"  (none)"}
	}
	return lines
}
