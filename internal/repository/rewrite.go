package repository

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
)

// Remote-tracking refs are left out: they record what the remote has.
var rewrittenRefPrefixes = []string{"refs/heads/", "refs/tags/", "refs/stash"}

var tagSignature = regexp.MustCompile(`(?m)^-----BEGIN (?:PGP SIGNATURE|PGP MESSAGE|SSH SIGNATURE|SIGNED MESSAGE)-----$`)

// CheckRewritable refuses to rewrite history where that could lose work or miss commits.
func CheckRewritable(directory string) error {
	root, err := Root(directory, "history rewrite")
	if err != nil {
		return err
	}
	fail := func(reason string) error { return fmt.Errorf("cannot rewrite history: %s", reason) }
	if output, err := git(root, "rev-parse", "--is-shallow-repository"); err != nil {
		return err
	} else if strings.TrimSpace(string(output)) == "true" {
		return fail("this is a shallow clone; fetch the full history with `git fetch --unshallow`")
	}
	grafts, err := gitPath(root, "info/grafts")
	if err != nil {
		return err
	}
	if output, err := git(root, "for-each-ref", "--count=1", "refs/replace/"); err != nil {
		return err
	} else if _, statErr := os.Lstat(grafts); len(output) != 0 || statErr == nil {
		return fail("the repository uses replace refs or grafts")
	}
	if output, err := git(root, "for-each-ref", "--count=1", originalRefs+"/"); err != nil {
		return err
	} else if len(output) != 0 {
		return fail(originalRefs + " holds a previous rewrite; once you no longer need it:\n\n  " + DeleteOriginalRefs)
	}
	for _, state := range []struct{ name, operation string }{
		{"MERGE_HEAD", "a merge"},
		{"CHERRY_PICK_HEAD", "a cherry-pick"},
		{"REVERT_HEAD", "a revert"},
		{"rebase-merge", "a rebase"},
		{"rebase-apply", "a rebase or git am"},
		{"BISECT_LOG", "a bisect"},
	} {
		name, err := gitPath(root, state.name)
		if err != nil {
			return err
		}
		if _, err := os.Lstat(name); err == nil {
			return fail(state.operation + " is in progress")
		}
	}
	worktrees, err := git(root, "worktree", "list", "--porcelain")
	if err != nil {
		return err
	}
	if bytes.Count(worktrees, []byte("worktree ")) > 1 {
		return fail("the repository has other worktrees; remove them with `git worktree remove`")
	}
	if status, err := git(root, "status", "--porcelain", "--untracked-files=no"); err != nil {
		return err
	} else if len(status) != 0 {
		return fail("there are uncommitted changes; commit or stash them first")
	}
	return nil
}

// RefMove is a ref a history rewrite moves.
type RefMove struct{ Ref, Old, New string }

// HistoryRekeyOptions configures a history rekey.
type HistoryRekeyOptions struct {
	Recipients, Identities []string
	PlaintextOnly          bool // Keep existing ciphertext.
	DryRun                 bool // Write nothing, making up the new object IDs.
}

// HistoryRekey re-encrypts the protected files of every commit of the local
// branches, tags and stash to the current recipients. Preparing it only writes
// objects; Apply then moves the refs.
type HistoryRekey struct {
	*HistoryRewrite
	Encrypted, Reencrypted int
	Undecryptable          []string // Versions that stay as they are, as "path in commit".
	PrivateKeys            int      // Private key files in history, which stay there.
}

// HistoryRewrite holds the ref changes shared by history rekey and purge.
type HistoryRewrite struct {
	Commits, Changed int
	Moves            []RefMove
	Signatures       int // Commit and tag signatures dropped.
	Warnings         []string

	root, directory string
	identities      []string
	operation       string
}

type rewriteRef struct{ name, oid, kind string }

// PrepareHistoryRekey writes the rewritten objects.
func PrepareHistoryRekey(directory string, options HistoryRekeyOptions) (*HistoryRekey, error) {
	directory, root, _, err := resolveDirectory(directory)
	if err != nil {
		return nil, err
	}
	if !options.DryRun {
		if err := checkRecipientTrust(root, nil); err != nil {
			return nil, err
		}
	}
	keys, err := loadKeys(directory, root, options.Recipients, options.Identities, nil)
	if err != nil {
		return nil, err
	}
	if !options.PlaintextOnly && len(keys.identities) == 0 {
		return nil, errNoIdentity
	}
	refs, err := rewritableRefs(root)
	if err != nil {
		return nil, err
	}
	result := &HistoryRekey{HistoryRewrite: &HistoryRewrite{root: root, directory: directory, identities: options.Identities, operation: "rekey"}}
	if len(refs) == 0 {
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
	// Every path in a tree was introduced by one of the commits.
	leaks, err := findLeaks(h)
	if err != nil {
		return nil, err
	}
	keyFiles := map[string]bool{}
	for _, leak := range leaks.PrivateKeys {
		keyFiles[leak.Path] = true
	}
	result.PrivateKeys, result.Warnings = len(keyFiles), leaks.Warnings

	r := &rewriter{
		HistoryRewrite: result.HistoryRewrite, rekey: result, history: h, keys: keys, options: options,
		oidLength: len(h.commits[0]) / 2, targets: map[string]fileTarget{},
		blobs: map[string]string{}, trees: map[string]string{}, commits: map[string]string{}, tags: map[string]string{},
		undecryptable: map[version]string{},
	}
	if err := r.rewriteRefs(refs); err != nil {
		return nil, err
	}
	for v, commit := range r.undecryptable {
		result.Undecryptable = append(result.Undecryptable, v.path+" in "+commit[:12])
	}
	slices.Sort(result.Undecryptable)
	return result, nil
}

func (r *rewriter) rewriteRefs(refs []rewriteRef) error {
	for _, commit := range r.history.commits {
		if err := r.rewriteCommit(commit); err != nil {
			return err
		}
	}
	for _, ref := range refs {
		updated := r.commits[ref.oid]
		if ref.kind == "tag" {
			var err error
			if updated, err = r.rewriteTag(ref.oid); err != nil {
				return err
			}
		}
		if updated != "" && updated != ref.oid {
			r.Moves = append(r.Moves, RefMove{ref.name, ref.oid, updated})
		}
	}
	r.Commits = len(r.history.commits)
	for old, updated := range r.commits {
		if old != updated {
			r.Changed++
		}
	}
	return nil
}

type rewriter struct {
	*HistoryRewrite
	rekey     *HistoryRekey
	history   *history
	keys      keys
	options   HistoryRekeyOptions
	oidLength int
	targets   map[string]fileTarget // By directory.
	// Rewritten objects: blobs by old ID and recipients, trees by path, old
	// ID and rule state, commits and tags by old ID.
	blobs, trees, commits, tags map[string]string
	undecryptable               map[version]string // The first commit of each.
	purge                       map[string]bool    // Non-nil for purge, by repository-relative path.
}

func (r *rewriter) write(kind string, content []byte) (string, error) {
	if r.options.DryRun {
		header := []byte(fmt.Sprintf("%s %d\x00", kind, len(content)))
		if r.oidLength == sha1.Size {
			sum := sha1.Sum(append(header, content...))
			return hex.EncodeToString(sum[:]), nil
		}
		sum := sha256.Sum256(append(header, content...))
		return hex.EncodeToString(sum[:]), nil
	}
	output, err := gitWithInput(r.root, content, "hash-object", "-t", kind, "-w", "--stdin")
	if err != nil {
		return "", fmt.Errorf("cannot write a Git %s: %w", kind, err)
	}
	return strings.TrimSpace(string(output)), nil
}

func (r *rewriter) target(name string) (fileTarget, error) {
	directory := path.Dir(name)
	if target, ok := r.targets[directory]; ok {
		return target, nil
	}
	target, err := r.keys.target(r.root, nativePath(r.root, name), nil)
	if err != nil {
		return target, fmt.Errorf("%s: %w", name, err)
	}
	r.targets[directory] = target
	return target, nil
}

func (r *rewriter) encrypt(target fileTarget, plaintext []byte) (string, error) {
	if r.options.DryRun {
		return r.write("blob", plaintext)
	}
	ciphertext, err := encryptContent(plaintext, target.recipients)
	if err != nil {
		return "", err
	}
	return r.write("blob", ciphertext)
}

func (r *rewriter) rewriteBlob(commit, name, oid string) (string, error) {
	target, err := r.target(name)
	if err != nil {
		return "", err
	}
	key := oid + "\n" + strings.Join(target.values, "\n")
	if updated, ok := r.blobs[key]; ok {
		return updated, nil
	}
	content, err := r.history.reader.read(oid)
	if err != nil {
		return "", err
	}
	updated := oid
	if contentState(content) == Unlocked {
		if updated, err = r.encrypt(target, content); err != nil {
			return "", err
		}
		r.rekey.Encrypted++
	} else if !r.options.PlaintextOnly {
		plaintext, err := decryptContent(content, r.keys.identities)
		if errors.Is(err, errNoIdentity) {
			return "", err
		}
		if err != nil {
			if _, ok := r.undecryptable[version{name, oid}]; !ok {
				r.undecryptable[version{name, oid}] = commit
			}
		} else {
			if updated, err = r.encrypt(target, plaintext); err != nil {
				return "", err
			}
			r.rekey.Reencrypted++
		}
	}
	r.blobs[key] = updated
	return updated, nil
}

func (r *rewriter) rewriteTree(commit, prefix, oid string) (string, error) {
	key := prefix + "\x00" + oid + "\x00" + r.history.states[commit]
	if updated, ok := r.trees[key]; ok {
		return updated, nil
	}
	content, err := r.history.reader.read(oid)
	if err != nil {
		return "", err
	}
	var rewritten bytes.Buffer
	changed := false
	for len(content) != 0 {
		space := bytes.IndexByte(content, ' ')
		nul := bytes.IndexByte(content, 0)
		if space < 0 || nul < space || nul+1+r.oidLength > len(content) {
			return "", fmt.Errorf("invalid Git tree %s", oid)
		}
		mode, entryName := string(content[:space]), string(content[space+1:nul])
		entry := hex.EncodeToString(content[nul+1 : nul+1+r.oidLength])
		content = content[nul+1+r.oidLength:]
		name := path.Join(prefix, entryName)
		updated := entry
		if mode != "40000" && r.purge[name] {
			changed = true
			continue
		} else if mode == "40000" {
			updated, err = r.rewriteTree(commit, name, entry)
		} else if r.purge == nil && regularMode(mode) && r.history.protects(commit, name) {
			updated, err = r.rewriteBlob(commit, name, entry)
		}
		if err != nil {
			return "", err
		}
		changed = changed || updated != entry
		if updated == "" { // The rewritten subtree is empty.
			continue
		}
		raw, err := hex.DecodeString(updated)
		if err != nil {
			return "", err
		}
		rewritten.WriteString(mode + " " + entryName + "\x00")
		rewritten.Write(raw)
	}
	updated := oid
	if changed {
		if r.purge != nil && prefix != "" && rewritten.Len() == 0 {
			updated = ""
		} else if updated, err = r.write("tree", rewritten.Bytes()); err != nil {
			return "", err
		}
	}
	r.trees[key] = updated
	return updated, nil
}

// splitObject returns the header lines and the message of a commit or tag.
func splitObject(content []byte) ([]string, []byte) {
	header, message, found := bytes.Cut(content, []byte("\n\n"))
	if !found {
		header = bytes.TrimRight(header, "\n")
	}
	return strings.Split(string(header), "\n"), message
}

// withoutSignature drops gpgsig headers with their continuation lines, and
// reports whether there were any.
func withoutSignature(lines []string) ([]string, bool) {
	var kept []string
	signed, inSignature := false, false
	for _, line := range lines {
		if inSignature && strings.HasPrefix(line, " ") {
			continue
		}
		inSignature = strings.HasPrefix(line, "gpgsig ") || strings.HasPrefix(line, "gpgsig-sha256 ")
		signed = signed || inSignature
		if !inSignature {
			kept = append(kept, line)
		}
	}
	return kept, signed
}

func joinObject(lines []string, message []byte) []byte {
	return append([]byte(strings.Join(lines, "\n")+"\n\n"), message...)
}

// rewriteCommit rewrites commit after its parents. Unchanged commits keep their ID.
func (r *rewriter) rewriteCommit(commit string) error {
	content, err := r.history.reader.read(commit)
	if err != nil {
		return err
	}
	lines, message := splitObject(content)
	tree := strings.TrimPrefix(lines[0], "tree ")
	var parents, rest []string
	for _, line := range lines[1:] {
		if parent, ok := strings.CutPrefix(line, "parent "); ok {
			parents = append(parents, parent)
		} else {
			rest = append(rest, line)
		}
	}
	updatedTree, err := r.rewriteTree(commit, "", tree)
	if err != nil {
		return err
	}
	changed := updatedTree != tree
	header := []string{"tree " + updatedTree}
	for _, parent := range parents {
		if updated, ok := r.commits[parent]; ok {
			changed = changed || updated != parent
			parent = updated
		}
		header = append(header, "parent "+parent)
	}
	if !changed {
		r.commits[commit] = commit
		return nil
	}
	rest, signed := withoutSignature(rest)
	if signed {
		r.Signatures++
	}
	r.commits[commit], err = r.write("commit", joinObject(append(header, rest...), message))
	return err
}

// rewriteTag returns an annotated tag pointing to the rewritten object, without its signature.
func (r *rewriter) rewriteTag(tag string) (string, error) {
	if updated, ok := r.tags[tag]; ok {
		return updated, nil
	}
	content, err := r.history.reader.read(tag)
	if err != nil {
		return "", err
	}
	lines, message := splitObject(content)
	if len(lines) < 2 {
		return "", fmt.Errorf("invalid Git tag %s", tag)
	}
	target := strings.TrimPrefix(lines[0], "object ")
	updatedTarget := target
	switch strings.TrimPrefix(lines[1], "type ") {
	case "commit":
		if updated, ok := r.commits[target]; ok {
			updatedTarget = updated
		}
	case "tag":
		if updatedTarget, err = r.rewriteTag(target); err != nil {
			return "", err
		}
	}
	updated := tag
	if updatedTarget != target {
		rest, signed := withoutSignature(lines[1:])
		if location := tagSignature.FindIndex(message); location != nil {
			message = message[:location[0]]
			signed = true
		}
		if signed {
			r.Signatures++
		}
		if updated, err = r.write("tag", joinObject(append([]string{"object " + updatedTarget}, rest...), message)); err != nil {
			return "", err
		}
	}
	r.tags[tag] = updated
	return updated, nil
}

// rewritableRefs lists the local branches, tags and stash that point to
// commits, and HEAD when detached.
func rewritableRefs(root string) ([]rewriteRef, error) {
	output, err := git(root, "for-each-ref", "--format=%(refname)%00%(objectname)%00%(objecttype)")
	if err != nil {
		return nil, err
	}
	var candidates []rewriteRef
	var tags bytes.Buffer
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Split(line, "\x00")
		if len(fields) != 3 || !slices.ContainsFunc(rewrittenRefPrefixes, func(prefix string) bool { return strings.HasPrefix(fields[0], prefix) }) {
			continue
		}
		candidates = append(candidates, rewriteRef{fields[0], fields[1], fields[2]})
		if fields[2] == "tag" {
			tags.WriteString(fields[1] + "^{}\n")
		}
	}
	// Peeled here, since older Git peels only one level with %(*objecttype).
	var peeled []string
	if tags.Len() != 0 {
		output, err := gitWithInput(root, tags.Bytes(), "cat-file", "--batch-check=%(objecttype)")
		if err != nil {
			return nil, err
		}
		peeled = strings.Fields(string(output))
	}
	var refs []rewriteRef
	for _, ref := range candidates {
		kind := ref.kind
		if kind == "tag" {
			if len(peeled) == 0 {
				return nil, fmt.Errorf("cannot peel tag %s", ref.name)
			}
			kind, peeled = peeled[0], peeled[1:]
		}
		if kind == "commit" {
			refs = append(refs, ref)
		}
	}
	if _, err := git(root, "symbolic-ref", "-q", "HEAD"); err != nil {
		if head, err := git(root, "rev-parse", "--verify", "-q", "HEAD"); err == nil {
			refs = append(refs, rewriteRef{"HEAD", strings.TrimSpace(string(head)), "commit"})
		}
	}
	return refs, nil
}

// Apply moves every ref, backing up its old value under refs/git-age/original,
// all or none; then it checks out the new HEAD and unlocks again the files
// that were unlocked.
func (r *HistoryRewrite) Apply() error {
	head, _ := git(r.root, "rev-parse", "--verify", "-q", "HEAD")
	unlocked := map[string]bool{}
	if r.operation == "rekey" {
		files, err := ProtectedFiles(r.root, nil)
		if err != nil && !errors.Is(err, ErrNoRules) {
			return err
		}
		for _, file := range files {
			if file.State == Unlocked {
				unlocked[file.Path] = true
			}
		}
	}

	commands := []string{"start"}
	for _, move := range r.Moves {
		commands = append(commands, fmt.Sprintf("create %s/%s %s", originalRefs, move.Ref, move.Old))
		if move.Ref == "HEAD" {
			commands = append(commands, "option no-deref")
		}
		commands = append(commands, fmt.Sprintf("update %s %s %s", move.Ref, move.New, move.Old))
	}
	commands = append(commands, "prepare", "commit", "")
	if _, err := gitWithInput(r.root, []byte(strings.Join(commands, "\n")), "update-ref", "-m", "git-age history "+r.operation, "--stdin"); err != nil {
		return fmt.Errorf("cannot update the refs; none was changed: %w", err)
	}

	oldHead := strings.TrimSpace(string(head))
	newHead, _ := git(r.root, "rev-parse", "--verify", "-q", "HEAD")
	if oldHead == "" || strings.TrimSpace(string(newHead)) == oldHead {
		return nil
	}
	if _, err := gitWithInput(r.root, nil, "read-tree", "-m", "-u", oldHead, strings.TrimSpace(string(newHead))); err != nil {
		return fmt.Errorf("the refs moved, but cannot update the working tree; run `git reset --hard`: %w", err)
	}
	if len(unlocked) == 0 {
		return nil
	}
	files, err := ProtectedFiles(r.root, nil)
	if err != nil {
		return err
	}
	var relock []ProtectedFile
	for _, file := range files {
		if unlocked[file.Path] && file.State == Locked {
			relock = append(relock, file)
		}
	}
	if len(relock) == 0 {
		return nil
	}
	identities := make([]string, len(r.identities))
	for i, identity := range r.identities {
		identities[i] = absolutePath(r.directory, identity)
	}
	_, err = Unlock(r.root, relock, identities, false)
	return err
}
