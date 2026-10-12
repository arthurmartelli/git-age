package repository

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"filippo.io/age/plugin"
)

const recipientCacheGrace = 30 * 24 * time.Hour

func ciphertextHash(ciphertext []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(ciphertext))
}

// recipientFingerprint records the effective set, without writing keys or
// plaintext. Plugin identity-based recipients have no public string encoding.
func (k keys) recipientFingerprint(target fileTarget) string {
	values := slices.Clone(target.values)
	if k.toIdentities {
		for _, identity := range k.identities {
			if identity, ok := identity.(*plugin.Identity); ok {
				values = append(values, "plugin-identity:"+fmt.Sprintf("%x", sha256.Sum256([]byte(identity.String()))))
			}
		}
	}
	return recipientSetFingerprint(values)
}

func (k keys) matchesRecipientRecord(target fileTarget, recorded []byte) bool {
	exact, fallback, _ := strings.Cut(string(recorded), "\n")
	return exact == k.recipientFingerprint(target) || k.toIdentities && fallback != "" && fallback == recipientSetFingerprint(target.listed)
}

func recipientSetFingerprint(values []string) string {
	values = slices.Clone(values)
	for i, value := range values {
		if fields := strings.Fields(value); strings.HasPrefix(value, "ssh-") && len(fields) >= 2 {
			values[i] = strings.Join(fields[:2], " ")
		}
	}
	slices.Sort(values)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(slices.Compact(values), "\n"))))
}

// rememberCiphertext lets later lock and clean operations verify that a blob
// uses the current recipients, even when their source isn't tracked in Git.
func (k keys) rememberCiphertext(root string, target fileTarget, ciphertext []byte, legacy bool) error {
	directory, err := k.recipientCacheDirectory(root)
	if err != nil {
		return err
	}
	if !k.cache.pruned {
		if err := pruneRecipientCache(root, directory, time.Now()); err != nil {
			return fmt.Errorf("prune ciphertext recipients: %w", err)
		}
		k.cache.pruned = true
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	record := k.recipientFingerprint(target)
	if k.toIdentities {
		if legacy {
			// History proves the listed recipients, not the original implicit
			// owner's identity. Do not certify an exact set we cannot know.
			record = ""
		}
		// With identity fallback, the original encryptor is an implicit
		// recipient. Another listed team member needn't replace that owner.
		record += "\n" + recipientSetFingerprint(target.listed)
	}
	if err := os.WriteFile(filepath.Join(directory, ciphertextHash(ciphertext)), []byte(record), 0600); err != nil {
		return fmt.Errorf("record ciphertext recipients: %w", err)
	}
	return nil
}

// Prune only expired, unreachable records. The grace period preserves recent
// ciphertext on other branches or in the stash without walking all history.
func pruneRecipientCache(root, directory string, now time.Time) error {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	cutoff := now.Add(-recipientCacheGrace)
	var expired []string
	for _, entry := range entries {
		name := entry.Name()
		if len(name) != sha256.Size*2 || strings.Trim(name, "0123456789abcdef") != "" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() && info.ModTime().Before(cutoff) {
			expired = append(expired, name)
		}
	}
	if len(expired) == 0 {
		return nil
	}
	live, err := liveCiphertextHashes(root)
	if err != nil {
		return err // Don't remove anything if the retention set couldn't be read.
	}
	for _, name := range expired {
		path := filepath.Join(directory, name)
		// Another process may have refreshed or removed the record meanwhile.
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() && info.ModTime().Before(cutoff) {
			if live[name] {
				// Don't rescan the repository on every encryption for a live
				// record that has already outlasted the grace period.
				err = os.Chtimes(path, now, now)
			} else {
				err = os.Remove(path)
			}
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

func liveCiphertextHashes(root string) (map[string]bool, error) {
	reader, err := newObjectReader(root)
	if err != nil {
		return nil, err
	}
	defer reader.close()
	output, err := git(root, "ls-files", "--stage", "-z")
	if err != nil {
		return nil, err
	}
	entries, err := stageEntries(output)
	if err != nil {
		return nil, err
	}
	oids := map[string]bool{}
	if err := collectProtectedBlobOIDs(root, entries, reader, oids); err != nil {
		return nil, err
	}
	head, err := git(root, "rev-parse", "--verify", "--quiet", "HEAD^{tree}")
	if err != nil && !exitCode(err, 1) {
		return nil, err
	}
	if err == nil {
		output, err := git(root, "ls-tree", "-r", "-z", strings.TrimSpace(string(head)))
		if err != nil {
			return nil, err
		}
		var entries []stageEntry
		for _, record := range bytes.Split(output, []byte{0}) {
			header, path, ok := strings.Cut(string(record), "\t")
			fields := strings.Fields(header)
			if !ok || len(fields) != 3 || fields[1] != "blob" {
				continue
			}
			entries = append(entries, stageEntry{fields[0], fields[2], "0", path})
		}
		if err := collectProtectedBlobOIDs(root, entries, reader, oids); err != nil {
			return nil, err
		}
	}
	live := map[string]bool{}
	for oid := range oids {
		content, err := reader.read(oid)
		if err != nil {
			return nil, err
		}
		if contentState(content) == Locked {
			live[ciphertextHash(content)] = true
		}
	}
	files, err := ProtectedFiles(root, nil)
	if err != nil && !errors.Is(err, ErrNoRules) {
		return nil, err
	}
	for _, file := range files {
		content, err := os.ReadFile(nativePath(root, file.Path))
		if err != nil {
			return nil, err
		}
		if contentState(content) == Locked {
			live[ciphertextHash(content)] = true
		}
	}
	return live, nil
}

// Read only rule blobs and protected file blobs from each snapshot. When rules
// conflict, retain all stages of any path protected by any rule version.
func collectProtectedBlobOIDs(root string, entries []stageEntry, reader *objectReader, oids map[string]bool) error {
	blobs := map[string][]string{}
	rulesByStage := map[string]map[string][]byte{"0": {}}
	var candidates []string
	for _, entry := range entries {
		if !regularMode(entry.mode) && entry.mode != "120000" {
			continue
		}
		path := nativePath(root, entry.path)
		if _, exists := blobs[entry.path]; !exists {
			candidates = append(candidates, path)
		}
		blobs[entry.path] = append(blobs[entry.path], entry.oid)
		if filepath.Base(entry.path) != ".gitage" || !regularMode(entry.mode) {
			continue
		}
		content, err := reader.read(entry.oid)
		if err != nil {
			return err
		}
		if rulesByStage[entry.stage] == nil {
			rulesByStage[entry.stage] = map[string][]byte{}
		}
		rulesByStage[entry.stage][path] = content
	}
	ignoreCase := ruleIgnoreCase(root, true)
	for _, rules := range rulesByStage {
		// Unconflicted rules apply to every conflict stage.
		for path, content := range rulesByStage["0"] {
			rules[path] = content
		}
		if len(rules) == 0 {
			continue
		}
		files, err := matchProtectedFiles(root, root, candidates, rules, ignoreCase)
		if err != nil {
			return err
		}
		for _, file := range files {
			for _, oid := range blobs[file.Path] {
				oids[oid] = true
			}
		}
	}
	return nil
}
