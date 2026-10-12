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
func (k keys) rememberCiphertext(root string, target fileTarget, ciphertext []byte) error {
	directory, err := gitPath(root, "git-age/recipients")
	if err != nil {
		return err
	}
	if !*k.cachePruned {
		if err := pruneRecipientCache(root, directory, time.Now()); err != nil {
			return fmt.Errorf("prune ciphertext recipients: %w", err)
		}
		*k.cachePruned = true
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	record := k.recipientFingerprint(target)
	if k.toIdentities {
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
		if live[name] {
			continue
		}
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
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

func liveCiphertextHashes(root string) (map[string]bool, error) {
	output, err := git(root, "ls-files", "--stage", "-z")
	if err != nil {
		return nil, err
	}
	entries, err := stageEntries(output)
	if err != nil {
		return nil, err
	}
	oids := map[string]bool{}
	for _, entry := range entries {
		if regularMode(entry.mode) || entry.mode == "120000" {
			oids[entry.oid] = true // Includes stages 1, 2 and 3 during conflicts.
		}
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
		for _, record := range bytes.Split(output, []byte{0}) {
			header, _, _ := strings.Cut(string(record), "\t")
			fields := strings.Fields(header)
			if len(fields) == 3 && fields[1] == "blob" {
				oids[fields[2]] = true
			}
		}
	}
	reader, err := newObjectReader(root)
	if err != nil {
		return nil, err
	}
	defer reader.close()
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
