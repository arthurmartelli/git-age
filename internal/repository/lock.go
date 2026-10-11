package repository

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
)

type encryptionOptions struct {
	noReuse, rekey bool
	edit           func(string) error
}

func Lock(directory string, files []ProtectedFile, explicitRecipients, identityPaths []string, noReuse bool) ([]ProtectedFile, error) {
	_, noAccess, err := encryptFiles(directory, files, explicitRecipients, identityPaths, encryptionOptions{noReuse: noReuse})
	return noAccess, err
}

func Rekey(directory string, files []ProtectedFile, explicitRecipients, identityPaths []string) ([]ProtectedFile, error) {
	skipped, _, err := encryptFiles(directory, files, explicitRecipients, identityPaths, encryptionOptions{noReuse: true, rekey: true})
	return skipped, err
}

func encryptFiles(directory string, files []ProtectedFile, explicitRecipients, identityPaths []string, options encryptionOptions) (skipped, noAccess []ProtectedFile, err error) {
	if err := CheckKnown(files); err != nil {
		return nil, nil, err
	}
	var pending []ProtectedFile
	for _, file := range files {
		if options.rekey || options.edit != nil || file.State != Locked {
			pending = append(pending, file)
		}
	}
	if len(pending) == 0 {
		return nil, nil, nil
	}
	directory, root, inGit, err := resolveDirectory(directory)
	if err != nil {
		return nil, nil, err
	}
	if inGit {
		if err := checkRecipientTrust(directory); err != nil {
			return nil, nil, err
		}
	}
	keys, err := loadKeys(directory, root, explicitRecipients, identityPaths, nil)
	if err != nil {
		return nil, nil, err
	}

	var replacements []replacement
	for _, file := range pending {
		path := nativePath(directory, file.Path)
		target, err := keys.target(root, path, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", file.Path, err)
		}
		original, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		plaintext := original
		if (options.rekey || options.edit != nil) && file.State == Locked {
			plaintext, err = decryptContent(original, keys.identities)
			if errors.Is(err, errNoIdentity) {
				return nil, nil, err
			}
			if err != nil {
				var noMatch *age.NoIdentityMatchError
				if options.rekey && errors.As(err, &noMatch) && !containsRecipient(target.values, keys.own) {
					// A team member may only have access to part of the repository.
					skipped = append(skipped, file)
					continue
				}
				return nil, nil, fmt.Errorf("cannot decrypt %s: %w", file.Path, err)
			}
		}
		if options.edit != nil {
			before := plaintext
			plaintext, err = editPlaintext(file.Path, plaintext, options.edit)
			if err != nil {
				return nil, nil, fmt.Errorf("%w; %s was not changed", err, file.Path)
			}
			if bytes.Equal(before, plaintext) {
				continue
			}
		}
		encrypted, err := keys.encrypt(root, path, target, plaintext, inGit && !options.noReuse)
		if err != nil {
			return nil, nil, err
		}
		replacements = append(replacements, replacement{path, original, encrypted})
		if len(keys.own) != 0 && !containsRecipient(target.values, keys.own) {
			noAccess = append(noAccess, file)
		}
	}
	if len(replacements) == 0 && len(skipped) != 0 {
		return nil, nil, fmt.Errorf("cannot decrypt %s: no files encrypted to your identities", skipped[0].Path)
	}
	return skipped, noAccess, replaceFiles(replacements)
}

func checkRecipientTrust(directory string) error {
	trusted, err := configValues(directory, "age.trustedRecipients")
	if err != nil {
		return err
	}
	if len(trusted) != 0 {
		return fmt.Errorf("recipient trust verification is not implemented; refusing to encrypt with age.trustedRecipients configured")
	}
	return nil
}

// keys holds the identities and base recipients for encrypting files.
type keys struct {
	identities []age.Identity
	own        []string // Recipients of the identities.
	base       []string
	external   bool // Base recipients come from outside the .gitage rules.
}

// loadKeys reads the base recipients from rules, or from the .gitage files on
// disk when rules is nil.
func loadKeys(directory, root string, explicitRecipients, identityPaths []string, rules map[string][]byte) (keys, error) {
	var k keys
	var err error
	k.identities, k.own, err = loadIdentities(directory, root, identityPaths)
	if err != nil {
		return k, err
	}
	k.base = explicitRecipients
	if len(k.base) == 0 && os.Getenv("GIT_AGE_RECIPIENT") != "" {
		k.base = []string{os.Getenv("GIT_AGE_RECIPIENT")}
	}
	k.external = len(k.base) != 0
	if len(k.base) == 0 {
		k.base, err = ruleRecipients(filepath.Join(root, ".gitage"), rules)
		if err != nil {
			return k, err
		}
	}
	if len(k.base) == 0 {
		k.base, err = configValues(directory, "age.recipient")
		if err != nil {
			return k, err
		}
		k.external = len(k.base) != 0
	}
	if len(k.base) == 0 {
		k.base = k.own
	}
	if len(k.base) == 0 {
		return k, fmt.Errorf("no encryption key configured; use -r, [recipients], or an age identity")
	}
	return k, nil
}

// fileTarget describes the recipients of one protected file.
type fileTarget struct {
	values     []string
	rules      []string // Rule files that apply to the file.
	recipients []age.Recipient
}

func (k keys) target(root, path string, ruleContents map[string][]byte) (fileTarget, error) {
	target := fileTarget{values: append([]string(nil), k.base...)}
	for _, parent := range ancestorDirs(root, filepath.Dir(path)) {
		rule := filepath.Join(parent, ".gitage")
		target.rules = append(target.rules, rule)
		if parent != root {
			extra, err := ruleRecipients(rule, ruleContents)
			if err != nil {
				return target, err
			}
			target.values = append(target.values, extra...)
		}
	}
	var err error
	target.recipients, err = parseRecipients(target.values)
	return target, err
}

// encrypt reuses unchanged ciphertext from Git when reuse is allowed.
func (k keys) encrypt(root, path string, target fileTarget, plaintext []byte, reuse bool) ([]byte, error) {
	if reuse && !k.external {
		if ciphertext := reusableCiphertext(root, path, target.rules, plaintext, k.identities); ciphertext != nil {
			return ciphertext, nil
		}
	}
	return encryptContent(plaintext, target.recipients)
}

// ruleRecipients reads a rule file from rules, or from disk when rules is nil.
func ruleRecipients(path string, rules map[string][]byte) ([]string, error) {
	content := rules[path]
	if rules == nil {
		var err error
		if content, err = readRuleFile(path); err != nil {
			return nil, err
		}
	}
	_, recipients, err := parseRules(path, content)
	return recipients, err
}

func encryptContent(plaintext []byte, recipients []age.Recipient) ([]byte, error) {
	var output bytes.Buffer
	writer, err := age.Encrypt(&output, recipients...)
	if err != nil {
		return nil, err
	}
	_, writeErr := writer.Write(plaintext)
	if err := errors.Join(writeErr, writer.Close()); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func containsRecipient(values, own []string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, "ssh-") {
			// SSH key comments do not affect recipient identity.
			value = strings.Join(strings.Fields(value)[:2], " ")
		}
		for _, recipient := range own {
			if value == recipient {
				return true
			}
		}
	}
	return false
}

func parseRecipients(values []string) ([]age.Recipient, error) {
	var recipients []age.Recipient
	seen := map[string]bool{}
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		var recipient age.Recipient
		var err error
		if strings.HasPrefix(value, "ssh-") {
			recipient, err = agessh.ParseRecipient(value)
		} else {
			recipient, err = age.ParseX25519Recipient(value)
		}
		if err != nil {
			return nil, fmt.Errorf("invalid recipient %q: %w", value, err)
		}
		recipients = append(recipients, recipient)
	}
	return recipients, nil
}

func reusableCiphertext(root, path string, rules []string, plaintext []byte, identities []age.Identity) []byte {
	if len(identities) == 0 {
		// Reuse needs decryption; avoid spawning Git when no identity can decrypt.
		return nil
	}
	relative, _ := filepath.Rel(root, path)
	// Even staged ciphertext may still use old recipients after a rules edit.
	if !rulesMatchRevision(root, rules, "HEAD") {
		return nil
	}
	var stale [][]byte
	for _, rule := range rules {
		current, err := os.ReadFile(rule)
		if err != nil {
			continue // Absent both here and in HEAD.
		}
		_, currentRecipients, err := parseRules(rule, current)
		if err != nil {
			return nil
		}
		rulePath, _ := filepath.Rel(root, rule)
		history, err := git(root, "log", "--format=%H", "--", filepath.ToSlash(rulePath))
		if err != nil {
			return nil
		}
		for _, revision := range strings.Fields(string(history)) {
			old, err := git(root, "show", revision+":"+filepath.ToSlash(rulePath))
			if err != nil {
				return nil
			}
			_, oldRecipients, err := parseRules(rule, old)
			if err != nil {
				return nil
			}
			if sameRecipients(currentRecipients, oldRecipients) {
				continue
			}
			if ciphertext, err := git(root, "show", revision+":"+filepath.ToSlash(relative)); err == nil {
				stale = append(stale, ciphertext)
			}
			break
		}
	}
	for _, revision := range []string{"", ":2", ":3", "HEAD"} {
		// Conflict sides use the same staged rules as a stage-zero candidate.
		ruleRevision := revision
		if strings.HasPrefix(revision, ":") {
			ruleRevision = ""
		}
		if !rulesMatchRevision(root, rules, ruleRevision) {
			continue
		}
		ciphertext, err := git(root, "show", revision+":"+filepath.ToSlash(relative))
		if err != nil || slices.ContainsFunc(stale, func(old []byte) bool { return bytes.Equal(old, ciphertext) }) {
			continue
		}
		decrypted, err := decryptContent(ciphertext, identities)
		if err == nil && bytes.Equal(decrypted, plaintext) {
			return ciphertext
		}
	}
	return nil
}

// rulesMatchRevision reports whether each working rule file equals its
// version at revision, counting a file absent from both as equal.
func rulesMatchRevision(root string, rules []string, revision string) bool {
	for _, rule := range rules {
		rulePath, _ := filepath.Rel(root, rule)
		current, readErr := os.ReadFile(rule)
		previous, gitErr := git(root, "show", revision+":"+filepath.ToSlash(rulePath))
		if errors.Is(readErr, os.ErrNotExist) && gitErr != nil {
			continue
		}
		if readErr != nil || gitErr != nil || !bytes.Equal(current, previous) {
			return false
		}
	}
	return true
}

// sameRecipients compares recipient lists as sets.
func sameRecipients(first, second []string) bool {
	first, second = slices.Clone(first), slices.Clone(second)
	slices.Sort(first)
	slices.Sort(second)
	return slices.Equal(slices.Compact(first), slices.Compact(second))
}
