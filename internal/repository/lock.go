package repository

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
)

type encryptionResult struct {
	skipped, noAccess []ProtectedFile
}

func Lock(directory string, files []ProtectedFile, explicitRecipients, identityPaths []string, noReuse bool) ([]ProtectedFile, error) {
	result, err := encryptFiles(directory, files, explicitRecipients, identityPaths, noReuse, false, nil)
	return result.noAccess, err
}

func Rekey(directory string, files []ProtectedFile, explicitRecipients, identityPaths []string) ([]ProtectedFile, error) {
	result, err := encryptFiles(directory, files, explicitRecipients, identityPaths, true, true, nil)
	return result.skipped, err
}

func encryptFiles(directory string, files []ProtectedFile, explicitRecipients, identityPaths []string, noReuse, rekey bool, edit func(string) error) (encryptionResult, error) {
	var pending []ProtectedFile
	for _, file := range files {
		if file.State == "UNKNOWN" {
			return encryptionResult{}, fmt.Errorf("cannot determine file state: %s", file.Path)
		}
		if rekey || edit != nil || file.State != "LOCKED" {
			pending = append(pending, file)
		}
	}
	if len(pending) == 0 {
		return encryptionResult{}, nil
	}
	directory, err := filepath.Abs(directory)
	if err != nil {
		return encryptionResult{}, err
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		return encryptionResult{}, err
	}
	root, err := gitRoot(directory)
	if err != nil {
		return encryptionResult{}, err
	}
	inGit := root != ""
	if !inGit {
		root = directory
	}
	if inGit {
		if err := checkRecipientTrust(directory); err != nil {
			return encryptionResult{}, err
		}
	}
	identities, own, base, external, err := encryptionKeys(directory, root, explicitRecipients, identityPaths)
	if err != nil {
		return encryptionResult{}, err
	}

	var replacements []replacement
	var skipped, noAccess []ProtectedFile
	for _, file := range pending {
		path := filepath.Join(directory, filepath.FromSlash(file.Path))
		values, ruleFiles, err := fileRecipients(root, path, base)
		if err != nil {
			return encryptionResult{}, err
		}
		recipients, err := parseRecipients(values)
		if err != nil {
			return encryptionResult{}, fmt.Errorf("%s: %w", file.Path, err)
		}
		original, err := os.ReadFile(path)
		if err != nil {
			return encryptionResult{}, err
		}
		plaintext := original
		if (rekey || edit != nil) && file.State == "LOCKED" {
			if len(identities) == 0 {
				return encryptionResult{}, fmt.Errorf("no identity configured; use -i or generate a key with git-age keygen")
			}
			plaintext, err = decryptContent(original, identities)
			if err != nil {
				var noMatch *age.NoIdentityMatchError
				if rekey && errors.As(err, &noMatch) && !containsRecipient(values, own) {
					// A team member may only have access to part of the repository.
					skipped = append(skipped, file)
					continue
				}
				return encryptionResult{}, fmt.Errorf("cannot decrypt %s: %w", file.Path, err)
			}
		}
		if edit != nil {
			before := plaintext
			plaintext, err = editPlaintext(file.Path, plaintext, edit)
			if err != nil {
				return encryptionResult{}, fmt.Errorf("%w; %s was not changed", err, file.Path)
			}
			if bytes.Equal(before, plaintext) {
				continue
			}
		}
		var encrypted []byte
		if inGit && !noReuse && !external {
			encrypted = reusableCiphertext(root, path, ruleFiles, plaintext, identities)
		}
		if encrypted == nil {
			encrypted, err = encryptContent(plaintext, recipients)
			if err != nil {
				return encryptionResult{}, err
			}
		}
		replacements = append(replacements, replacement{path, original, encrypted})
		if len(own) != 0 && !containsRecipient(values, own) {
			noAccess = append(noAccess, file)
		}
	}
	if len(replacements) == 0 && len(skipped) != 0 {
		return encryptionResult{}, fmt.Errorf("cannot decrypt %s: no files encrypted to your identities", skipped[0].Path)
	}
	return encryptionResult{skipped, noAccess}, replaceFiles(replacements)
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

func encryptionKeys(directory, root string, explicitRecipients, identityPaths []string) (identities []age.Identity, own, base []string, external bool, err error) {
	return encryptionKeysFromRules(directory, root, explicitRecipients, identityPaths, nil)
}

func encryptionKeysFromRules(directory, root string, explicitRecipients, identityPaths []string, rules map[string][]byte) (identities []age.Identity, own, base []string, external bool, err error) {
	identities, own, err = loadIdentities(directory, root, identityPaths)
	if err != nil {
		return
	}
	base = explicitRecipients
	if len(base) == 0 && os.Getenv("GIT_AGE_RECIPIENT") != "" {
		base = []string{os.Getenv("GIT_AGE_RECIPIENT")}
	}
	external = len(base) != 0
	if len(base) == 0 {
		base, err = recipientsFromRules(filepath.Join(root, ".gitage"), rules)
		if err != nil {
			return
		}
	}
	if len(base) == 0 {
		base, err = configValues(directory, "age.recipient")
		if err != nil {
			return
		}
		external = len(base) != 0
	}
	if len(base) == 0 {
		base = own
	}
	if len(base) == 0 {
		err = fmt.Errorf("no encryption key configured; use -r, [recipients], or an age identity")
	}
	return
}

func fileRecipients(root, path string, base []string) ([]string, []string, error) {
	return fileRecipientsFromRules(root, path, base, nil)
}

func fileRecipientsFromRules(root, path string, base []string, ruleContents map[string][]byte) ([]string, []string, error) {
	values := append([]string(nil), base...)
	var rules []string
	for parent := filepath.Dir(path); inside(root, parent); parent = filepath.Dir(parent) {
		rule := filepath.Join(parent, ".gitage")
		rules = append(rules, rule)
		if parent != root {
			extra, err := recipientsFromRules(rule, ruleContents)
			if err != nil {
				return nil, nil, err
			}
			values = append(values, extra...)
		}
		if parent == root {
			break
		}
	}
	return values, rules, nil
}

func recipientsFromRules(path string, rules map[string][]byte) ([]string, error) {
	if rules == nil {
		return ruleRecipients(path)
	}
	_, recipients, err := parseRules(path, rules[path])
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

func ruleRecipients(path string) ([]string, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	_, recipients, err := parseRules(path, content)
	return recipients, err
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
		return nil
	}
	relative, _ := filepath.Rel(root, path)
	var stale [][]byte
	// Even staged ciphertext may still use old recipients after a rules edit.
	for _, rule := range rules {
		rulePath, _ := filepath.Rel(root, rule)
		current, readErr := os.ReadFile(rule)
		previous, gitErr := exec.Command("git", "-C", root, "show", "HEAD:"+filepath.ToSlash(rulePath)).Output()
		if errors.Is(readErr, os.ErrNotExist) && gitErr != nil {
			continue
		}
		if readErr != nil || gitErr != nil || !bytes.Equal(current, previous) {
			return nil
		}
		_, currentRecipients, err := parseRules(rule, current)
		if err != nil {
			return nil
		}
		history, err := exec.Command("git", "-C", root, "log", "--format=%H", "--", filepath.ToSlash(rulePath)).Output()
		if err != nil {
			return nil
		}
		for _, revision := range strings.Fields(string(history)) {
			old, err := exec.Command("git", "-C", root, "show", revision+":"+filepath.ToSlash(rulePath)).Output()
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
			if ciphertext, err := exec.Command("git", "-C", root, "show", revision+":"+filepath.ToSlash(relative)).Output(); err == nil {
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
		unchanged := true
		for _, rule := range rules {
			rulePath, _ := filepath.Rel(root, rule)
			current, readErr := os.ReadFile(rule)
			previous, gitErr := exec.Command("git", "-C", root, "show", ruleRevision+":"+filepath.ToSlash(rulePath)).Output()
			if errors.Is(readErr, os.ErrNotExist) && gitErr != nil {
				continue
			}
			if readErr != nil || gitErr != nil || !bytes.Equal(current, previous) {
				unchanged = false
				break
			}
		}
		if !unchanged {
			continue
		}
		ciphertext, err := exec.Command("git", "-C", root, "show", revision+":"+filepath.ToSlash(relative)).Output()
		if err != nil {
			continue
		}
		isStale := false
		for _, old := range stale {
			if bytes.Equal(old, ciphertext) {
				isStale = true
				break
			}
		}
		if isStale {
			continue
		}
		decrypted, err := decryptContent(ciphertext, identities)
		if err == nil && bytes.Equal(decrypted, plaintext) {
			return ciphertext
		}
	}
	return nil
}

func sameRecipients(first, second []string) bool {
	values := map[string]bool{}
	for _, value := range first {
		values[value] = true
	}
	for _, value := range second {
		if !values[value] {
			return false
		}
		delete(values, value)
	}
	return len(values) == 0
}
