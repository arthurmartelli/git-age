package repository

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
)

// Lock prepares every replacement before writing, and restores originals on write failure.
// Writing through existing files preserves their permissions, ACLs and extended attributes.
func Lock(directory string, files []ProtectedFile, explicitRecipients, identityPaths []string, noReuse bool) error {
	var pending []ProtectedFile
	for _, file := range files {
		if file.State == "UNKNOWN" {
			return fmt.Errorf("cannot determine file state: %s", file.Path)
		}
		if file.State != "LOCKED" {
			pending = append(pending, file)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	directory, err := filepath.Abs(directory)
	if err != nil {
		return err
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		return err
	}
	root, err := gitRoot(directory)
	if err != nil {
		return err
	}
	inGit := root != ""
	if !inGit {
		root = directory
	}
	if inGit {
		trusted, err := configValues(directory, "age.trustedRecipients")
		if err != nil {
			return err
		}
		if len(trusted) != 0 {
			return fmt.Errorf("recipient trust verification is not implemented; refusing to lock with age.trustedRecipients configured")
		}
	}
	identities, own, err := loadIdentities(directory, root, identityPaths)
	if err != nil {
		return err
	}
	base := explicitRecipients
	if len(base) == 0 && os.Getenv("GIT_AGE_RECIPIENT") != "" {
		base = []string{os.Getenv("GIT_AGE_RECIPIENT")}
	}
	external := len(base) != 0
	if len(base) == 0 {
		base, err = ruleRecipients(filepath.Join(root, ".gitage"))
		if err != nil {
			return err
		}
	}
	if len(base) == 0 {
		base, err = configValues(directory, "age.recipient")
		if err != nil {
			return err
		}
		external = len(base) != 0
	}
	if len(base) == 0 {
		base = own
	}
	if len(base) == 0 {
		return fmt.Errorf("no recipients configured; use -r, [recipients], or an age identity")
	}

	var replacements []replacement
	for _, file := range pending {
		path := filepath.Join(directory, filepath.FromSlash(file.Path))
		values := append([]string(nil), base...)
		var ruleFiles []string
		for parent := filepath.Dir(path); inside(root, parent); parent = filepath.Dir(parent) {
			rule := filepath.Join(parent, ".gitage")
			ruleFiles = append(ruleFiles, rule)
			if parent != root {
				extra, err := ruleRecipients(rule)
				if err != nil {
					return err
				}
				values = append(values, extra...)
			}
			if parent == root {
				break
			}
		}
		recipients, err := parseRecipients(values)
		if err != nil {
			return fmt.Errorf("%s: %w", file.Path, err)
		}
		original, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var encrypted []byte
		if inGit && !noReuse && !external {
			encrypted = reusableCiphertext(root, path, ruleFiles, original, identities)
		}
		if encrypted == nil {
			var output bytes.Buffer
			writer, err := age.Encrypt(&output, recipients...)
			if err != nil {
				return err
			}
			_, writeErr := writer.Write(original)
			if err := errors.Join(writeErr, writer.Close()); err != nil {
				return err
			}
			encrypted = output.Bytes()
		}
		replacements = append(replacements, replacement{path, original, encrypted})
	}
	return replaceFiles(replacements)
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
	// A staged rules edit can still sit beside ciphertext encrypted to the old list.
	// Require rules to agree with HEAD before considering either source.
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
	for _, revision := range []string{"", "HEAD"} {
		unchanged := true
		for _, rule := range rules {
			rulePath, _ := filepath.Rel(root, rule)
			current, readErr := os.ReadFile(rule)
			previous, gitErr := exec.Command("git", "-C", root, "show", revision+":"+filepath.ToSlash(rulePath)).Output()
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
		reader, err := age.Decrypt(bytes.NewReader(ciphertext), identities...)
		if err != nil {
			continue
		}
		decrypted, err := io.ReadAll(reader)
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
