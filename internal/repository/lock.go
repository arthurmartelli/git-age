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
	"golang.org/x/crypto/ssh"
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

	type replacement struct {
		path                string
		original, encrypted []byte
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
	// Detect edits made while encryption was being prepared before changing any file.
	for _, change := range replacements {
		info, err := os.Lstat(change.path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s: no longer a regular file", change.path)
		}
		content, err := os.ReadFile(change.path)
		if err != nil {
			return err
		}
		if !bytes.Equal(content, change.original) {
			return fmt.Errorf("%s: changed while preparing encryption", change.path)
		}
	}
	for i, change := range replacements {
		if err := writeExisting(change.path, change.encrypted); err != nil {
			for _, previous := range replacements[:i+1] {
				if restoreErr := writeExisting(previous.path, previous.original); restoreErr != nil {
					err = errors.Join(err, fmt.Errorf("restore %s: %w", previous.path, restoreErr))
				}
			}
			return err
		}
	}
	return nil
}

func writeExisting(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(content)
	if writeErr == nil {
		writeErr = file.Truncate(int64(len(content)))
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	return errors.Join(writeErr, file.Close())
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

func configValues(directory, key string) ([]string, error) {
	output, err := exec.Command("git", "-C", directory, "config", "--null", "--get-all", key).Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var values []string
	for _, value := range strings.Split(strings.TrimSuffix(string(output), "\x00"), "\x00") {
		if value == "" {
			values = nil
		} else {
			values = append(values, value)
		}
	}
	return values, nil
}

func loadIdentities(directory, root string, paths []string) ([]age.Identity, []string, error) {
	if len(paths) == 0 {
		paths = filepath.SplitList(os.Getenv("GIT_AGE_KEY_FILE"))
	}
	if len(paths) == 0 {
		var err error
		paths, err = configValues(directory, "age.keyFile")
		if err != nil {
			return nil, nil, err
		}
	}
	if len(paths) == 0 {
		path := filepath.Join(root, ".gitage.key")
		if _, err := os.Stat(path); err == nil {
			paths = []string{path}
		}
	}
	var identities []age.Identity
	var recipients []string
	for _, path := range paths {
		if !filepath.IsAbs(path) {
			path = filepath.Join(directory, path)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		var parsed []age.Identity
		if bytes.HasPrefix(content, []byte("-----BEGIN")) {
			identity, err := agessh.ParseIdentity(content)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", path, err)
			}
			parsed = []age.Identity{identity}
			signer, err := ssh.ParsePrivateKey(content)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", path, err)
			}
			recipients = append(recipients, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))))
		} else {
			parsed, err = age.ParseIdentities(bytes.NewReader(content))
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", path, err)
			}
		}
		for _, identity := range parsed {
			switch identity := identity.(type) {
			case *age.X25519Identity:
				recipients = append(recipients, identity.Recipient().String())
			}
		}
		identities = append(identities, parsed...)
	}
	return identities, recipients, nil
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
