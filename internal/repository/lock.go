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
	"filippo.io/age/plugin"
	"filippo.io/age/tag"
)

type encryptionOptions struct {
	noReuse, rekey, dryRun bool
	edit                   func(string) error
}

func Lock(directory string, files []ProtectedFile, explicitRecipients, identityPaths []string, noReuse, dryRun bool) ([]ProtectedFile, error) {
	_, noAccess, err := encryptFiles(directory, files, explicitRecipients, identityPaths, encryptionOptions{noReuse: noReuse, dryRun: dryRun})
	return noAccess, err
}

func Rekey(directory string, files []ProtectedFile, explicitRecipients, identityPaths []string, dryRun bool) ([]ProtectedFile, error) {
	skipped, _, err := encryptFiles(directory, files, explicitRecipients, identityPaths, encryptionOptions{noReuse: true, rekey: true, dryRun: dryRun})
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
		if err := checkRecipientTrust(root, nil); err != nil {
			return nil, nil, err
		}
	}
	keys, err := loadKeys(directory, root, explicitRecipients, identityPaths, nil)
	if err != nil {
		return nil, nil, err
	}
	defer keys.cache.objects.close()

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
				if options.rekey && errors.As(err, &noMatch) {
					// A team member may only have access to part of the repository.
					if mine, checkErr := keys.encryptedToUser(target); checkErr != nil {
						return nil, nil, checkErr
					} else if !mine {
						skipped = append(skipped, file)
						continue
					}
				}
				return nil, nil, fmt.Errorf("cannot decrypt %s: %w", file.Path, err)
			}
		}
		if options.edit != nil && !options.dryRun {
			before := plaintext
			plaintext, err = editPlaintext(root, path, plaintext, options.edit)
			if err != nil {
				return nil, nil, fmt.Errorf("%w; %s was not changed", err, file.Path)
			}
			if bytes.Equal(before, plaintext) {
				continue
			}
		}
		encrypted, err := keys.encrypt(root, path, target, plaintext, inGit && !options.noReuse, inGit && !options.dryRun)
		if err != nil {
			return nil, nil, err
		}
		replacements = append(replacements, replacement{path, original, encrypted})
		if !keys.toIdentities && (len(keys.own) != 0 || keys.plugins) {
			mine := containsRecipient(target.values, keys.own)
			if !mine && keys.plugins {
				mine, err = keys.canDecrypt(encrypted)
				if err != nil {
					return nil, nil, err
				}
			}
			if !mine {
				noAccess = append(noAccess, file)
			}
		}
	}
	if len(replacements) == 0 && len(skipped) != 0 {
		return nil, nil, fmt.Errorf("cannot decrypt %s: no files encrypted to your identities", skipped[0].Path)
	}
	if options.dryRun {
		return skipped, noAccess, nil
	}
	return skipped, noAccess, replaceFiles(replacements)
}

// keys holds the identities and base recipients for encrypting files.
type keys struct {
	identitySet
	base     []string
	external bool // Base recipients come from outside the .gitage rules.
	// Without a base list, files are encrypted to the identities of whoever
	// locks them, and base holds the user's own recipients.
	toIdentities bool
	source       string // Where base comes from, for messages.
	root         string
	rules        map[string][]byte
	listed       *[]string // Every [recipients] entry in the repository, once read.
	cache        *encryptionCache
}

type recipientBaseline struct {
	revision string
	ok       bool
}

type encryptionCache struct {
	objects       *gitObjects
	directory     string
	directoryErr  error
	directoryRead bool
	pruned        bool
	matches       map[string]bool
	baselines     map[string]recipientBaseline
}

func (k keys) recipientCacheDirectory(root string) (string, error) {
	if !k.cache.directoryRead {
		k.cache.directory, k.cache.directoryErr = gitPath(root, "git-age/recipients")
		k.cache.directoryRead = true
	}
	return k.cache.directory, k.cache.directoryErr
}

var errNoKey = errors.New("no encryption key configured; use -r, [recipients], or an age identity")

// loadKeys reads the base recipients from rules, or from the .gitage files on
// disk when rules is nil.
func loadKeys(directory, root string, explicitRecipients, identityPaths []string, rules map[string][]byte) (keys, error) {
	identities, err := loadIdentities(directory, root, identityPaths)
	if err != nil {
		return keys{}, err
	}
	k, err := resolveKeys(directory, root, explicitRecipients, identities, rules)
	if err == nil && len(k.base) == 0 && (!k.toIdentities || len(k.identitySet.recipients) == 0) {
		err = errNoKey
	}
	return k, err
}

// resolveKeys finds the base recipients; the first source that is set wins.
func resolveKeys(directory, root string, explicitRecipients []string, identities identitySet, rules map[string][]byte) (keys, error) {
	k := keys{identitySet: identities, root: root, rules: rules, listed: new([]string), cache: &encryptionCache{
		objects: newGitObjects(root), matches: map[string]bool{}, baselines: map[string]recipientBaseline{},
	}}
	top := filepath.Join(root, ".gitage")
	var err error
	switch environment := os.Getenv("GIT_AGE_RECIPIENT"); {
	case len(explicitRecipients) != 0:
		k.base, k.source, k.external = explicitRecipients, "-r/--recipient", true
	case environment != "":
		k.base, k.source, k.external = []string{environment}, "GIT_AGE_RECIPIENT", true
	default:
		if k.base, err = ruleRecipients(top, rules); err != nil {
			return k, err
		}
		if len(k.base) != 0 {
			k.source = displayPath(directory, top) + " [recipients]"
			break
		}
		if k.base, err = configValues(directory, "age.recipient"); err != nil {
			return k, err
		}
		if len(k.base) != 0 {
			k.source, k.external = "git config age.recipient", true
			break
		}
		k.base, k.toIdentities = k.own, true
	}
	return k, nil
}

// describe says what the base recipients are, for messages.
func (k keys) describe() string {
	if k.toIdentities {
		return k.identitySet.describe()
	}
	return k.source
}

// displayPath is path relative to directory when inside it, with forward slashes.
func displayPath(directory, path string) string {
	if relative, err := filepath.Rel(directory, path); err == nil && inside(directory, path) {
		path = relative
	}
	return filepath.ToSlash(path)
}

// fileTarget describes the recipients of one protected file.
type fileTarget struct {
	values     []string
	listed     []string // values without the user's own recipients added for toIdentities.
	rules      []string // Rule files that apply to the file.
	source     string   // What the file is encrypted to, for messages.
	recipients []age.Recipient
}

// target finds the recipients of path and parses them.
func (k keys) target(root, path string, ruleContents map[string][]byte) (fileTarget, error) {
	target, err := k.describeTarget(root, path, ruleContents)
	if err != nil {
		return target, err
	}
	values := target.values
	if k.toIdentities {
		values = target.listed
		target.recipients = append(target.recipients, k.identitySet.recipients...)
	}
	parsed, err := parseRecipients(values)
	target.recipients = append(target.recipients, parsed...)
	return target, err
}

// describeTarget is target without parsing the recipients.
func (k keys) describeTarget(root, path string, ruleContents map[string][]byte) (fileTarget, error) {
	target := fileTarget{values: append([]string(nil), k.base...), source: k.describe()}
	var nested []string
	for _, parent := range ancestorDirs(root, filepath.Dir(path)) {
		rule := filepath.Join(parent, ".gitage")
		target.rules = append(target.rules, rule)
		if parent != root {
			extra, err := ruleRecipients(rule, ruleContents)
			if err != nil {
				return target, err
			}
			if len(extra) != 0 {
				target.values = append(target.values, extra...)
				relative, _ := filepath.Rel(root, rule)
				nested = append([]string{filepath.ToSlash(relative) + " [recipients]"}, nested...)
			}
		}
	}
	target.listed = target.values
	if k.toIdentities {
		target.listed = target.values[len(k.base):]
	}
	if len(nested) != 0 {
		target.source += " + " + strings.Join(nested, " + ")
	}
	return target, nil
}

// encryptedToUser reports whether target encrypts to one of the user's
// identities, assuming so when that cannot be told. Without a base list, a
// file is also encrypted to whoever locked it, which counts as the user
// unless the user is listed elsewhere and so has partial access.
func (k keys) encryptedToUser(target fileTarget) (bool, error) {
	if len(k.own) == 0 && !k.plugins {
		return true, nil
	}
	mine, err := k.containsIdentity(target.listed)
	if err != nil || mine {
		return mine, err
	}
	if len(target.listed) != 0 && !k.toIdentities {
		return false, nil
	}
	listed, err := k.listedRecipients()
	if err != nil {
		return false, err
	}
	mine, err = k.containsIdentity(listed)
	return !mine, err
}

func (k keys) containsIdentity(values []string) (bool, error) {
	if containsRecipient(values, k.own) {
		return true, nil
	}
	if !k.plugins || len(values) == 0 {
		return false, nil
	}
	// Plugin identities don't expose a public key encoding. Confirm access to
	// the listed recipients with an empty in-memory message instead.
	recipients, err := parseRecipients(values)
	if err != nil {
		return false, err
	}
	probe, err := encryptContent(nil, recipients)
	if err != nil {
		return false, err
	}
	return k.canDecrypt(probe)
}

// listedRecipients reads every [recipients] list in the repository once.
func (k keys) listedRecipients() ([]string, error) {
	if *k.listed != nil {
		return *k.listed, nil
	}
	rules := k.rules
	if rules == nil {
		gitRoot, err := gitRoot(k.root)
		if err != nil {
			return nil, err
		}
		paths, err := regularFiles(k.root, gitRoot != "")
		if err != nil {
			return nil, err
		}
		if rules, err = readRules(paths); err != nil {
			return nil, err
		}
	}
	listed := []string{}
	for path, content := range rules {
		_, recipients, err := parseRules(path, content)
		if err != nil {
			return nil, err
		}
		listed = append(listed, recipients...)
	}
	*k.listed = listed
	return listed, nil
}

// encrypt reuses unchanged ciphertext from Git when reuse is allowed.
func (k keys) encrypt(root, path string, target fileTarget, plaintext []byte, reuse, remember bool) ([]byte, error) {
	var ciphertext []byte
	var legacy bool
	if reuse {
		ciphertext, legacy = k.reusableCiphertext(root, path, target, plaintext)
	}
	if ciphertext != nil && (!remember || !legacy) {
		return ciphertext, nil
	}
	if ciphertext == nil {
		var err error
		ciphertext, err = encryptContent(plaintext, target.recipients)
		if err != nil || !remember {
			return ciphertext, err
		}
	}
	if err := k.rememberCiphertext(root, target, ciphertext, legacy); err != nil {
		return nil, err
	}
	return ciphertext, nil
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
			if fields := strings.Fields(value); len(fields) >= 2 {
				value = strings.Join(fields[:2], " ")
			}
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
		switch {
		case strings.HasPrefix(value, "ssh-"):
			recipient, err = agessh.ParseRecipient(value)
		case strings.HasPrefix(value, "age1tag1"), strings.HasPrefix(value, "age1tagpq1"):
			recipient, err = tag.ParseRecipient(value)
		case strings.HasPrefix(value, "age1") && !strings.HasPrefix(value, "age1pq1") && strings.Count(value, "1") > 1:
			recipient, err = plugin.NewRecipient(value, pluginUI())
		default:
			var parsed []age.Recipient
			parsed, err = age.ParseRecipients(strings.NewReader(value))
			if err == nil && len(parsed) != 1 {
				err = errors.New("expected one recipient per value")
			}
			if err == nil {
				recipient = parsed[0]
			}
		}
		if err != nil {
			return nil, fmt.Errorf("invalid recipient %q: %w", value, err)
		}
		recipients = append(recipients, recipient)
	}
	return recipients, nil
}

// reusableCiphertext also reports whether reuse was verified through history
// rather than a local recipient record, so encryption can retain that proof.
func (k keys) reusableCiphertext(root, path string, target fileTarget, plaintext []byte) ([]byte, bool) {
	if len(k.identities) == 0 {
		// Reuse needs decryption; avoid spawning Git when no identity can decrypt.
		return nil, false
	}
	cache, err := k.recipientCacheDirectory(root)
	if err != nil {
		return nil, false
	}
	relative, _ := filepath.Rel(root, path)
	var stale [][]byte
	var checkedLegacy, legacy bool
	for _, revision := range []string{"", ":2", ":3", "HEAD"} {
		ciphertext, err := k.cache.objects.blob(revision, relative)
		if err != nil {
			continue
		}
		recorded, err := os.ReadFile(filepath.Join(cache, ciphertextHash(ciphertext)))
		needsRecord := errors.Is(err, os.ErrNotExist)
		if err == nil {
			if !k.matchesRecipientRecord(target, recorded) {
				continue
			}
		} else {
			if !errors.Is(err, os.ErrNotExist) {
				continue
			}
			// Older ciphertext has no local provenance. Only rule-based keys
			// have recipient history in Git that can justify reusing it.
			if !checkedLegacy {
				checkedLegacy = true
				legacy = !k.external && k.rulesMatchRevision(root, path, target, "HEAD")
				if legacy {
					stale, legacy = k.staleCiphertexts(root, path, target)
				}
			}
			// Conflict sides use the same staged rules as a stage-zero candidate.
			ruleRevision := revision
			if strings.HasPrefix(revision, ":") {
				ruleRevision = ""
			}
			if !legacy || !k.rulesMatchRevision(root, path, target, ruleRevision) || slices.ContainsFunc(stale, func(old []byte) bool { return bytes.Equal(old, ciphertext) }) {
				continue
			}
		}
		decrypted, err := decryptContent(ciphertext, k.identities)
		if err == nil && bytes.Equal(decrypted, plaintext) {
			return ciphertext, needsRecord
		}
	}
	return nil, false
}

func (k keys) staleCiphertexts(root, path string, target fileTarget) ([][]byte, bool) {
	relative, _ := filepath.Rel(root, path)
	scope := filepath.Dir(path) + "\x00" + k.recipientFingerprint(target)
	baseline, cached := k.cache.baselines[scope]
	if !cached {
		baseline.revision, baseline.ok = k.staleRevision(root, path, target)
		k.cache.baselines[scope] = baseline
	}
	if !baseline.ok || baseline.revision == "" {
		return nil, baseline.ok
	}
	if ciphertext, err := k.cache.objects.blob(baseline.revision, relative); err == nil {
		return [][]byte{ciphertext}, true
	}
	return nil, true
}

func (k keys) staleRevision(root, path string, target fileTarget) (string, bool) {
	var rulePaths []string
	for _, rule := range target.rules {
		rulePath, _ := filepath.Rel(root, rule)
		rulePaths = append(rulePaths, filepath.ToSlash(rulePath))
	}
	history, err := git(root, append([]string{"--literal-pathspecs", "log", "--format=%H", "HEAD", "--"}, rulePaths...)...)
	if err != nil {
		return "", false
	}
	for _, commit := range strings.Fields(string(history)) {
		for _, revision := range []string{commit, commit + "^"} {
			if !k.cache.objects.hasCommit(revision) || k.rulesMatchRevision(root, path, target, revision) {
				continue
			}
			return revision, true
		}
	}
	return "", true
}

// rulesMatchRevision compares effective recipients, including nested lists,
// rather than patterns, comments or how recipients are split between files.
func (k keys) rulesMatchRevision(root, path string, target fileTarget, revision string) bool {
	scope := filepath.Dir(path) + "\x00" + revision + "\x00" + k.recipientFingerprint(target)
	if matches, ok := k.cache.matches[scope]; ok {
		return matches
	}
	matches := k.compareRulesRevision(root, path, target, revision)
	k.cache.matches[scope] = matches
	return matches
}

func (k keys) compareRulesRevision(root, path string, target fileTarget, revision string) bool {
	rules := map[string][]byte{}
	for _, rule := range target.rules {
		rulePath, _ := filepath.Rel(root, rule)
		if content := k.cache.objects.rule(revision, rulePath); content != nil {
			rules[rule] = content
		}
	}
	previousKeys := k
	base, err := ruleRecipients(filepath.Join(root, ".gitage"), rules)
	if err != nil || len(base) == 0 && !k.toIdentities {
		// An implicit original encryptor or old external configuration cannot
		// be reconstructed from Git. A local fingerprint can still prove reuse.
		return false
	}
	previousKeys.base, previousKeys.toIdentities = base, len(base) == 0
	if previousKeys.toIdentities {
		previousKeys.base = k.own
	}
	previous, err := previousKeys.describeTarget(root, path, rules)
	if err != nil {
		return false
	}
	if k.toIdentities && previousKeys.toIdentities {
		return sameRecipients(target.listed, previous.listed)
	}
	return k.recipientFingerprint(target) == previousKeys.recipientFingerprint(previous)
}

// sameRecipients compares recipient lists as sets.
func sameRecipients(first, second []string) bool {
	return recipientSetFingerprint(first) == recipientSetFingerprint(second)
}
