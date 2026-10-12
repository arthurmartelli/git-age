package repository

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/plugin"
	"golang.org/x/crypto/ssh"
)

// configValues returns every value of key, where a blank value clears
// those before it. Flags such as --path or --bool convert the values.
func configValues(directory, key string, flags ...string) ([]string, error) {
	args := append(append([]string{"config", "--null"}, flags...), "--get-all", key)
	output, err := git(directory, args...)
	if exitCode(err, 1) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var values []string
	for _, value := range strings.Split(strings.TrimSuffix(string(output), "\x00"), "\x00") {
		if strings.TrimSpace(value) == "" {
			values = nil
		} else {
			values = append(values, value)
		}
	}
	return values, nil
}

var errNoIdentity = errors.New("no identity configured; use -i or generate a key with git-age keygen")

func containsPrivateIdentity(content []byte) bool {
	return bytes.Contains(content, []byte("AGE-SECRET-KEY-")) || bytes.Contains(content, []byte("AGE-PLUGIN-"))
}

// identitySet holds the user's identities and the recipients they decrypt for.
type identitySet struct {
	identities []age.Identity
	recipients []age.Recipient
	own        []string
	paths      []string
	plugins    bool
}

// describe names the identity files, for messages.
func (s identitySet) describe() string {
	switch len(s.paths) {
	case 0:
		return "no identity"
	case 1:
		return "identity " + s.paths[0]
	}
	return "identities " + strings.Join(s.paths, ", ")
}

func (s identitySet) canDecrypt(content []byte) (bool, error) {
	_, err := decryptContent(content, s.identities)
	var noMatch *age.NoIdentityMatchError
	if errors.As(err, &noMatch) {
		return false, nil
	}
	return err == nil, err
}

func loadIdentities(directory, root string, paths []string) (identitySet, error) {
	if len(paths) == 0 {
		for _, path := range filepath.SplitList(os.Getenv("GIT_AGE_KEY_FILE")) {
			if strings.TrimSpace(path) != "" {
				paths = append(paths, path)
			}
		}
	}
	if len(paths) == 0 {
		var err error
		paths, err = configValues(directory, "age.keyFile", "--path")
		if err != nil {
			return identitySet{}, err
		}
	}
	if len(paths) == 0 {
		path := filepath.Join(root, ".gitage.key")
		if _, err := os.Stat(path); err == nil {
			paths = []string{path}
		}
	}
	var set identitySet
	seen := map[string]bool{}
	for _, path := range paths {
		path, err := identityPath(directory, path)
		if err != nil {
			return identitySet{}, err
		}
		if seen[path] {
			continue
		}
		seen[path] = true
		content, err := os.ReadFile(path)
		if err != nil {
			return identitySet{}, err
		}
		if contentState(content) == Locked || bytes.HasPrefix(content, []byte("-----BEGIN AGE ENCRYPTED FILE-----")) {
			return identitySet{}, fmt.Errorf("%s: encrypted age identity files are not supported; use an unencrypted identity file", path)
		}
		if bytes.HasPrefix(content, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----")) {
			return identitySet{}, fmt.Errorf("%s: passphrase-protected private keys are not supported; use an unencrypted identity file", path)
		}
		var parsed []age.Identity
		if bytes.HasPrefix(content, []byte("-----BEGIN")) {
			identity, err := agessh.ParseIdentity(content)
			if err != nil {
				var protected *ssh.PassphraseMissingError
				if errors.As(err, &protected) {
					return identitySet{}, fmt.Errorf("%s: passphrase-protected SSH identities are not supported; use an unencrypted identity file", path)
				}
				return identitySet{}, fmt.Errorf("%s: %w", path, err)
			}
			parsed = []age.Identity{identity}
			signer, err := ssh.ParsePrivateKey(content)
			if err != nil {
				return identitySet{}, fmt.Errorf("%s: %w", path, err)
			}
			set.own = append(set.own, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))))
		} else {
			parsed, err = parseIdentityFile(content)
			if err != nil {
				return identitySet{}, fmt.Errorf("%s: %w", path, err)
			}
		}
		for _, identity := range parsed {
			switch identity := identity.(type) {
			case *age.X25519Identity:
				set.own = append(set.own, identity.Recipient().String())
				set.recipients = append(set.recipients, identity.Recipient())
			case *age.HybridIdentity:
				set.own = append(set.own, identity.Recipient().String())
				set.recipients = append(set.recipients, identity.Recipient())
			case *plugin.Identity:
				set.recipients = append(set.recipients, identity.Recipient())
				set.plugins = true
			case *agessh.RSAIdentity:
				set.recipients = append(set.recipients, identity.Recipient())
			case *agessh.Ed25519Identity:
				set.recipients = append(set.recipients, identity.Recipient())
			}
		}
		set.identities = append(set.identities, parsed...)
		set.paths = append(set.paths, path)
	}
	return set, nil
}

func identityPath(directory, path string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") || os.PathSeparator == '\\' && strings.HasPrefix(path, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand identity path: %w", err)
		}
		if path == "~" {
			path = home
		} else {
			path = filepath.Join(home, path[2:])
		}
	}
	return filepath.EvalSymlinks(absolutePath(directory, path))
}

func pluginUI() *plugin.ClientUI {
	message := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "git-age: "+format+"\n", args...)
	}
	return plugin.NewTerminalUI(message, message)
}

// parseIdentityFile keeps native age parsing and adds plugin identity lines.
// Never include a failed line in an error: it may contain a private key.
func parseIdentityFile(content []byte) ([]age.Identity, error) {
	if len(content) > 1<<24 {
		return nil, errors.New("identities file is too long")
	}
	var identities []age.Identity
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for line := 1; scanner.Scan(); line++ {
		value := scanner.Text()
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		var parsed []age.Identity
		var err error
		if strings.HasPrefix(value, "AGE-PLUGIN-") {
			var identity *plugin.Identity
			identity, err = plugin.NewIdentity(value, pluginUI())
			parsed = []age.Identity{identity}
		} else {
			parsed, err = age.ParseIdentities(strings.NewReader(value))
		}
		if err != nil {
			return nil, fmt.Errorf("identity at line %d: %w", line, err)
		}
		identities = append(identities, parsed...)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read identities: %w", err)
	}
	if len(identities) == 0 {
		return nil, errors.New("no identities found")
	}
	return identities, nil
}
