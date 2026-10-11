package repository

import (
	"bytes"
	"errors"
	"filippo.io/age"
	"filippo.io/age/agessh"
	"fmt"
	"golang.org/x/crypto/ssh"
	"os"
	"path/filepath"
	"strings"
)

// configValues returns every value of key, where an empty value clears
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
		if value == "" {
			values = nil
		} else {
			values = append(values, value)
		}
	}
	return values, nil
}

var errNoIdentity = errors.New("no identity configured; use -i or generate a key with git-age keygen")

// identitySet holds the user's identities and the recipients they decrypt for.
type identitySet struct {
	identities []age.Identity
	own        []string
	paths      []string
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

func loadIdentities(directory, root string, paths []string) (identitySet, error) {
	if len(paths) == 0 {
		paths = filepath.SplitList(os.Getenv("GIT_AGE_KEY_FILE"))
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
	for _, path := range paths {
		path = absolutePath(directory, path)
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
			parsed, err = age.ParseIdentities(bytes.NewReader(content))
			if err != nil {
				return identitySet{}, fmt.Errorf("%s: %w", path, err)
			}
		}
		for _, identity := range parsed {
			switch identity := identity.(type) {
			case *age.X25519Identity:
				set.own = append(set.own, identity.Recipient().String())
			}
		}
		set.identities = append(set.identities, parsed...)
		set.paths = append(set.paths, path)
	}
	return set, nil
}
