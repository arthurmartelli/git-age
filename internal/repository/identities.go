package repository

import (
	"bytes"
	"errors"
	"filippo.io/age"
	"filippo.io/age/agessh"
	"fmt"
	"golang.org/x/crypto/ssh"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func configValues(directory, key string) ([]string, error) {
	args := []string{"-C", directory, "config", "--null"}
	if key == "age.keyFile" {
		args = append(args, "--path")
	}
	args = append(args, "--get-all", key)
	output, err := exec.Command("git", args...).Output()
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
