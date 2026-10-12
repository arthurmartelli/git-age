package repository

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

func Uninstall(directory string, dryRun bool, stdout, stderr io.Writer) error {
	root, err := Root(directory, "uninstall")
	if err != nil {
		return err
	}
	hooks, err := gitPath(root, "hooks")
	if err != nil {
		return err
	}
	var steps []installStep
	var kept []string
	info, err := os.Stat(hooks)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil && info.IsDir() {
		for _, event := range hookEvents {
			path := filepath.Join(hooks, event)
			info, err := os.Lstat(path)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			// Never follow symlinks or remove hooks belonging to other tools.
			if !info.Mode().IsRegular() {
				kept = append(kept, event)
				continue
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if !managedHook(content, event) {
				kept = append(kept, event)
				continue
			}
			steps = append(steps, installStep{"remove git-age " + event + " hook: " + path, func() error { return os.Remove(path) }})
		}
	}
	attributes, err := gitPath(root, "info/attributes")
	if err != nil {
		return err
	}
	existing, mode, err := readInstallFile(attributes)
	if err != nil {
		return err
	}
	updated, err := updateAttributes(existing, nil)
	if err != nil {
		return fmt.Errorf("%s: %w", attributes, err)
	}
	if !bytes.Equal(existing, updated) {
		steps = append(steps, installStep{"remove git-age patterns from " + attributes, func() error {
			return writeInstallFile(attributes, updated, mode)
		}})
	}
	cache, err := gitPath(root, "git-age/recipients")
	if err != nil {
		return err
	}
	if _, err := os.Lstat(cache); err == nil {
		steps = append(steps, installStep{"remove ciphertext recipient cache: " + cache, func() error {
			return os.RemoveAll(cache)
		}})
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// Only remove the local keys install writes, preserving identities,
	// recipients, trust settings and configuration inherited from other files.
	output, err := git(root, "config", "--local", "--null", "--list")
	if err != nil {
		return err
	}
	configured := map[string]bool{}
	for _, record := range bytes.Split(output, []byte{0}) {
		key, _, _ := strings.Cut(string(record), "\n")
		configured[key] = true
	}
	for _, key := range installConfigKeys() {
		// Git lists config keys in lowercase.
		key = strings.ToLower(key)
		if configured[key] {
			steps = append(steps, installStep{"unset repo git config " + key, func() error {
				return setLocalConfig(root, key, "")
			}})
		}
	}
	output, err = git(root, "config", "--local", "--null", "--name-only", "--get-regexp", `^age\.(keyfile|recipient|trustedrecipients)$`)
	if err != nil && !exitCode(err, 1) {
		return err
	}
	var keptConfig []string
	configuredKeys := strings.Split(string(output), "\x00")
	for _, key := range []string{"age.keyFile", "age.recipient", "age.trustedRecipients"} {
		if slices.Contains(configuredKeys, strings.ToLower(key)) {
			keptConfig = append(keptConfig, key)
		}
	}
	for _, event := range kept {
		if _, err := fmt.Fprintf(stderr, "Kept %s hook: not managed by git-age\n", event); err != nil {
			return err
		}
	}
	if len(keptConfig) != 0 {
		if _, err := fmt.Fprintf(stderr, "Kept user Git config: %s\n", strings.Join(keptConfig, ", ")); err != nil {
			return err
		}
	}
	if len(steps) == 0 {
		_, err := fmt.Fprintln(stdout, "git-age: nothing to uninstall")
		return err
	}
	if err := runSteps(steps, dryRun, stdout); err != nil || dryRun {
		return err
	}
	_, err = fmt.Fprintln(stdout, "git-age: uninstalled Git integration")
	return err
}
