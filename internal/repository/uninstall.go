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
)

func Uninstall(directory string, dryRun bool, stdout, stderr io.Writer) error {
	root, err := gitRoot(directory)
	if err != nil {
		return err
	}
	if root == "" {
		return fmt.Errorf("uninstall requires a Git worktree")
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
	existing, mode, _, err := readInstallFile(attributes)
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
	// Only remove the local keys install writes, preserving identities,
	// recipients, trust settings and configuration inherited from other files.
	output, err := exec.Command("git", "-C", root, "config", "--local", "--null", "--list").Output()
	if err != nil {
		return err
	}
	configured := map[string]bool{}
	for _, record := range bytes.Split(output, []byte{0}) {
		key, _, _ := strings.Cut(string(record), "\n")
		configured[key] = true
	}
	for _, key := range []string{
		"age.hookmode", "age.unlockaftercommit",
		"diff.age.textconv", "diff.age.cachetextconv",
		"merge.age.name", "merge.age.driver",
		"filter.age.clean", "filter.age.smudge", "filter.age.required",
	} {
		if configured[key] {
			steps = append(steps, installStep{"unset repo git config " + key, func() error {
				return setInstallConfig(root, key, "")
			}})
		}
	}
	for _, event := range kept {
		if _, err := fmt.Fprintf(stderr, "Kept %s hook: not managed by git-age\n", event); err != nil {
			return err
		}
	}
	if len(steps) == 0 {
		_, err := fmt.Fprintln(stdout, "git-age: nothing to uninstall")
		return err
	}
	for _, step := range steps {
		if dryRun {
			if _, err := fmt.Fprintln(stdout, "would "+step.description); err != nil {
				return err
			}
		} else if err := step.apply(); err != nil {
			return fmt.Errorf("%s: %w", step.description, err)
		}
	}
	if dryRun {
		return nil
	}
	_, err = fmt.Fprintln(stdout, "git-age: uninstalled Git integration")
	return err
}
