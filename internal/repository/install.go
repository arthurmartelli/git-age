package repository

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type InstallOptions struct {
	Mode              string
	UnlockAfterCommit *bool
	Diff, Merge       bool
	Filter, DryRun    bool
}

type installStep struct {
	description string
	apply       func() error
}

var hookEvents = []string{"pre-commit", "post-commit", "pre-push", "post-checkout", "post-merge", "post-rewrite"}

func Install(directory string, options InstallOptions, stdout io.Writer) error {
	root, err := gitRoot(directory)
	if err != nil {
		return err
	}
	if root == "" {
		return fmt.Errorf("install requires a Git worktree")
	}
	hooks, err := gitPath(root, "hooks")
	if err != nil {
		return err
	}
	if info, err := os.Stat(hooks); err == nil && !info.IsDir() {
		return fmt.Errorf("Git hooks path is not a directory: %s", hooks)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	attributes, err := gitPath(root, "info/attributes")
	if err != nil {
		return err
	}
	var steps []installStep
	enabled := options.Diff || options.Merge || options.Filter
	for _, event := range hookEvents {
		path := filepath.Join(hooks, event)
		content, _, exists, err := readInstallFile(path)
		active := enabled || event != "post-checkout" && event != "post-rewrite"
		if !active {
			// Hooks from other tools remain when disabling attribute sync.
			if err == nil && exists && managedHook(content, event) {
				steps = append(steps, installStep{"remove git-age " + event + " hook: " + path, func() error { return os.Remove(path) }})
			}
			continue
		}
		if err != nil {
			return err
		}
		if exists && !managedHook(content, event) {
			return fmt.Errorf("refusing to overwrite an existing non-git-age %s hook: %s; compose the hooks manually or move the existing hook first", event, path)
		}
		verb := "install"
		if exists {
			verb = "update"
		}
		steps = append(steps, installStep{verb + " git-age " + event + " hook: " + path, func() error {
			return writeInstallFile(path, []byte(renderHook(event)), 0755)
		}})
	}
	// Prepare the attributes before applying any steps, including config edits.
	existing, mode, _, err := readInstallFile(attributes)
	if err != nil {
		return err
	}
	var block []byte
	if enabled {
		block, err = renderAttributes(root, options)
		if err != nil {
			return err
		}
	}
	updated, err := updateAttributes(existing, block)
	if err != nil {
		return fmt.Errorf("%s: %w", attributes, err)
	}
	config := func(key, value string) {
		description := "set repo git config " + key + "=" + value
		if value == "" {
			description = "unset repo git config " + key
		}
		steps = append(steps, installStep{description, func() error { return setInstallConfig(root, key, value) }})
	}
	if options.Mode != "" {
		if options.Mode != "interactive" && options.Mode != "always-lock" && options.Mode != "abort" {
			return fmt.Errorf("invalid hook mode: %s", options.Mode)
		}
		config("age.hookMode", options.Mode)
	}
	if options.UnlockAfterCommit != nil {
		config("age.unlockAfterCommit", strconv.FormatBool(*options.UnlockAfterCommit))
	}
	setting := func(key, value string, active bool) {
		if !active {
			value = ""
		}
		config(key, value)
	}
	setting("diff.age.textconv", "git age textconv", options.Diff)
	// Cached textconv output could store decrypted secrets in Git's object store.
	config("diff.age.cachetextconv", "false")
	setting("merge.age.name", "git-age: merge decrypted", options.Merge)
	setting("merge.age.driver", "git age merge --path %P --marker-size %L %O %A %B", options.Merge)
	setting("filter.age.clean", "git age clean %f", options.Filter)
	setting("filter.age.smudge", "cat", options.Filter)
	setting("filter.age.required", "true", options.Filter)
	description := "write git-age patterns to " + attributes
	if !enabled {
		description = "remove git-age patterns from " + attributes
	}
	steps = append(steps, installStep{description, func() error {
		if bytes.Equal(existing, updated) {
			return nil
		}
		return writeInstallFile(attributes, updated, mode)
	}})
	for _, step := range steps {
		if options.DryRun {
			if _, err := fmt.Fprintln(stdout, "would "+step.description); err != nil {
				return err
			}
		} else {
			if err := step.apply(); err != nil {
				return fmt.Errorf("%s: %w", step.description, err)
			}
		}
	}
	if options.DryRun {
		return nil
	}
	_, err = fmt.Fprintf(stdout, "Installed git-age hooks: %s\nPlaintext diffs: %s\nUnchanged unlocked files hidden: %s\nDecrypted merges: %s\n", hooks, installYesNo(options.Diff), installYesNo(options.Filter), installYesNo(options.Merge))
	return err
}

func gitPath(root, name string) (string, error) {
	// Git's absolute path format resolves symlinks, hiding them from the
	// file checks used by install and uninstall. Make the path absolute here.
	output, err := exec.Command("git", "-C", root, "rev-parse", "--git-path", name).Output()
	if err != nil {
		return "", err
	}
	path := filepath.FromSlash(strings.TrimSuffix(strings.TrimSuffix(string(output), "\n"), "\r"))
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	return path, nil
}

func setInstallConfig(root, key, value string) error {
	args := []string{"-C", root, "config", "--local"}
	if value == "" {
		args = append(args, "--unset-all", key)
	} else {
		args = append(args, "--replace-all", key, value)
	}
	output, err := exec.Command("git", args...).CombinedOutput()
	var exit *exec.ExitError
	if value == "" && errors.As(err, &exit) && exit.ExitCode() == 5 {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func managedHook(content []byte, event string) bool {
	for _, line := range strings.Split(string(content), "\n") {
		if strings.TrimSuffix(line, "\r") == "# git-age managed "+event+" hook" {
			return true
		}
	}
	return false
}

func renderHook(event string) string {
	command := "git age hook " + event
	if event == "pre-push" {
		command += ` "$@"`
	}
	return "#!/bin/sh\n# git-age managed " + event + " hook\nexec " + command + "\n"
}

func readInstallFile(path string) ([]byte, os.FileMode, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0644, false, nil
	}
	if err != nil {
		return nil, 0, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, 0, true, fmt.Errorf("refusing to replace a non-regular file: %s", path)
	}
	content, err := os.ReadFile(path)
	return content, info.Mode().Perm(), true, err
}

func writeInstallFile(path string, content []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".git-age-install-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(content)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return err
	}
	if err := os.Chmod(file.Name(), mode); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func installYesNo(enabled bool) string {
	if enabled {
		return "yes"
	}
	return "no"
}
