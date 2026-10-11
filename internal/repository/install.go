package repository

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

// HookModes are the pre-commit policies for protected plaintext.
var HookModes = []string{"interactive", "always-lock", "abort"}

type configSetting struct {
	key, value string
	active     bool
}

// driverSettings lists the local config the Git drivers use. Install sets the
// active ones and unsets the rest; uninstall unsets all of them.
func driverSettings(options InstallOptions) []configSetting {
	return []configSetting{
		{"diff.age.textconv", "git age textconv", options.Diff},
		// Cached textconv output could store decrypted secrets in Git's object store.
		{"diff.age.cachetextconv", "false", true},
		{"merge.age.name", "git-age: merge decrypted", options.Merge},
		{"merge.age.driver", "git age merge --path %P --marker-size %L %O %A %B", options.Merge},
		{"filter.age.clean", "git age clean %f", options.Filter},
		{"filter.age.smudge", "cat", options.Filter},
		{"filter.age.required", "true", options.Filter},
	}
}

// installConfigKeys lists every local config key install may write.
func installConfigKeys() []string {
	keys := []string{"age.hookMode", "age.unlockAfterCommit"}
	for _, setting := range driverSettings(InstallOptions{}) {
		keys = append(keys, setting.key)
	}
	return keys
}

func Install(directory string, options InstallOptions, stdout io.Writer) error {
	root, err := Root(directory, "install")
	if err != nil {
		return err
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
		content, _, err := readInstallFile(path)
		exists := content != nil
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
	existing, mode, err := readInstallFile(attributes)
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
		if err := ValidateHookMode(options.Mode); err != nil {
			return err
		}
		config("age.hookMode", options.Mode)
	}
	if options.UnlockAfterCommit != nil {
		config("age.unlockAfterCommit", strconv.FormatBool(*options.UnlockAfterCommit))
	}
	for _, setting := range driverSettings(options) {
		if setting.active {
			config(setting.key, setting.value)
		} else {
			config(setting.key, "")
		}
	}
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
	if err := runSteps(steps, options.DryRun, stdout); err != nil || options.DryRun {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Installed git-age hooks: %s\nPlaintext diffs: %s\nUnchanged unlocked files hidden: %s\nDecrypted merges: %s\n", hooks, installYesNo(options.Diff), installYesNo(options.Filter), installYesNo(options.Merge))
	return err
}

// runSteps applies the steps, or only describes them in a dry run.
func runSteps(steps []installStep, dryRun bool, stdout io.Writer) error {
	for _, step := range steps {
		if dryRun {
			if _, err := fmt.Fprintln(stdout, "would "+step.description); err != nil {
				return err
			}
		} else if err := step.apply(); err != nil {
			return fmt.Errorf("%s: %w", step.description, err)
		}
	}
	return nil
}

// HookMode returns GIT_AGE_HOOK_MODE or age.hookMode, by default interactive.
func HookMode(directory string) (string, error) {
	value := os.Getenv("GIT_AGE_HOOK_MODE")
	if value == "" {
		values, err := configValues(directory, "age.hookMode")
		if err != nil {
			return "", err
		}
		if len(values) != 0 {
			value = values[len(values)-1]
		}
	}
	if value == "" {
		value = "interactive"
	}
	return value, ValidateHookMode(value)
}

func ValidateHookMode(mode string) error {
	if !slices.Contains(HookModes, mode) {
		return fmt.Errorf("invalid choice: '%s' (choose from %s)", mode, strings.Join(HookModes, ", "))
	}
	return nil
}

// UnlockAfterCommit returns GIT_AGE_UNLOCK_AFTER_COMMIT or age.unlockAfterCommit.
func UnlockAfterCommit(directory string) (bool, error) {
	const environment = "GIT_AGE_UNLOCK_AFTER_COMMIT"
	value, configured := os.LookupEnv(environment)
	if !configured {
		values, err := configValues(directory, "age.unlockAfterCommit", "--bool")
		if err != nil || len(values) == 0 {
			return false, err
		}
		value = values[len(values)-1]
	}
	enabled, err := ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%w for %s", err, environment)
	}
	return enabled, nil
}

// ParseBool accepts the boolean spellings Git accepts in config files.
func ParseBool(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("invalid boolean value %q", value)
}

func gitPath(root, name string) (string, error) {
	// Git's absolute path format resolves symlinks, hiding them from the
	// file checks used by install and uninstall. Make the path absolute here.
	output, err := git(root, "rev-parse", "--git-path", name)
	if err != nil {
		return "", err
	}
	return absolutePath(root, filepath.FromSlash(strings.TrimSuffix(strings.TrimSuffix(string(output), "\n"), "\r"))), nil
}

func setInstallConfig(root, key, value string) error {
	args := []string{"-C", root, "config", "--local"}
	if value == "" {
		args = append(args, "--unset-all", key)
	} else {
		args = append(args, "--replace-all", key, value)
	}
	output, err := exec.Command("git", args...).CombinedOutput()
	if value == "" && exitCode(err, 5) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func managedHook(content []byte, event string) bool {
	return hasLine(content, "# git-age managed "+event+" hook")
}

func renderHook(event string) string {
	command := "git age hook " + event
	if event == "pre-push" {
		command += ` "$@"`
	}
	return "#!/bin/sh\n# git-age managed " + event + " hook\nexec " + command + "\n"
}

// readInstallFile returns nil content for a missing file.
func readInstallFile(path string) ([]byte, os.FileMode, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0644, nil
	}
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("refusing to replace a non-regular file: %s", path)
	}
	content, err := os.ReadFile(path)
	return content, info.Mode().Perm(), err
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
