package repository

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func git(directory string, args ...string) ([]byte, error) {
	return exec.Command("git", append([]string{"-C", directory}, args...)...).Output()
}

// gitWithInput includes Git's error output in the error it returns.
func gitWithInput(directory string, input []byte, args ...string) ([]byte, error) {
	command := exec.Command("git", append([]string{"-C", directory}, args...)...)
	command.Stdin = bytes.NewReader(input)
	output, err := command.Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		err = fmt.Errorf("%w: %s", err, bytes.TrimSpace(exit.Stderr))
	}
	return output, err
}

func exitCode(err error, code int) bool {
	var exit *exec.ExitError
	return errors.As(err, &exit) && exit.ExitCode() == code
}

func gitRoot(directory string) (string, error) {
	output, err := git(directory, "rev-parse", "--show-toplevel")
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return "", nil // A key can also be generated outside a Git worktree.
	}
	if err != nil {
		return "", err
	}

	root := filepath.FromSlash(strings.TrimSpace(string(output)))
	return filepath.EvalSymlinks(root)
}

// Root returns the worktree root containing directory, or an error naming command.
func Root(directory, command string) (string, error) {
	root, err := gitRoot(directory)
	if err == nil && root == "" {
		err = fmt.Errorf("%s requires a Git worktree", command)
	}
	return root, err
}

// resolveDirectory returns directory as an absolute path without symlinks,
// and its Git root, which is the directory itself outside a Git worktree.
func resolveDirectory(directory string) (resolved, root string, inGit bool, err error) {
	resolved, err = filepath.Abs(directory)
	if err != nil {
		return "", "", false, err
	}
	resolved, err = filepath.EvalSymlinks(resolved)
	if err != nil {
		return "", "", false, err
	}
	root, err = gitRoot(resolved)
	if err != nil {
		return "", "", false, err
	}
	if root == "" {
		return resolved, resolved, false, nil
	}
	return resolved, root, true, nil
}

// absolutePath resolves path against directory unless it is absolute.
func absolutePath(directory, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(directory, path)
}

// nativePath joins a slash-separated Git path to base.
func nativePath(base, path string) string {
	return filepath.Join(base, filepath.FromSlash(path))
}

// FirstLine returns the first line of err's message.
func FirstLine(err error) string {
	line, _, _ := strings.Cut(err.Error(), "\n")
	return line
}

// isBinary uses Git's heuristic: a NUL byte in the first 8000 bytes.
func isBinary(content []byte) bool {
	return bytes.Contains(content[:min(len(content), 8000)], []byte{0})
}

// hasLine reports whether content contains line, ignoring CRLF endings.
func hasLine(content []byte, line string) bool {
	for _, candidate := range strings.Split(string(content), "\n") {
		if strings.TrimSuffix(candidate, "\r") == line {
			return true
		}
	}
	return false
}

// ancestorDirs lists directory and its parents up to and including root.
func ancestorDirs(root, directory string) []string {
	var directories []string
	for parent := directory; inside(root, parent); parent = filepath.Dir(parent) {
		directories = append(directories, parent)
		if parent == root {
			break
		}
	}
	return directories
}

func regularMode(mode string) bool {
	return mode == "100644" || mode == "100755"
}

type stageEntry struct {
	mode, oid, stage, path string
}

// stageEntries parses the output of git ls-files --stage -z.
func stageEntries(output []byte) ([]stageEntry, error) {
	var entries []stageEntry
	for _, record := range bytes.Split(output, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		header, path, ok := strings.Cut(string(record), "\t")
		fields := strings.Fields(header)
		if !ok || len(fields) != 3 {
			return nil, fmt.Errorf("invalid Git index record")
		}
		entries = append(entries, stageEntry{fields[0], fields[1], fields[2], path})
	}
	return entries, nil
}

// readRules reads the .gitage files among paths.
func readRules(paths []string) (map[string][]byte, error) {
	rules := map[string][]byte{}
	for _, path := range paths {
		if filepath.Base(path) != ".gitage" {
			continue
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		rules[path] = content
	}
	return rules, nil
}

// readRuleFile reads a regular .gitage file, returning nil when there is none.
func readRuleFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return nil, err
	}
	return os.ReadFile(path)
}
