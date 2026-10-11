package repository

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

type ProtectedFile struct {
	Path     string
	State    string
	RuleFile string
	RuleLine int
	Pattern  string
}

var ErrNoRules = errors.New("no .gitage files found")

func ProtectedFiles(directory string, paths []string) ([]ProtectedFile, error) {
	directory, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("not a directory: %s", directory)
	}
	root, err := gitRoot(directory)
	if err != nil {
		return nil, err
	}
	inGit := root != ""
	if !inGit {
		root = directory
	}
	candidates, err := regularFiles(directory, inGit)
	if err != nil {
		return nil, err
	}
	rules := []string{}
	for _, path := range candidates {
		if filepath.Base(path) == ".gitage" {
			rules = append(rules, path)
		}
	}
	for parent := filepath.Dir(directory); inGit && inside(root, parent); parent = filepath.Dir(parent) {
		path := filepath.Join(parent, ".gitage")
		if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
			rules = append(rules, path)
		}
		if parent == root {
			break
		}
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("%w under %s", ErrNoRules, root)
	}
	ruleContents := make(map[string][]byte, len(rules))
	for _, path := range rules {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		ruleContents[path] = content
	}
	files, err := matchProtectedFiles(directory, root, candidates, ruleContents, ruleIgnoreCase(root, inGit))
	if err != nil {
		return nil, err
	}
	for i := range files {
		files[i].State = fileState(filepath.Join(directory, filepath.FromSlash(files[i].Path)))
	}
	return selectFiles(directory, files, paths)
}

func ruleIgnoreCase(root string, inGit bool) string {
	if inGit {
		if output, err := exec.Command("git", "-C", root, "config", "--bool", "core.ignoreCase").Output(); err == nil {
			return strings.TrimSpace(string(output))
		}
	}
	return "false"
}

func matchProtectedFiles(directory, root string, candidates []string, rules map[string][]byte, ignoreCase string) ([]ProtectedFile, error) {
	// A scratch repository keeps rule matching from changing the user's ignore rules or index.
	scratch, err := os.MkdirTemp("", "git-age-rules-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(scratch)
	init := exec.Command("git", "-C", scratch, "-c", "init.templateDir=", "init", "-q")
	init.Env = ruleMatcherEnvironment()
	if output, err := init.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("initialize rule matcher: %w: %s", err, output)
	}
	for path, content := range rules {
		patterns, err := filePatterns(path, content)
		if err != nil {
			return nil, err
		}
		relative, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return nil, err
		}
		parent := filepath.Join(scratch, relative)
		if err := os.MkdirAll(parent, 0700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(parent, ".gitignore"), patterns, 0600); err != nil {
			return nil, err
		}
	}

	var input bytes.Buffer
	for _, path := range candidates {
		if base := filepath.Base(path); base == ".gitage" || base == ".gitage.key" {
			continue
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return nil, err
		}
		input.WriteString(filepath.ToSlash(relative))
		input.WriteByte(0)
	}
	cmd := exec.Command("git", "-C", scratch, "-c", "core.excludesFile="+os.DevNull, "-c", "core.ignoreCase="+ignoreCase, "check-ignore", "--no-index", "--stdin", "-z", "-v")
	cmd.Env = ruleMatcherEnvironment()
	cmd.Stdin = &input
	output, err := cmd.Output()
	var exit *exec.ExitError
	if err != nil && !(errors.As(err, &exit) && exit.ExitCode() == 1) {
		return nil, fmt.Errorf("match .gitage rules: %w", err)
	}
	records := bytes.Split(bytes.TrimSuffix(output, []byte{0}), []byte{0})
	var files []ProtectedFile
	for i := 0; i+3 < len(records); i += 4 {
		pattern := string(records[i+2])
		if strings.HasPrefix(pattern, "!") {
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(string(records[i+3])))
		relative, _ := filepath.Rel(directory, path)
		rule := filepath.Join(root, filepath.FromSlash(string(records[i])))
		rule = filepath.Join(filepath.Dir(rule), ".gitage")
		ruleRelative, _ := filepath.Rel(directory, rule)
		line, _ := strconv.Atoi(string(records[i+1]))
		files = append(files, ProtectedFile{filepath.ToSlash(relative), "", filepath.ToSlash(ruleRelative), line, pattern})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func ruleMatcherEnvironment() []string {
	// Hooks export repository paths. The scratch matcher must use its own Git
	// directory and index, including during partial commits and in worktrees.
	local := map[string]bool{
		"GIT_DIR": true, "GIT_WORK_TREE": true, "GIT_COMMON_DIR": true,
		"GIT_INDEX_FILE": true, "GIT_OBJECT_DIRECTORY": true,
		"GIT_ALTERNATE_OBJECT_DIRECTORIES": true, "GIT_PREFIX": true,
		"GIT_SHALLOW_FILE": true, "GIT_GRAFT_FILE": true,
	}
	var environment []string
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		if !local[key] {
			environment = append(environment, value)
		}
	}
	return environment
}

func regularFiles(directory string, inGit bool) ([]string, error) {
	var candidates []string
	if inGit {
		output, err := exec.Command("git", "-C", directory, "ls-files", "--cached", "--others", "--exclude-standard", "-z").Output()
		if err != nil {
			return nil, err
		}
		for _, name := range bytes.Split(output, []byte{0}) {
			if len(name) != 0 {
				candidates = append(candidates, filepath.Join(directory, string(name)))
			}
		}
	} else {
		err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if entry.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			candidates = append(candidates, path)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	var files []string
	seen := map[string]bool{}
	for _, path := range candidates {
		if seen[path] {
			continue
		}
		seen[path] = true
		if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
			files = append(files, path)
		}
	}
	return files, nil
}

func filePatterns(path string, content []byte) ([]byte, error) {
	patterns, _, err := parseRules(path, content)
	return patterns, err
}

func parseRules(path string, content []byte) ([]byte, []string, error) {
	if !utf8.Valid(content) {
		return nil, nil, fmt.Errorf("%s: .gitage must be UTF-8 text", path)
	}
	lines := strings.Split(string(content), "\n")
	section := ""
	seen := map[string]bool{}
	var recipients []string
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			lines[i] = ""
			continue
		}
		if ruleSectionHeader(line) {
			section = line[1 : len(line)-1]
			if section != "files" && section != "recipients" {
				return nil, nil, fmt.Errorf("%s:%d: unknown section [%s]", path, i+1, section)
			}
			if seen[section] {
				return nil, nil, fmt.Errorf("%s:%d: duplicate section [%s]", path, i+1, section)
			}
			seen[section] = true
			lines[i] = ""
			continue
		}
		switch section {
		case "files":
			if line == "!" {
				return nil, nil, fmt.Errorf("%s:%d: empty negation rule", path, i+1)
			}
			pattern := trimPatternSpaces(strings.TrimSuffix(raw, "\r"))
			pattern = strings.TrimPrefix(pattern, "!")
			pattern = strings.TrimSuffix(pattern, "/")
			if err := validatePattern(pattern); err != nil {
				return nil, nil, fmt.Errorf("%s:%d: %w", path, i+1, err)
			}
		case "recipients":
			if !strings.HasPrefix(line, "age1") && !strings.HasPrefix(line, "ssh-") {
				return nil, nil, fmt.Errorf("%s:%d: is not an age recipient or SSH public key", path, i+1)
			}
			recipients = append(recipients, line)
			lines[i] = ""
		default:
			return nil, nil, fmt.Errorf("%s:%d: entry is outside a section; start with [files]", path, i+1)
		}
	}
	if seen["recipients"] && len(recipients) == 0 {
		return nil, nil, fmt.Errorf("%s: [recipients] section is empty", path)
	}
	return []byte(strings.Join(lines, "\n")), recipients, nil
}

func ruleSectionHeader(line string) bool {
	if len(line) < 3 || line[0] != '[' || line[len(line)-1] != ']' || line[1] < 'a' || line[1] > 'z' {
		return false
	}
	for _, c := range line[2 : len(line)-1] {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func trimPatternSpaces(pattern string) string {
	for strings.HasSuffix(pattern, " ") {
		backslashes := 0
		for i := len(pattern) - 2; i >= 0 && pattern[i] == '\\'; i-- {
			backslashes++
		}
		if backslashes%2 != 0 {
			break
		}
		pattern = strings.TrimSuffix(pattern, " ")
	}
	return pattern
}

func validatePattern(pattern string) error {
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++
			if i == len(pattern) {
				return fmt.Errorf("pattern ends with an unescaped backslash")
			}
		case '[':
			i++
			if i < len(pattern) && (pattern[i] == '!' || pattern[i] == '^') {
				i++
			}
			// A closing bracket as the first member is a literal bracket.
			if i < len(pattern) && pattern[i] == ']' {
				i++
			}
			for ; i < len(pattern) && pattern[i] != ']'; i++ {
				if pattern[i] == '\\' {
					i++
				} else if pattern[i] == '[' && i+1 < len(pattern) && pattern[i+1] == ':' {
					close := strings.IndexByte(pattern[i+2:], ']')
					if close == -1 {
						return fmt.Errorf("pattern has an unterminated [")
					}
					close += i + 2
					if close > i+2 && pattern[close-1] == ':' {
						name := pattern[i+2 : close-1]
						switch name {
						case "alnum", "alpha", "blank", "cntrl", "digit", "graph", "lower", "print", "punct", "space", "upper", "xdigit":
						default:
							return fmt.Errorf("unknown character class [:%s:]", name)
						}
						i = close
					}
				}
			}
			if i >= len(pattern) {
				return fmt.Errorf("pattern has an unterminated [")
			}
		}
	}
	return nil
}

func fileState(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return "UNKNOWN"
	}
	defer file.Close()
	header := make([]byte, len("-----BEGIN AGE ENCRYPTED FILE-----\n"))
	n, err := io.ReadFull(file, header)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return "UNKNOWN"
	}
	return contentState(header[:n])
}

func contentState(content []byte) string {
	if bytes.HasPrefix(content, []byte("age-encryption.org/v1\n")) || bytes.HasPrefix(content, []byte("-----BEGIN AGE ENCRYPTED FILE-----\n")) {
		return "LOCKED"
	}
	return "UNLOCKED"
}

func inside(directory, path string) bool {
	relative, err := filepath.Rel(directory, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func selectFiles(directory string, files []ProtectedFile, paths []string) ([]ProtectedFile, error) {
	if len(paths) == 0 {
		return files, nil
	}
	selected := map[string]bool{}
	for _, path := range paths {
		target := path
		if !filepath.IsAbs(target) {
			target = filepath.Join(directory, target)
		}
		if !inside(directory, target) {
			return nil, fmt.Errorf("%s: outside %s", path, directory)
		}
		matched := false
		for _, file := range files {
			if inside(target, filepath.Join(directory, filepath.FromSlash(file.Path))) {
				selected[file.Path] = true
				matched = true
			}
		}
		if !matched {
			info, err := os.Stat(target)
			if errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("%s: no such file or directory", path)
			}
			if err != nil {
				return nil, err
			}
			if info.IsDir() {
				return nil, fmt.Errorf("%s: no file in it is protected by .gitage", path)
			}
			return nil, fmt.Errorf("%s: not protected by .gitage", path)
		}
	}
	var result []ProtectedFile
	for _, file := range files {
		if selected[file.Path] {
			result = append(result, file)
		}
	}
	return result, nil
}
