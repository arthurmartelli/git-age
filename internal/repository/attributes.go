package repository

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
)

const attributesBegin = "# BEGIN git-age (generated from .gitage; do not edit)"
const attributesEnd = "# END git-age"

func RefreshAttributes(directory string) error {
	root, err := gitRoot(directory)
	if err != nil || root == "" {
		return err
	}
	path, err := gitPath(root, "info/attributes")
	if err != nil {
		return err
	}
	existing, mode, err := readInstallFile(path)
	if err != nil {
		return err
	}
	if !hasLine(existing, attributesBegin) {
		return nil
	}
	options, err := installedDrivers(root)
	if err != nil {
		return err
	}
	block, err := renderAttributes(root, options)
	if err != nil {
		return err
	}
	updated, err := updateAttributes(existing, block)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if string(existing) == string(updated) {
		return nil
	}
	return writeInstallFile(path, updated, mode)
}

func installedDrivers(root string) (InstallOptions, error) {
	var options InstallOptions
	// Local driver settings record install's choices; inherited settings must
	// not reactivate integrations disabled by this repository.
	output, err := git(root, "config", "--local", "--null", "--get-regexp", `^(diff\.age\.textconv|merge\.age\.driver|filter\.age\.clean)$`)
	if exitCode(err, 1) {
		return options, nil
	}
	if err != nil {
		return options, err
	}
	for _, record := range bytes.Split(output, []byte{0}) {
		key, value, _ := strings.Cut(string(record), "\n")
		switch key {
		case "diff.age.textconv":
			options.Diff = value != ""
		case "merge.age.driver":
			options.Merge = value != ""
		case "filter.age.clean":
			options.Filter = value != ""
		}
	}
	return options, nil
}

func renderAttributes(root string, options InstallOptions) ([]byte, error) {
	paths, err := regularFiles(root, true)
	if err != nil {
		return nil, err
	}
	var block strings.Builder
	block.WriteString(attributesBegin + "\n")
	attributes := []string{"!diff", "-filter", "-merge"}
	if options.Diff {
		attributes[0] = "diff=age"
	}
	if options.Filter {
		attributes[1] = "filter=age"
	}
	if options.Merge {
		attributes[2] = "merge=age"
	}
	rules, err := readRules(paths)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, path := range paths {
		content, ok := rules[path]
		if !ok {
			continue
		}
		patterns, _, err := parseRules(path, content)
		if err != nil {
			return nil, err
		}
		prefix, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return nil, err
		}
		if prefix == "." {
			prefix = ""
		}
		for _, pattern := range strings.Split(string(patterns), "\n") {
			pattern = strings.TrimSuffix(pattern, "\r")
			pattern = trimPatternSpaces(pattern)
			if pattern == "" || strings.HasPrefix(pattern, "!") {
				continue
			}
			for _, attribute := range attributePatterns(filepath.ToSlash(prefix), pattern) {
				if !seen[attribute] {
					seen[attribute] = true
					block.WriteString(attribute + " " + strings.Join(attributes, " ") + "\n")
				}
			}
		}
	}
	block.WriteString(attributesEnd + "\n")
	return []byte(block.String()), nil
}

func attributePatterns(prefix, pattern string) []string {
	directory := strings.HasSuffix(pattern, "/")
	pattern = strings.TrimSuffix(pattern, "/")
	anchored := strings.HasPrefix(pattern, "/")
	pattern = strings.TrimPrefix(pattern, "/")
	if pattern == "" {
		return nil
	}
	base := ""
	if prefix != "" {
		escape := strings.NewReplacer(`\`, `\\`, "*", `\*`, "?", `\?`, "[", `\[`)
		base = escape.Replace(prefix) + "/"
	}
	head := "/" + base + pattern
	file := head
	if !anchored && !strings.Contains(pattern, "/") {
		head = "/" + base + "**/" + pattern
		file = head
		if base == "" {
			file = pattern
		}
	}
	var patterns []string
	switch {
	case strings.HasSuffix(head, "/**"):
		patterns = []string{head}
	case directory:
		patterns = []string{head + "/**"}
	default:
		patterns = []string{file, head + "/**"}
	}
	for i, pattern := range patterns {
		// Git accepts C-quoted patterns for spaces, quotes and control bytes.
		patterns[i] = quoteAttributePattern(pattern)
	}
	return patterns
}

func quoteAttributePattern(pattern string) string {
	var quoted strings.Builder
	quoted.WriteByte('"')
	needsQuotes := false
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch {
		case c == '"' || c == '\\':
			quoted.WriteByte('\\')
			quoted.WriteByte(c)
			needsQuotes = true
		case c < 32 || c == 127:
			fmt.Fprintf(&quoted, "\\%03o", c)
			needsQuotes = true
		default:
			quoted.WriteByte(c)
			needsQuotes = needsQuotes || c == ' '
		}
	}
	quoted.WriteByte('"')
	if needsQuotes {
		return quoted.String()
	}
	return pattern
}

func updateAttributes(existing, block []byte) ([]byte, error) {
	lines := strings.SplitAfter(string(existing), "\n")
	begin, end := -1, -1
	for i, line := range lines {
		switch strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r") {
		case attributesBegin:
			if begin != -1 {
				return nil, fmt.Errorf("multiple git-age attributes blocks")
			}
			begin = i
		case attributesEnd:
			if end != -1 {
				return nil, fmt.Errorf("multiple git-age attributes blocks")
			}
			end = i
		}
	}
	if begin == -1 && end == -1 {
		if len(block) == 0 {
			return existing, nil
		}
		prefix := string(existing)
		if prefix != "" && !strings.HasSuffix(prefix, "\n") {
			prefix += "\n"
		}
		return []byte(prefix + string(block)), nil
	}
	if begin != -1 && end == -1 {
		return nil, fmt.Errorf("incomplete git-age attributes block: missing %q; insert this marker after the generated patterns and before any user attributes, then retry", attributesEnd)
	}
	if begin == -1 || end <= begin {
		return nil, fmt.Errorf("incomplete git-age attributes block")
	}
	return []byte(strings.Join(lines[:begin], "") + string(block) + strings.Join(lines[end+1:], "")), nil
}
