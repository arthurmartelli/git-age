package repository

import (
	"path/filepath"
	"strings"
)

// gitObjects shares a lazy cat-file process and rule lookups within an operation.
// References are stable until the operation updates the index or refs.
type gitObjects struct {
	root    string
	reader  *objectReader
	rules   map[string][]byte
	commits map[string]bool
}

func newGitObjects(root string) *gitObjects {
	return &gitObjects{root: root, rules: map[string][]byte{}, commits: map[string]bool{}}
}

func (g *gitObjects) read(reference string) ([]byte, error) {
	// The batch protocol is line-delimited. Git paths may contain newlines.
	if strings.ContainsAny(reference, "\r\n") {
		return git(g.root, "show", reference)
	}
	if g.reader == nil {
		var err error
		g.reader, err = newObjectReader(g.root)
		if err != nil {
			return nil, err
		}
	}
	return g.reader.read(reference)
}

func (g *gitObjects) blob(revision, path string) ([]byte, error) {
	return g.read(revision + ":" + filepath.ToSlash(path))
}

func (g *gitObjects) rule(revision, path string) []byte {
	reference := revision + ":" + filepath.ToSlash(path)
	if content, ok := g.rules[reference]; ok {
		return content
	}
	content, _ := g.read(reference)
	g.rules[reference] = content
	return content
}

func (g *gitObjects) hasCommit(revision string) bool {
	if exists, ok := g.commits[revision]; ok {
		return exists
	}
	_, err := g.read(revision + "^{commit}")
	g.commits[revision] = err == nil
	return err == nil
}

func (g *gitObjects) close() {
	if g.reader != nil {
		g.reader.close()
	}
}
