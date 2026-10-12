package repository

import (
	"bytes"
	"runtime"
	"testing"
)

func TestGitObjectsMissingAndUnusualPaths(t *testing.T) {
	root := identityTestRepo(t)
	var paths []string
	for _, path := range []string{"secret.env", "a file.env", "tab\tfile.env", "line\nfile.env"} {
		if runtime.GOOS == "windows" && (path == "tab\tfile.env" || path == "line\nfile.env") {
			continue // Windows does not allow these bytes in filenames.
		}
		paths = append(paths, path)
		cacheFile(t, root, path, []byte("secret for "+path))
		cacheGit(t, root, nil, "--literal-pathspecs", "add", "--", path)
	}
	objects := newGitObjects(root)
	defer objects.close()
	for _, path := range paths {
		content := []byte("secret for " + path)
		// Missing requests must not desynchronize subsequent batch responses.
		if _, err := objects.blob("HEAD", path); err == nil {
			t.Fatal("found HEAD on an unborn branch")
		}
		got, err := objects.blob("", path)
		if err != nil || !bytes.Equal(got, content) {
			t.Fatalf("read %q after missing request: %q, %v", path, got, err)
		}
	}
}
