package cli

import (
	"bytes"
	"os/exec"
	"testing"
)

// runCommand runs a git-age command in directory, combining its output.
func runCommand(directory, command string, args ...string) (string, error) {
	var output bytes.Buffer
	root := newRootCommand()
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs(append([]string{"-C", directory, command}, args...))
	err := root.Execute()
	return output.String(), err
}

func runGit(t *testing.T, directory string, args ...string) []byte {
	t.Helper()
	output, err := exec.Command("git", append([]string{"-C", directory}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
	return output
}
