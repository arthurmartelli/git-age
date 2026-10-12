package cli

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func gitShell() (string, error) {
	shell, err := exec.LookPath("sh")
	if err != nil && runtime.GOOS == "windows" {
		// Git for Windows includes sh even when only git.exe is on PATH.
		gitPath, gitErr := exec.Command("git", "--exec-path").Output()
		if gitErr != nil {
			return "", gitErr
		}
		return filepath.Join(strings.TrimSpace(string(gitPath)), "..", "..", "..", "usr", "bin", "sh.exe"), nil
	}
	return shell, err
}
