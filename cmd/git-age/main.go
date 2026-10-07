// git-age is a temporary migration launcher for the Python reference.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	// ponytail: Replace this launcher as native commands pass the acceptance suite.
	script, err := referenceScript()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	python := "python3"
	if runtime.GOOS == "windows" {
		python = "python"
	}
	interpreter, err := exec.LookPath(python)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: the Go migration launcher requires %s on PATH\n", python)
		return 1
	}
	return launch(interpreter, append([]string{script}, args...))
}

func referenceScript() (string, error) {
	script := os.Getenv("GIT_AGE_PYTHON_SCRIPT")
	if script == "" {
		executable, err := os.Executable()
		if err != nil {
			return "", err
		}
		executable, err = filepath.EvalSymlinks(executable)
		if err != nil {
			return "", err
		}
		// The development binary lives in the checkout's bin/ directory.
		script = filepath.Join(filepath.Dir(executable), "..", "git-age")
	}
	script, err := filepath.Abs(script)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(script)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("Python reference not found at %s; build in bin/ or set GIT_AGE_PYTHON_SCRIPT to the reference script", script)
	}
	return script, nil
}
