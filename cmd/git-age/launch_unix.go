//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

func launch(interpreter string, args []string) int {
	// Replacing this process preserves the terminal, signals and exit status.
	err := syscall.Exec(interpreter, append([]string{interpreter}, args...), os.Environ())
	fmt.Fprintln(os.Stderr, "error:", err)
	return 1
}
