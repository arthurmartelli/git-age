package cli

import "os/exec"

// Native Windows processes have no /dev/tty to detach from.
func detachTerminal(command *exec.Cmd) {}
