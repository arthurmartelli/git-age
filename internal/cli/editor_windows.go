package cli

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

func commandSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

func runEditor(ctx context.Context, command *exec.Cmd, state *editorSignals) error {
	// Windows delivers console Ctrl-C events to the editor too. Let it handle
	// them; only termination cancels CommandContext and kills the process.
	command.Cancel = func() error {
		// taskkill's tree option also stops editors launched by the shell.
		if err := exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(command.Process.Pid)).Run(); err != nil {
			return command.Process.Kill()
		}
		return nil
	}
	if err := state.start(command, func() error { return nil }); err != nil {
		return err
	}
	defer state.finish()
	return command.Wait()
}
