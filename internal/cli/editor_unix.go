//go:build !windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func commandSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGHUP, syscall.SIGTERM}
}

func runEditor(ctx context.Context, command *exec.Cmd, state *editorSignals) (err error) {
	// A separate group lets termination stop the shell and all its children.
	// Give that group the foreground terminal so editors can read keyboard input
	// and receive Ctrl-C directly, then restore the caller's foreground group.
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if tty, openErr := os.OpenFile("/dev/tty", os.O_RDWR, 0); openErr == nil {
		defer tty.Close()
		fd := int(tty.Fd())
		if group, getErr := unix.IoctlGetInt(fd, unix.TIOCGPGRP); getErr == nil && group == syscall.Getpgrp() {
			terminalState, _ := term.GetState(fd)
			command.SysProcAttr.Foreground = true
			command.SysProcAttr.Ctty = fd
			defer func() {
				// Reclaiming the terminal from a background process group requires
				// SIGTTOU to be ignored, not merely caught by a Go handler.
				signal.Ignore(syscall.SIGTTOU)
				defer signal.Reset(syscall.SIGTTOU)
				restoreErr := unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, group)
				if terminalState != nil {
					restoreErr = errors.Join(restoreErr, term.Restore(fd, terminalState))
				}
				if restoreErr != nil && ctx.Err() == nil {
					err = errors.Join(err, fmt.Errorf("restore editor terminal: %w", restoreErr))
				}
			}()
		}
	}
	command.Cancel = func() error {
		if err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL); errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		} else {
			return err
		}
	}
	if err := state.start(command, func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGINT) }); err != nil {
		return err
	}
	defer state.finish()
	return command.Wait()
}
