package cli

import (
	"os"
	"os/exec"
	"sync"
	"syscall"
)

type editorSignalKey struct{}

// editorSignals routes interrupts only while an editor is actually running.
// start holds the mutex until Process exists, so signal delivery cannot race it.
type editorSignals struct {
	mu        sync.Mutex
	interrupt func() error
}

func (s *editorSignals) start(command *exec.Cmd, interrupt func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := command.Start(); err != nil {
		return err
	}
	s.interrupt = interrupt
	return nil
}

func (s *editorSignals) finish() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.interrupt = nil
}

func (s *editorSignals) forwardInterrupt() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.interrupt == nil {
		return false
	}
	// The editor may already have exited, but its exit status still belongs
	// to it. Don't replace that status with global command cancellation.
	s.interrupt()
	return true
}

type commandSignalError struct{ signal os.Signal }

func (e *commandSignalError) Error() string {
	if e.signal == os.Interrupt {
		return "interrupted"
	}
	return e.signal.String()
}

func (e *commandSignalError) exitCode() int {
	if signal, ok := e.signal.(syscall.Signal); ok {
		return 128 + int(signal)
	}
	return 130
}

type editorExitError struct {
	err  error
	code int
}

func (e *editorExitError) Error() string { return "editor: " + e.err.Error() }
func (e *editorExitError) Unwrap() error { return e.err }

func processExitCode(exit *exec.ExitError) int {
	if code := exit.ExitCode(); code >= 0 {
		return code
	}
	if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return 1
}
