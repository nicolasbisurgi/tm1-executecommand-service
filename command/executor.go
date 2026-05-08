package command

import (
	"context"
	"os/exec"
	"time"
)

// SyncExecutor runs a Command and waits for it to finish, returning a Result
// that captures stdout, stderr, exit code and duration. Cancelled when the
// configured timeout elapses (the executor owns the timeout — callers do not
// pass a context). Used for Wait=1.
type SyncExecutor interface {
	Run(cmd Command) (Result, error)
}

// AsyncExecutor spawns a Command and returns immediately with a Handle
// describing the started process. The process is fully detached — no
// goroutine watches it, no context cancels it. Used for Wait=0. The Handle
// contains a UUID so a future registry (see ROADMAP R1) can track status
// without a breaking change to this interface.
type AsyncExecutor interface {
	Start(cmd Command) (Handle, error)
}

// Result captures the outcome of a synchronous execution. Stdout and Stderr
// are kept separate so logs can differentiate; the HTTP layer concatenates
// them to preserve wire compatibility with existing TM1 callers.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
}

// Handle identifies a process started asynchronously. The ID is generated
// even when the caller discards it today; it becomes the registry key when
// the polling endpoints land.
type Handle struct {
	ID        string
	PID       int
	StartedAt time.Time
}

// buildOSCmd turns a parsed Command into an *exec.Cmd, replicating the
// shell wrapper preserved by ParseCommand. When ctx is non-nil, the command
// is bound to it (used by SyncExecutor for timeouts).
func buildOSCmd(ctx context.Context, cmd Command) *exec.Cmd {
	exe, args := osArgs(cmd)
	if ctx != nil {
		return exec.CommandContext(ctx, exe, args...)
	}
	return exec.Command(exe, args...)
}

// osArgs maps a Command to the (executable, args) pair that the OS process
// API expects, applying the wrapper.
func osArgs(cmd Command) (string, []string) {
	switch cmd.Wrapper {
	case ShellCmdC:
		args := append([]string{"/C", cmd.Executable}, cmd.Args...)
		return "cmd", args
	case ShellPowerShellFile:
		args := append([]string{"-File", cmd.Executable}, cmd.Args...)
		return "powershell", args
	default:
		return cmd.Executable, cmd.Args
	}
}
