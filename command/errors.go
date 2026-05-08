package command

import (
	"fmt"
	"time"
)

// ErrPolicyRejected is returned when a Command fails the configured policy.
// Carries the human-readable rejection reason for logs; HTTP responses stay
// generic per the security philosophy.
type ErrPolicyRejected struct {
	Reason string
}

func (e *ErrPolicyRejected) Error() string {
	return fmt.Sprintf("command not permitted: %s", e.Reason)
}

// ErrSpawnFailed is returned when the OS could not start the process at all
// (executable not found, permission denied, fork/exec failure, etc.). Wraps
// the underlying error for logs; callers using errors.Is/Unwrap can drill in.
type ErrSpawnFailed struct {
	Cause error
}

func (e *ErrSpawnFailed) Error() string {
	if e.Cause == nil {
		return "failed to spawn process"
	}
	return fmt.Sprintf("failed to spawn process: %v", e.Cause)
}

func (e *ErrSpawnFailed) Unwrap() error { return e.Cause }

// ErrTimeout is returned by SyncExecutor when the configured timeout elapses
// before the process exits. The process is killed at this point.
type ErrTimeout struct {
	Duration time.Duration
}

func (e *ErrTimeout) Error() string {
	return fmt.Sprintf("command execution timed out after %s", e.Duration)
}

// ErrNonZeroExit is returned by SyncExecutor when the process completed but
// exited with a non-zero status. The Result returned alongside this error
// still contains stdout, stderr, and the exit code — handlers may surface
// the output to callers (this service returns 200 with the body).
type ErrNonZeroExit struct {
	Code int
}

func (e *ErrNonZeroExit) Error() string {
	return fmt.Sprintf("command exited with non-zero status %d", e.Code)
}
