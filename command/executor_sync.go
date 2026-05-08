package command

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"time"
)

// NewSyncExecutor constructs a SyncExecutor that enforces the given timeout
// on every Run. A non-positive timeout means "no timeout" — used by tests
// and explicitly opt-in.
func NewSyncExecutor(timeout time.Duration) SyncExecutor {
	return &syncExecutor{timeout: timeout}
}

type syncExecutor struct {
	timeout time.Duration
}

func (e *syncExecutor) Run(cmd Command) (Result, error) {
	ctx, cancel := e.context()
	defer cancel()

	osCmd := buildOSCmd(ctx, cmd)
	var stdout, stderr bytes.Buffer
	osCmd.Stdout = &stdout
	osCmd.Stderr = &stderr

	start := time.Now()
	runErr := osCmd.Run()
	duration := time.Since(start)

	result := Result{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: duration,
	}

	if ctx.Err() == context.DeadlineExceeded {
		return result, &ErrTimeout{Duration: e.timeout}
	}

	if runErr == nil {
		result.ExitCode = 0
		return result, nil
	}

	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, &ErrNonZeroExit{Code: result.ExitCode}
	}

	return result, &ErrSpawnFailed{Cause: runErr}
}

func (e *syncExecutor) context() (context.Context, context.CancelFunc) {
	if e.timeout <= 0 {
		return context.WithCancel(context.Background())
	}
	return context.WithTimeout(context.Background(), e.timeout)
}
