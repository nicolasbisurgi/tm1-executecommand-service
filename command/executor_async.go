package command

import (
	"time"

	"github.com/google/uuid"
)

// NewAsyncExecutor constructs an AsyncExecutor that spawns processes
// detached — no goroutine waits, no context cancels. The returned Handle
// captures identity (ID, PID) for forward-compatibility with the registry
// planned in ROADMAP R1.
func NewAsyncExecutor() AsyncExecutor {
	return &asyncExecutor{}
}

type asyncExecutor struct{}

func (e *asyncExecutor) Start(cmd Command) (Handle, error) {
	osCmd := buildOSCmd(nil, cmd)
	if err := osCmd.Start(); err != nil {
		return Handle{}, &ErrSpawnFailed{Cause: err}
	}
	return Handle{
		ID:        uuid.NewString(),
		PID:       osCmd.Process.Pid,
		StartedAt: time.Now(),
	}, nil
}
