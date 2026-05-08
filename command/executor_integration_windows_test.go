//go:build windows

package command

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// These tests shell out to real Windows binaries (cmd.exe). They are gated
// behind the windows build tag so the rest of the suite stays cross-platform.

func mustParseT(t *testing.T, raw string) Command {
	t.Helper()
	cmd, err := ParseCommand(raw)
	if err != nil {
		t.Fatalf("ParseCommand(%q): %v", raw, err)
	}
	return cmd
}

func TestSyncExecutor_EchoSuccess(t *testing.T) {
	exec := NewSyncExecutor(5 * time.Second)
	cmd := mustParseT(t, `cmd /C echo hello`)

	result, err := exec.Run(cmd)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", result.ExitCode)
	}
	if !strings.Contains(result.Stdout, "hello") {
		t.Errorf("Stdout = %q, want substring 'hello'", result.Stdout)
	}
}

func TestSyncExecutor_NonZeroExit(t *testing.T) {
	exec := NewSyncExecutor(5 * time.Second)
	cmd := mustParseT(t, `cmd /C exit 7`)

	result, err := exec.Run(cmd)

	var nonZero *ErrNonZeroExit
	if !errors.As(err, &nonZero) {
		t.Fatalf("expected ErrNonZeroExit, got %T: %v", err, err)
	}
	if nonZero.Code != 7 {
		t.Errorf("Code = %d, want 7", nonZero.Code)
	}
	if result.ExitCode != 7 {
		t.Errorf("Result.ExitCode = %d, want 7", result.ExitCode)
	}
}

func TestSyncExecutor_Timeout(t *testing.T) {
	exec := NewSyncExecutor(500 * time.Millisecond)
	// `timeout /T 30 /NOBREAK` waits 30s; we expect the executor to kill it.
	cmd := mustParseT(t, `cmd /C timeout /T 30 /NOBREAK`)

	_, err := exec.Run(cmd)

	var timeout *ErrTimeout
	if !errors.As(err, &timeout) {
		t.Fatalf("expected ErrTimeout, got %T: %v", err, err)
	}
}

func TestSyncExecutor_SpawnFails(t *testing.T) {
	exec := NewSyncExecutor(5 * time.Second)
	cmd := mustParseT(t, `definitely_not_a_real_executable_xyz123`)

	_, err := exec.Run(cmd)

	var spawn *ErrSpawnFailed
	if !errors.As(err, &spawn) {
		t.Fatalf("expected ErrSpawnFailed, got %T: %v", err, err)
	}
}

func TestAsyncExecutor_Spawn(t *testing.T) {
	exec := NewAsyncExecutor()
	cmd := mustParseT(t, `cmd /C echo hi`)

	handle, err := exec.Start(cmd)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if handle.ID == "" {
		t.Error("expected non-empty Handle.ID")
	}
	if handle.PID == 0 {
		t.Error("expected non-zero Handle.PID")
	}
	if handle.StartedAt.IsZero() {
		t.Error("expected StartedAt to be set")
	}
}

func TestAsyncExecutor_SpawnFails(t *testing.T) {
	exec := NewAsyncExecutor()
	cmd := mustParseT(t, `definitely_not_a_real_executable_xyz123`)

	_, err := exec.Start(cmd)

	var spawn *ErrSpawnFailed
	if !errors.As(err, &spawn) {
		t.Fatalf("expected ErrSpawnFailed, got %T: %v", err, err)
	}
}
