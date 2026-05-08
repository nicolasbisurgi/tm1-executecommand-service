@echo off
REM Sleeps ~9s, exceeding command_timeout_seconds: 5 in the test config.
REM We deliberately keep this short because Go's exec.CommandContext on
REM Windows kills only the parent (cmd.exe), not the spawned child (ping).
REM Until process-tree kill lands (see docs/ROADMAP.md::TD5), the executor's
REM cmd.Wait() blocks until the orphan child closes the inherited stdout/stderr
REM pipes — which happens when ping finishes naturally. So total request
REM duration ≈ ping duration, regardless of when the timeout fires.
REM
REM Keeping the wait short avoids tripping connection-level idle limits in
REM Tailscale/NAT/keepalives.
ping -n 9 127.0.0.1 >nul
echo should not be reached
