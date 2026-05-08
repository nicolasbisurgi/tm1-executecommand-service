# Context

Domain glossary and load-bearing concepts for the `tm1-executecommand-service` codebase. New code should use these terms; reviewers should hold names accountable to these definitions.

## Deployment shape

- **TM1 v12 (SaaS)** issues `ExecuteHttpRequest` calls from IBM's egress IPs to this service.
- The service runs on the **customer's server**, alongside ODBCIS, under a least-privilege Windows service account.
- All command executions are **premeditated**: scripts are pre-deployed to designated directories. There is no ad-hoc "run anything" use case.
- Egress IPs from IBM are known and published; the IP allowlist is the first line of defence.

## Core domain terms

### Command

A parsed representation of a single execution request. Produced by `command.ParseCommand(raw string) (Command, error)`. Has four fields:

- `Wrapper` — `ShellNone | CmdC | PowerShellFile`. Preserves the customer's intent: if they sent `cmd /C foo.bat`, we run it back through `cmd`. We do not silently rewrite to a direct exec.
- `Executable` — the resolved script path (e.g. `C:\Scripts\TM1\foo.ps1`). What policy evaluates against. Quoted paths with spaces (`"C:\Program Files\..."`) are supported and unquoted at parse time.
- `Args` — everything after the executable, in original token order. Quoted args remain a single element.
- `Raw` — the original command line as received. Retained for logging and metacharacter scanning.

`Command` is the **single source of truth** for "what was the customer asking us to run." Both policy and executor consume `Command`; neither re-parses the raw string.

### Executor

A seam that turns a `Command` into a running OS process. There are **two distinct interfaces**, not one:

- `SyncExecutor.Run(cmd Command) (Result, error)` — fire and wait. Hard timeout is constructor-owned. Captures stdout and stderr into a `Result`. Used when `Wait=1`.
- `AsyncExecutor.Start(cmd Command) (Handle, error)` — fire and detach. No context, no timeout — the spawned process must outlive the HTTP request. Returns a `Handle` (id, pid, started_at). Used when `Wait=0`.

Two interfaces (rather than one with optional fields) is deliberate: it makes "cancel an async process via context" structurally impossible, which was the bug that prompted this seam.

### Result

What `SyncExecutor` returns: `{ Stdout, Stderr string; ExitCode int; Duration time.Duration }`. Stored separately so logs can differentiate; the HTTP response body still concatenates `Stdout + Stderr` for wire compatibility with existing TM1 callers.

### Handle

What `AsyncExecutor` returns: `{ ID string; PID int; StartedAt time.Time }`. The `ID` is a UUID generated unconditionally — today the handler discards it; the planned `/ExecuteCommand/status/{id}` endpoint (see `docs/ROADMAP.md`) will use it as a registry key.

### Policy

The directory + extension allowlist that decides whether a `Command` is permitted to run. Lives in `config.IsCommandPermitted(cmd Command) (allowed bool, reason string)`. Three checks:

1. `Command.Executable` extension is in `allowed_extensions`.
2. `Command.Executable` resolves to an absolute path within one of the `allowed_directories` (respecting `include_subdirs`).
3. `Command.Raw` contains no shell metacharacters (`& | ; \` > < $ \n \r`) — defence-in-depth against injection through args.

Policy is config-data-driven; the *evaluation* happens in `config/` today, which is mild architectural debt (see ROADMAP).

### Request authorization

Three middlewares answer "should this request reach the handler?":

- **RequestID** (outermost) — generates a UUID, stuffs it into `r.Context()`, sets `X-Request-ID` on the response. Every other layer reads from context. Customer-facing traceability anchor.
- **IPWhitelist** — checks `r.RemoteAddr` (or the leftmost `X-Forwarded-For` IP iff `trust_proxy=true` and the immediate peer is in `trusted_proxies`). Rejects with 403 before body parse. No `/health` bypass — health probes from disallowed IPs return 403.
- **APIKeyAuth** — constant-time compare against `Authorization: Bearer <key>`. `/health` bypasses (so external probes don't need the key).

Order in the chain: `RequestID → IPWhitelist → RateLimit → APIKeyAuth → SecurityHeaders → mux`. IPWhitelist runs before RateLimit so denied IPs can't consume rate-limiter memory.

### Wait modes

`Wait=1` (sync) and `Wait=0` (async) are the only legal values. Inherited from the TM1 v11 `ExecuteCommand` TI function. Each maps to one Executor interface — the value is never branched on inside the executor itself.

## Non-goals (today)

- Polling the status of an async process. The `Handle.ID` exists for forward-compat; the registry and status endpoint are planned (see ROADMAP).
- Killing the entire process tree on timeout. `exec.CommandContext` kills only the parent; orphaned children are accepted risk because TI scripts in scope rarely spawn children.
- Cross-OS execution. The service is Windows-only by design. Tests split: `*_test.go` runs anywhere; `*_windows_test.go` (build tag) runs only on Windows.
