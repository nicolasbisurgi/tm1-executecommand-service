# Implementation Plan: Architectural Deepening

Follow-up to `.claude/plan.md`. Three deepening refactors before raising the upstream PR against `Hubert-Heijkers/tm1-executecommand-service`:

- **#1** `Command` value module — collapse two parsers into one, parse once.
- **#2** `Executor` seam — split sync/async into adapters of distinct interfaces.
- **#3** Request-authorization middlewares — `RequestID` + `IPWhitelist`, lifted out of the handler.

Plus deferred items tracked in `docs/ROADMAP.md` and domain glossary in `CONTEXT.md`.

---

## Locked decisions

| Decision | Choice |
|---|---|
| Quoted paths with spaces | Supported (`"C:\Program Files\foo.bat" arg`) |
| `Command` constructor | `ParseCommand(raw)` only — no public struct literal |
| Shell wrapper handling | Preserved in `Command.Wrapper` (`CmdC`, `PowerShellFile`, `None`) |
| Shell metacharacter rejection | Stays strict on raw input — current behavior preserved |
| Package layout | `command/` owns `Command` + executors; policy stays in `config/` |
| Sync/async interfaces | Two distinct interfaces, distinct return shapes |
| Sync timeout | Constructor-owned (`NewSyncExecutor(timeout)`) — no ctx parameter |
| Output capture | Split internally into stdout/stderr; HTTP body still concatenates for wire compat |
| Typed errors | `ErrTimeout`, `ErrSpawnFailed`, `ErrNonZeroExit{Code}`, `ErrPolicyRejected{Reason}` |
| `AsyncExecutor` return | `Handle{ID, PID, StartedAt}` — ID generated today, registry deferred (see ROADMAP R1) |
| Process-tree kill | Deferred (TD5) |
| Middleware chain | `RequestID → IPWhitelist → RateLimit → APIKeyAuth → SecurityHeaders → mux` |
| `IPWhitelist` `/health` bypass | No bypass |
| Request ID propagation | `r.Context()` value + `X-Request-ID` response header |
| Test split | Pure tests cross-platform; integration tests behind `//go:build windows` tag |

---

## Phase 0: Documentation scaffolding

Already done as part of this planning round:

- `CONTEXT.md` — domain glossary (Command, Executor, Result, Handle, Policy, Request authorization, Wait modes).
- `docs/ROADMAP.md` — async registry/polling (R1), JSON envelope (R2), cross-platform CI (R3), tech debt items (TD1–TD7).

---

## Phase 1: `Command` value module

### 1.1 New package `command/`

**File: `command/command.go`**

```go
package command

type ShellWrapper int

const (
    ShellNone ShellWrapper = iota
    ShellCmdC
    ShellPowerShellFile
)

type Command struct {
    Wrapper    ShellWrapper
    Executable string   // resolved exec path, unquoted
    Args       []string // tokens after exec, quoted args remain single tokens
    Raw        string   // original input
}

// ParseCommand parses a raw command line into a structured Command.
// Recognises `cmd /C ...` and `powershell -File ...` wrappers (case-insensitive).
// Honours double-quoted tokens (Windows convention) for paths with spaces.
func ParseCommand(raw string) (Command, error) { ... }
```

**Parsing rules**:
1. Trim leading/trailing whitespace from `raw`.
2. Detect wrapper prefix (case-insensitive): `cmd /c `, `cmd.exe /c `, `powershell -file `, `powershell.exe -file `. If matched, strip and set `Wrapper`.
3. Tokenise the remainder with a small Windows-style quoted-token splitter:
   - `"foo bar"` → one token `foo bar`
   - Backslash-escape inside quotes is **not** honoured (Windows shell doesn't honour it consistently anyway; keep simple).
   - Unbalanced quote → `error`.
4. First token → `Executable`. Rest → `Args`.
5. Empty `Executable` after parsing → `error`.

**File: `command/command_test.go`** (cross-platform, no shell-out)

Test cases:
- Bare exec: `C:\Scripts\foo.bat` → `{None, "C:\\Scripts\\foo.bat", [], raw}`
- Bare exec + args: `C:\Scripts\foo.bat a b` → `Args: [a, b]`
- `cmd /C` wrapper: `cmd /C C:\Scripts\foo.bat a` → `{CmdC, exec, [a], raw}`
- `powershell -File`: `powershell -File C:\Scripts\foo.ps1 a` → `{PowerShellFile, ...}`
- Quoted exec path: `"C:\Program Files\Foo\bar.bat" a` → `Executable: "C:\\Program Files\\Foo\\bar.bat"`
- Quoted exec under wrapper: `cmd /C "C:\Program Files\Foo\bar.bat" a`
- Empty input → error
- Unbalanced quote → error
- Wrapper with no exec: `cmd /C` → error

### 1.2 Update `config.IsCommandPermitted`

Change signature: `func (c *Config) IsCommandPermitted(cmd command.Command) (bool, string)`.

Internal change:
- Use `cmd.Executable` for extension check and absolute-path resolution.
- Use `cmd.Raw` for shell-metacharacter scan.
- No string-parsing in this method anymore.

Note circular-import risk: `config/` would import `command/`. If `command/` ever needs `config` types, we have a cycle. To avoid: `command/` stays leaf, depends on nothing in this repo. ✅ as designed.

### 1.3 Update callers

`main.go::executeCommand` and `commandHandler` (after Phase 2 reshapes them) call `command.ParseCommand` once and hand the `Command` to both policy and executor.

---

## Phase 2: `Executor` seam

### 2.1 Interfaces and value types

**File: `command/executor.go`**

```go
package command

type SyncExecutor interface {
    Run(cmd Command) (Result, error)
}

type AsyncExecutor interface {
    Start(cmd Command) (Handle, error)
}

type Result struct {
    Stdout   string
    Stderr   string
    ExitCode int
    Duration time.Duration
}

type Handle struct {
    ID        string    // UUID; today discarded by handler, used by registry tomorrow
    PID       int
    StartedAt time.Time
}
```

### 2.2 Errors

**File: `command/errors.go`**

```go
type ErrTimeout struct{ Duration time.Duration }
type ErrSpawnFailed struct{ Cause error }
type ErrNonZeroExit struct{ Code int }
type ErrPolicyRejected struct{ Reason string }

func (e *ErrTimeout) Error() string       { ... }
// etc — implement Unwrap where applicable
```

Handler maps via `errors.As`. Behavioural decision recorded:

| Typed error | HTTP status | Body |
|---|---|---|
| `ErrPolicyRejected` | 403 | `Command not permitted` |
| `ErrTimeout` | 500 | `Command execution failed` *(generic — see TD7)* |
| `ErrSpawnFailed` | 500 | `Command execution failed` |
| `ErrNonZeroExit` | 200 | `result.Stdout + result.Stderr` *(callers see the failing script's output; behavioural change vs current 500-with-body-discarded)* |
| Anything else | 500 | `Command execution failed` |

### 2.3 SyncExecutor implementation

**File: `command/executor_sync.go`**

```go
type syncExecutor struct {
    timeout time.Duration
}

func NewSyncExecutor(timeout time.Duration) SyncExecutor { ... }

func (e *syncExecutor) Run(cmd Command) (Result, error) {
    ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
    defer cancel()

    osCmd := buildOsCommand(ctx, cmd) // applies wrapper
    var stdout, stderr bytes.Buffer
    osCmd.Stdout = &stdout
    osCmd.Stderr = &stderr

    start := time.Now()
    err := osCmd.Run()
    duration := time.Since(start)

    if ctx.Err() == context.DeadlineExceeded {
        return Result{...}, &ErrTimeout{Duration: e.timeout}
    }
    if exitErr, ok := err.(*exec.ExitError); ok {
        return Result{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: exitErr.ExitCode(), Duration: duration},
            &ErrNonZeroExit{Code: exitErr.ExitCode()}
    }
    if err != nil {
        return Result{...}, &ErrSpawnFailed{Cause: err}
    }
    return Result{Stdout: ..., Stderr: ..., ExitCode: 0, Duration: duration}, nil
}
```

`buildOsCommand(ctx, cmd Command) *exec.Cmd`:
- `ShellCmdC`: `exec.CommandContext(ctx, "cmd", append([]string{"/C", cmd.Executable}, cmd.Args...)...)`
- `ShellPowerShellFile`: `exec.CommandContext(ctx, "powershell", append([]string{"-File", cmd.Executable}, cmd.Args...)...)`
- `ShellNone`: `exec.CommandContext(ctx, cmd.Executable, cmd.Args...)`

### 2.4 AsyncExecutor implementation

**File: `command/executor_async.go`**

```go
type asyncExecutor struct{}

func NewAsyncExecutor() AsyncExecutor { return &asyncExecutor{} }

func (e *asyncExecutor) Start(cmd Command) (Handle, error) {
    osCmd := buildOsCommandNoCtx(cmd) // same shape as buildOsCommand but exec.Command, no ctx
    if err := osCmd.Start(); err != nil {
        return Handle{}, &ErrSpawnFailed{Cause: err}
    }
    return Handle{
        ID:        uuid.NewString(),
        PID:       osCmd.Process.Pid,
        StartedAt: time.Now(),
    }, nil
}
```

No context, no `Wait`, no goroutine — process is fully detached. (Registry/poll lives in ROADMAP R1.)

### 2.5 Fakes

**File: `command/executor_fake.go`** (test helpers, not gated)

```go
type FakeSync struct {
    OnRun func(cmd Command) (Result, error)
}
func (f *FakeSync) Run(cmd Command) (Result, error) { return f.OnRun(cmd) }

type FakeAsync struct {
    OnStart func(cmd Command) (Handle, error)
}
func (f *FakeAsync) Start(cmd Command) (Handle, error) { return f.OnStart(cmd) }
```

`commandHandler` tests inject these. No real `cmd /C echo` needed.

### 2.6 Integration tests (Windows-only)

**File: `command/executor_integration_windows_test.go`**

```go
//go:build windows
package command
```

- `TestSyncExecutor_Echo`: `cmd /C echo hello` → exit 0, stdout `hello\r\n`
- `TestSyncExecutor_NonZeroExit`: `cmd /C exit 7` → `ErrNonZeroExit{7}`
- `TestSyncExecutor_Timeout`: `cmd /C timeout /T 30` with 1s timeout → `ErrTimeout`
- `TestAsyncExecutor_Spawn`: `cmd /C echo hi` → handle with valid PID, started_at
- `TestAsyncExecutor_SpawnFails`: nonexistent exec → `ErrSpawnFailed`

### 2.7 `App` and handler restructure

**`main.go`**:

```go
type App struct {
    cfg    *config.Config
    logger *logger.CommandLogger
    sync   command.SyncExecutor
    async  command.AsyncExecutor
}
```

`ipChecker` moves out of `App` (Phase 3 — into the IP middleware).

`commandHandler` shrinks: parse HTTP → `ParseCommand` → policy check → dispatch to `app.sync` or `app.async` based on `wait` → write response. The 100-line `executeCommand` function disappears.

HTTP body construction:
- Sync success: `w.Write([]byte(result.Stdout + result.Stderr))`
- Async success: `w.Write([]byte("Command started successfully"))` (compat)
- Errors: typed-error switch → `http.Error` with generic message.

---

## Phase 3: Request authorization middlewares

### 3.1 RequestID middleware

**File: `server/middleware.go`** (additions)

```go
type ctxKey int
const requestIDKey ctxKey = 0

func RequestID(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        id := uuid.NewString()
        w.Header().Set("X-Request-ID", id)
        ctx := context.WithValue(r.Context(), requestIDKey, id)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// RequestIDFrom retrieves the request ID set by the RequestID middleware.
// Returns empty string if not present.
func RequestIDFrom(ctx context.Context) string { ... }
```

### 3.2 IPWhitelist middleware

**File: `server/middleware.go`** (additions)

```go
func IPWhitelist(checker *ip.IPChecker, trustProxy bool, trustedProxies []string, log *logger.CommandLogger) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            clientIP := resolveClientIP(r, trustProxy, trustedProxies)
            if !checker.IsAllowed(clientIP) {
                requestID := RequestIDFrom(r.Context())
                log.LogIPRejected(r, clientIP, requestID) // new log method or reuse existing with allowed=false
                http.Error(w, "Access denied", http.StatusForbidden)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}

func resolveClientIP(r *http.Request, trustProxy bool, trustedProxies []string) string { ... }
```

`resolveClientIP` is the moved-and-inlined version of `App.getClientIP`.

**Logging fidelity** (your 3.4 question): the rejected request still gets logged with:
- Source IP (resolved)
- Request ID (from context)
- Method, path, user agent
- *No* command line — body is unread by design

The customer says "request `abc-123` was blocked"; ops greps `abc-123` and sees the IP rejection.

### 3.3 Update `commandHandler`

Remove:
- `app.isIPAllowed(r)` call
- `app.getClientIP(r)`
- `App.ipChecker` field
- `App.isIPAllowed`, `App.getClientIP` methods

Read request_id from context:
```go
requestID := server.RequestIDFrom(r.Context())
```

`logger.LogHTTPRequestReceived` signature changes: no longer generates request_id, accepts it as parameter. Returns only `threadID` (still atomic-counter-generated).

### 3.4 Update `server.createServeMux`

```go
func (s *Server) createServeMux() http.Handler {
    mux := http.NewServeMux()
    for path, handler := range s.handlers {
        mux.HandleFunc(path, handler)
    }

    var h http.Handler = mux
    h = SecurityHeaders(s.config.Security.HTTPS.Enabled, h)

    if s.config.Security.Authentication.Enabled {
        h = APIKeyAuth(s.config.Security.Authentication.APIKey, h)
    }
    if s.config.Security.RateLimit.Enabled {
        h = RateLimit(s.config.Security.RateLimit.RequestsPerMinute, h)
    }
    if s.config.Security.IPWhitelist.Enabled {
        h = IPWhitelist(s.ipChecker, s.config.Security.IPWhitelist.TrustProxy, s.config.Security.IPWhitelist.TrustedProxies, s.logger)(h)
    }
    h = RequestID(h)
    return h
}
```

`Server` now needs `ipChecker *ip.IPChecker` field. Constructed in `main.go` and passed to `NewServer`.

### 3.5 Tests

**File: `server/middleware_test.go`** (additions)

- `TestRequestID`: middleware sets `X-Request-ID` header, value is a valid UUID, value matches what's in `r.Context()`.
- `TestIPWhitelist_Allow`: allowed IP passes through.
- `TestIPWhitelist_Deny`: disallowed IP gets 403, handler not called.
- `TestIPWhitelist_TrustProxyHonoured`: `X-Forwarded-For` consulted only when proxy IP is in trusted list.
- `TestIPWhitelist_TrustProxySpoofIgnored`: `X-Forwarded-For` ignored when peer is not a trusted proxy.
- `TestIPWhitelist_NoHealthBypass`: `/health` from disallowed IP returns 403.
- `TestRequestID_HandlerCanReadFromContext`: integration — `RequestID` wraps a handler that reads `RequestIDFrom(ctx)` and confirms equality.

---

## File change summary

| File | Action |
|---|---|
| `CONTEXT.md` | NEW (Phase 0) |
| `docs/ROADMAP.md` | NEW (Phase 0) |
| `command/command.go` | NEW |
| `command/command_test.go` | NEW |
| `command/executor.go` | NEW |
| `command/executor_sync.go` | NEW |
| `command/executor_async.go` | NEW |
| `command/executor_fake.go` | NEW |
| `command/errors.go` | NEW |
| `command/executor_integration_windows_test.go` | NEW (build tag) |
| `config/config.go` | `IsCommandPermitted` takes `command.Command`; remove inline executable parsing |
| `config/config_test.go` | Update test inputs to construct `Command` via `ParseCommand` |
| `server/middleware.go` | Add `RequestID`, `RequestIDFrom`, `IPWhitelist`, `resolveClientIP` |
| `server/middleware_test.go` | Add tests for both new middlewares |
| `server/server.go` | `Server` holds `ipChecker`; `createServeMux` adds RequestID + IPWhitelist |
| `server/server_test.go` | Update setup for `ipChecker` field |
| `main.go` | `App` gains `sync`/`async` executors, loses `ipChecker`/`isIPAllowed`/`getClientIP`; `commandHandler` shrinks; `executeCommand` deleted |
| `main_test.go` | Use `command.FakeSync`/`FakeAsync`; remove dependency on real `cmd /C echo`; existing integration-flavoured tests gated `//go:build windows` |
| `logger/logger.go` | `LogHTTPRequestReceived` accepts request_id, no longer generates it |
| `go.mod` | `uuid` already present (used by logger); confirm direct dep |

---

## Implementation order

Strict: 0 → 1 → 2 → 3. Within Phase 2, sub-steps `2.1 → 2.2 → 2.3/2.4 (parallel) → 2.5 → 2.6 → 2.7`.

**Why strict**: Phase 2 needs Phase 1's `Command` type. Phase 3's `commandHandler` simplification assumes Phase 2's executors are wired. Doing them out of order means redoing handler code twice.

After Phase 3, run:
- `go build ./...` on Mac (must succeed — proves no Windows-only code leaked into shared paths)
- `go test ./...` on Mac (cross-platform tests pass)
- `go test ./... -tags=integration` on Windows test machine (integration tests pass) — manual until ROADMAP R3.

---

## Out of scope for this PR

Tracked in `docs/ROADMAP.md`:
- Async registry + status/output/cancel endpoints (R1)
- JSON envelope HTTP response (R2)
- GitHub Actions Windows runner + Mac→Windows test scripts (R3)
- Configurable middleware chain (R4)
- TD1–TD7 (config/policy split, logger singleton, Server.Start sentinel, process-tree kill, etc.)

If any of these surface as blockers during implementation, raise as a separate plan rather than expanding this one.
