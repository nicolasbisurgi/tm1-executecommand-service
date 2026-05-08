# Roadmap & Technical Debt

Forward-looking work and known compromises. Pulled out of the deepening-refactor PR (`feature/logs_https_whitelist`) so the PR itself stays focused.

---

## Roadmap (planned features)

### R1. Async process registry + polling endpoints

**Why**: enables rushti to use this service as a node that runs commands alongside TI processes and chores — fire-and-poll instead of fire-and-forget.

**Shape**:
- In-memory registry keyed by `Handle.ID` (UUID). Maps id → `{ pid, started_at, status, exit_code, stdout, stderr, completed_at }`.
- `AsyncExecutor.Start` spawns a goroutine that calls `cmd.Wait()`, captures exit + buffered output, updates registry.
- New endpoints:
  - `GET /ExecuteCommand/status/{id}` → `{status: "running"|"completed"|"failed"|"not_found", exit_code, started_at, completed_at}`
  - `GET /ExecuteCommand/output/{id}` → captured stdout/stderr (subject to a max-buffer cap)
  - `DELETE /ExecuteCommand/{id}` → kill in-flight (optional; tree-kill considerations apply)
- Retention: TTL (e.g. 1h after completion) + max-entries cap. Stale entries GC'd by a background sweep.
- State is **in-memory only** — vanishes on restart. Persistent registry (sqlite, BoltDB) is a further follow-up if required.

**Forward-compat**: `Handle.ID` is already generated today; the registry slots in without changing the AsyncExecutor interface.

### R2. JSON envelope HTTP response

**Why**: cleaner separation of stdout/stderr/exit_code on the wire, instead of concatenating into the body.

**Blocker**: requires a TM1-side parser (the upcoming "TM1 JSON formatter"). Until that lands, the body stays as `stdout + stderr` concatenation for compat with existing callers.

**When ready**: introduce a content-negotiation switch — `Accept: application/json` returns the envelope; default `text/plain` keeps current behavior.

### R3. Cross-platform CI + Mac→Windows test scripts

**Why**: today the integration tests can only run on a Windows host, so contributors on macOS/Linux can't run the full suite locally.

**Two parts**:
- **GitHub Actions workflow** with a `windows-latest` runner that runs `go test ./... -tags=integration`.
- **Local Mac→Windows scripts** — the developer has a Windows test machine. A small shell helper (`scripts/test-on-windows.sh`) that rsync's the working tree to the Windows box (over SSH or a shared mount) and runs `go test` there. Optional but unblocks rapid iteration on integration tests.

**Today's mitigation**: build tags split unit tests (cross-platform, mockable) from integration tests (Windows-only). See plan-deepening §Phase 2.

### R4. Configurable middleware chain

Today `server.createServeMux` has the chain hardcoded with `if cfg.X.Enabled` branches. If a second deployment shape ever appears (different auth scheme, custom middleware), the function rots. Defer until that second shape exists.

---

## Technical debt (known deferrals)

### TD1. `config/` package straddles schema and policy

`config.IsCommandPermitted` does policy *evaluation*, which conceptually belongs in a `policy/` package consuming config types. Today it stays in `config/` to keep the deepening PR small. Cost: config tests can't be written without exercising executable parsing; policy tests pull in YAML.

**When to fix**: when a second policy emerges (e.g. user-scoped, role-based) or when config validation gets complex enough that the policy noise hurts.

### ~~TD2. Logger half-singleton~~ — RESOLVED

Resolved during the deepening PR. `var instance *CommandLogger` and `GetLogger()` were removed from `logger/logger.go`; `InitLogger` no longer assigns the global. The `App` struct is the sole owner.

### TD3. `Server.Start(httpPort, httpsPort string)` empty-string sentinel

Caller signals "HTTPS off" by passing `""` as `httpsPort`. The convention is implicit. Better shape: pass typed `*config.HTTPSConfig` or a `*ListenSpec`-with-nil.

**When to fix**: any future change to `Server.Start`'s signature; not worth a standalone refactor.

### TD4. Hardcoded middleware composition (also see R4)

Same shape as R4 — deferred until a second deployment shape forces it.

### TD5. Process-tree kill on timeout

When `SyncExecutor`'s timeout fires, `exec.CommandContext` SIGKILLs the parent only. A `.bat` that spawned children leaves orphans. Mitigation would require `CREATE_NEW_PROCESS_GROUP` + `taskkill /T /F` on Windows.

**When to fix**: if customer scripts in scope start spawning child processes that need cleanup. Today's TI scripts don't; accepted risk.

### TD6. Combined-output wire format loses interleaving

Splitting stdout/stderr into separate buffers means the response body is `stdout + stderr` end-to-end, not interleaved in temporal order as `CombinedOutput` would produce. For most scripts the difference is invisible (stdout-only, or stderr-only on failure). Scripts that interleave heavily will see reordering.

**When to fix**: rolled into R2 (JSON envelope) — at that point we expose them as separate fields and the temporal-merge problem disappears.

### TD7. ErrTimeout maps to generic 500

Per the existing security philosophy ("generic error responses"), timeout doesn't surface as a distinct status code. Operationally diagnosable only via the request_id in logs. If customers start asking "why are some calls slow?" without log access, consider 504 with a generic body.

---

## Status legend (for future tracking)

Each entry can later be tagged with:
- `status: planned` — agreed, not yet scheduled
- `status: in-progress` — assigned + branch open
- `status: blocked-by-X` — gated externally
- `status: deferred-indefinitely` — accepted as permanent debt

(Not applied yet — populate as items move.)
