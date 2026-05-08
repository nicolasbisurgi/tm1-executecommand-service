# Implementation Plan: Security & Quality Fixes

## Context
Fix all issues identified in the code review of the `feature/logs_https_whitelist` branch before raising a PR against `Hubert-Heijkers/tm1-executecommand-service`.

Deployment model: IBM Planning Analytics (SaaS) sends requests via `ExecuteHttpRequest` TI function to this service running on the customer's server (alongside ODBCIS, which already has CA-produced TLS certs). IBM egress IPs are known and published.

**Security philosophy**: All command executions are premeditated and planned. Scripts are pre-deployed into designated directories. The service runs under a least-privilege Windows service account with restricted OS permissions. There is no ad-hoc "run whatever" use case.

---

## Phase 1: P0 — Critical Bug Fixes

### 1.1 Directory-Scoped Command Execution (config/config.go, main.go)

**Replace the regex-based command whitelist entirely** with a directory + file-extension allowlist model:

- **New config structure** (`security.command_policy`):
  ```yaml
  security:
    command_policy:
      enabled: true
      allowed_extensions:       # Only these file types can be executed
        - ".ps1"
        - ".py"
        - ".bat"
        - ".cmd"
      allowed_directories:      # Only files within these directories (resolved to absolute paths)
        - path: "C:\\Scripts\\TM1"
          include_subdirs: true
        - path: "C:\\Scripts\\Shared"
          include_subdirs: false
  ```

- **New `CommandPolicyConfig` struct** in `config/config.go`:
  ```go
  type CommandPolicyConfig struct {
      Enabled            bool                    `yaml:"enabled"`
      AllowedExtensions  []string                `yaml:"allowed_extensions"`
      AllowedDirectories []AllowedDirectoryEntry `yaml:"allowed_directories"`
  }
  type AllowedDirectoryEntry struct {
      Path           string `yaml:"path"`
      IncludeSubdirs bool   `yaml:"include_subdirs"`
  }
  ```

- **Remove** the old `CommandWhitelistConfig` struct and `compiledRegexps` field entirely
- **Remove** `IsCommandAllowed()` regex matching; replace with new `IsCommandPermitted(commandLine string) (bool, string)` that:
  1. Parses the command to extract the executable path (first token, or the path after `cmd /C` / `powershell -File`)
  2. Resolves the path to an absolute path (via `filepath.Abs`)
  3. Checks file extension is in `allowed_extensions`
  4. Checks the resolved absolute path is within one of the `allowed_directories` (respecting `include_subdirs`)
  5. Rejects shell metacharacters (`&`, `|`, `;`, `` ` ``, `>`, `<`, `$()`, `\n`, `\r`) in the full command line as a safety net
  6. Returns `(allowed bool, reason string)` for logging

- **Validation in `Validate()`**:
  - Each `allowed_directories[].path` must exist and be an actual directory
  - Each `allowed_extensions` entry must start with `.`
  - Paths are normalized to absolute form at config load time

- **Update `config.yaml`** with the new structure, remove old `command_whitelist` section

### 1.2 Fix X-Forwarded-For IP Spoofing (main.go, config/config.go)
- Change `isIPAllowed()` to use `r.RemoteAddr` by default
- Add new config options under `security.ip_whitelist`:
  ```yaml
  ip_whitelist:
    enabled: true
    allowed_ips: [...]
    trust_proxy: false           # default false
    trusted_proxies: []          # only consulted when trust_proxy is true
  ```
- Only read `X-Forwarded-For` when `trust_proxy == true` AND `r.RemoteAddr` matches a `trusted_proxies` entry
- Add `TrustProxy bool` and `TrustedProxies []string` fields to `IPWhitelistConfig`

### 1.3 Fix Fire-and-Forget Context Cancellation Bug (main.go)
- When `wait == 0`: use plain `exec.Command` (no context) so the spawned process survives after the handler returns
- When `wait == 1`: use `exec.CommandContext` with the configured timeout
- Build the command only once (remove the double-construction pattern where `exec.Command` is created then reconstructed via `exec.CommandContext`)

---

## Phase 2: P1 — Security Enhancements

### 2.1 API Key Authentication (config/config.go, server/middleware.go, main.go)
- Add config section:
  ```yaml
  security:
    authentication:
      enabled: true
      api_key: "your-secret-key-here"
  ```
- New `AuthConfig` struct: `Enabled bool`, `APIKey string`
- Validation: if enabled, key must be non-empty and >= 32 characters
- New middleware `APIKeyAuth(apiKey string)` in `server/middleware.go`:
  - Checks `Authorization: Bearer <key>` header
  - Uses constant-time comparison (`crypto/subtle.ConstantTimeCompare`) to prevent timing attacks
  - Returns 401 Unauthorized with generic message on failure
  - Skips auth for `/health` endpoint
- Wire into `createServeMux()` in `server.go`, applied before `SecurityHeaders`

### 2.2 Generic Error Responses (main.go)
- Replace detailed error messages to clients:
  - "command not allowed by whitelist: ..." → `"Command not permitted"` (403)
  - Command execution errors → `"Command execution failed"` (500)
- Keep detailed error info in log entries only (already happening via logger)
- Use 403 Forbidden (not 500) for policy-rejected commands

### 2.3 Rate Limiting (server/middleware.go)
- Config section:
  ```yaml
  security:
    rate_limit:
      enabled: true
      requests_per_minute: 60
  ```
- New `RateLimitConfig` struct: `Enabled bool`, `RequestsPerMinute int`
- Implement per-IP token bucket using `sync.Map` + atomic counters (no external deps)
- New middleware `RateLimit(cfg RateLimitConfig)` in `server/middleware.go`
- Returns 429 Too Many Requests when limit exceeded
- Periodic cleanup goroutine to evict stale entries (every 5 minutes)
- Wire into `createServeMux()` as outermost middleware

---

## Phase 3: P2 — Correctness & Design Improvements

### 3.1 Register `/health` Endpoint (main.go)
- Add health handler returning `200 OK` with `{"status":"ok"}`
- Register via `srv.RegisterHandler("/health", healthHandler)`
- The self-warm goroutine in `server.go` will now get 200s instead of 404s

### 3.2 Fix Port Logic in `runServer()` (main.go)
- Simplify:
  ```go
  httpPort := strconv.Itoa(cfg.Server.HTTPPort)
  httpsPort := ""
  if cfg.Security.HTTPS.Enabled {
      httpsPort = strconv.Itoa(cfg.Security.HTTPS.Port)
  }
  ```
- Remove the confusing initial `httpsPort = strconv.Itoa(cfg.Server.HTTPPort)` assignment

### 3.3 Reduce Global Mutable State (main.go)
- Create `App` struct:
  ```go
  type App struct {
      cfg       *config.Config
      ipChecker *ip.IPChecker
      logger    *logger.CommandLogger
  }
  ```
- `commandHandler` becomes a method on `App`: `func (app *App) commandHandler(...)`
- `isIPAllowed` becomes a method on `App`: `func (app *App) isIPAllowed(...)`
- Tests create their own `App` instances instead of mutating package-level globals
- Keep `elog` as package-level (it's the Windows event log, only used at startup)

### 3.4 Add Missing Tests
All tests remain **Windows-only** (using `cmd /C` patterns).

- **`config/config_test.go`** (NEW):
  - `TestValidate()`: valid config, invalid port, invalid timeout, missing HTTPS certs
  - `TestLoadConfig()`: valid file, missing file (auto-creates), invalid YAML
  - `TestSaveToFile()`: round-trip save/load
  - `TestIsCommandPermitted()`: allowed file in allowed dir, wrong extension, wrong dir, subdir allowed/denied, shell metacharacters blocked, path traversal (`..`) blocked
  - `TestAllowedDirectoryValidation()`: non-existent dir, relative path resolution

- **`main_test.go` updates**:
  - Add directory-scoped command policy tests (script in allowed dir vs. outside)
  - Add X-Forwarded-For spoofing test (verify ignored when `trust_proxy=false`)
  - Update `setupTestEnvironment()` for `App` struct

- **`server/middleware_test.go` additions**:
  - `TestAPIKeyAuth()`: valid key, invalid key, missing header, wrong scheme, health endpoint bypass
  - `TestRateLimit()`: under limit passes, over limit returns 429, per-IP isolation, reset after window

---

## Phase 4: P3 — Cleanup & Modernization

### 4.1 Fix Deprecated TLS Options (server/server.go)
- Remove `PreferServerCipherSuites: true` (no-op since Go 1.17)
- Remove `ClientSessionCache` (client-side option, no effect on server)

### 4.2 HSTS Only on HTTPS (server/middleware.go)
- Change `SecurityHeaders` signature to `SecurityHeaders(httpsEnabled bool) func(http.HandlerFunc) http.HandlerFunc`
- Only set `Strict-Transport-Security` when `httpsEnabled == true`
- Update call sites in `server.go` to pass the HTTPS config flag

### 4.3 Update Go Version (go.mod)
- Bump `go 1.19` → `go 1.21`
- Run `go mod tidy`
- Fix `uuid` from `// indirect` to direct dependency

### 4.4 Remove Redundant `waitForPort` (server/server.go)
- Listener creation success is sufficient verification
- Remove `waitForPort()` method and all calls
- Signal readiness immediately after successful `net.Listen()`

### 4.5 Add Missing Newline at EOF (main.go)

---

## File Change Summary

| File | Changes |
|------|---------|
| `config/config.go` | Replace `CommandWhitelistConfig` with `CommandPolicyConfig`, add `AuthConfig`, `RateLimitConfig`, `TrustProxy`/`TrustedProxies` to IP whitelist, new `IsCommandPermitted()`, update `Validate()` |
| `config/config.yaml` | Replace `command_whitelist` with `command_policy` (dirs + extensions), add `authentication`, `rate_limit`, `trust_proxy` sections |
| `config/config_test.go` | **NEW** — comprehensive config validation and command policy tests |
| `main.go` | `App` struct, fix port logic, fix context bug, generic errors, health endpoint, use `IsCommandPermitted()`, fix EOF |
| `main_test.go` | Update for `App` struct, add directory-scoped policy tests, IP spoofing tests |
| `server/middleware.go` | Add `APIKeyAuth`, `RateLimit` middlewares; `SecurityHeaders` takes `httpsEnabled` param |
| `server/middleware_test.go` | Add auth middleware tests, rate limit tests |
| `server/server.go` | Remove deprecated TLS opts, remove `waitForPort`, wire new middlewares, pass `httpsEnabled` to `SecurityHeaders` |
| `server/server_test.go` | Update for new middleware signatures |
| `ip/validation.go` | No changes |
| `ip/validation_test.go` | No changes |
| `logger/logger.go` | No changes |
| `go.mod` | Bump to go 1.21, fix uuid dependency |

## Implementation Order
Phases are sequential (1→2→3→4). Within each phase, tasks are independent and can be done in any order. Tests for each feature are written alongside the feature in the same phase.

## What Does NOT Change
- `ip/` package — already solid
- `logger/` package — working well
- Windows service support — preserved as-is
- README.md — will be updated after all code changes are complete (separate commit)
