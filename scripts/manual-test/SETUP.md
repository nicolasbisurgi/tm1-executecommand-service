# Mac → Windows Manual Test Setup

End-to-end smoke test for `tm1-executecommand-service` running on a Windows host, exercised from a Mac over Tailscale.

| Layer | Value |
|---|---|
| Windows host | `100.84.94.15` (Tailscale IP) |
| Service port | `9092` |
| API key | `test-api-key-that-is-at-least-32-chars-long!!` |
| Allowed scripts dir | `C:\Scripts\TM1\` (with subdirs allowed) |
| "Outside" scripts dir | `C:\Scripts\Outside\` (NOT allowed — used to test rejection) |

This directory contains everything needed to run the test end-to-end:

```
scripts/manual-test/
├── config.yaml                 # deployment config for the Windows host
├── SETUP.md                    # this file
├── test-from-mac.sh            # automated test runner (run from Mac)
├── test-scripts/               # deploy contents to C:\Scripts\TM1\
│   ├── echo.bat
│   ├── exit-7.bat
│   ├── long-running.bat
│   ├── fake.txt                #   wrong-extension test fixture
│   └── sub/
│       └── nested.bat
└── test-scripts-outside/       # deploy contents to C:\Scripts\Outside\
    └── blocked.bat
```

---

## Step 1 — Build the Windows binary (on Mac)

From the repo root on your Mac:

```bash
GOOS=windows GOARCH=amd64 go build -o tm1-executecommand-service.exe .
```

This produces a ~10 MB `tm1-executecommand-service.exe` you can copy to the Windows host.

## Step 2 — Lay out files on the Windows host

> **⚠ Critical:** the `config.yaml` you copy to `C:\TM1ExecCmd\` MUST be `scripts/manual-test/config.yaml` (the test config), not the repo-root `config/config.yaml`. The two have different security settings and the test suite is calibrated for the test config. Mixing them up produces a cascade of misleading test failures.

Create the directories and copy files:

```powershell
# In an elevated PowerShell on the Windows host
mkdir C:\TM1ExecCmd\logs
mkdir C:\Scripts\TM1\sub
mkdir C:\Scripts\Outside

# Copy the binary (from wherever you transferred it):
Copy-Item .\tm1-executecommand-service.exe C:\TM1ExecCmd\

# Copy the TEST config (from scripts/manual-test/, NOT from repo-root config/):
Copy-Item .\config.yaml C:\TM1ExecCmd\

# Copy test scripts (verify echo.bat is in the list — easy to miss):
Copy-Item .\test-scripts\echo.bat          C:\Scripts\TM1\
Copy-Item .\test-scripts\exit-7.bat        C:\Scripts\TM1\
Copy-Item .\test-scripts\long-running.bat  C:\Scripts\TM1\
Copy-Item .\test-scripts\fake.txt          C:\Scripts\TM1\
Copy-Item .\test-scripts\sub\nested.bat    C:\Scripts\TM1\sub\
Copy-Item .\test-scripts-outside\blocked.bat C:\Scripts\Outside\

# Verify everything is in place:
dir C:\Scripts\TM1\         # should show: echo.bat, exit-7.bat, fake.txt, long-running.bat, sub
dir C:\Scripts\TM1\sub\     # should show: nested.bat
dir C:\Scripts\Outside\     # should show: blocked.bat

# Verify the deployed config is the test config (not the dev config):
Get-Content C:\TM1ExecCmd\config.yaml | Select-String "command_timeout_seconds|enabled" -Context 0,0
# Expected highlights:
#   command_timeout_seconds: 5         (NOT 15 — that's the dev config)
#   authentication: enabled: true      (NOT false)
#   command_policy: enabled: true      (NOT false)
```

Quickest transfer methods over Tailscale: `scp` (if OpenSSH server is enabled on Windows), Tailscale Drive, or a one-shot HTTP server (`python3 -m http.server` on Mac, `Invoke-WebRequest` on Windows).

## Step 3 — Open the firewall (Windows)

```powershell
# Elevated PowerShell
New-NetFirewallRule -DisplayName "TM1 ExecCmd 9092" -Direction Inbound `
  -Protocol TCP -LocalPort 9092 -Action Allow -Profile Any
```

If you already have a Tailscale-only network profile, scope the rule with `-Profile Private` or similar.

## Step 4 — Run the service

### Option A — Foreground (recommended for first test)

```powershell
cd C:\TM1ExecCmd
.\tm1-executecommand-service.exe --config=config.yaml
```

You should see:

```
Starting ExecuteCommand service on port 9092...
```

Logs stream to `C:\TM1ExecCmd\logs\tm1executecommandservice.log`.

### Option B — Install as a Windows service

```powershell
# Elevated PowerShell, after Option A works
sc.exe create "TM1-ExecuteCommand-Service" `
  binPath= "C:\TM1ExecCmd\tm1-executecommand-service.exe --config=C:\TM1ExecCmd\config.yaml" `
  start= auto `
  obj= "NT AUTHORITY\NetworkService"

sc.exe start "TM1-ExecuteCommand-Service"
```

To remove later:

```powershell
sc.exe stop   "TM1-ExecuteCommand-Service"
sc.exe delete "TM1-ExecuteCommand-Service"
```

> The service account (`NetworkService` above) needs **read + execute** on `C:\Scripts\TM1`. If the Windows account that owns those files differs, grant explicit ACLs:
> ```powershell
> icacls C:\Scripts\TM1 /grant "NT AUTHORITY\NetworkService:(OI)(CI)RX"
> ```

## Step 5 — Verify reachability from Mac

```bash
curl -fsS http://100.84.94.15:9092/health
# Expected: {"status":"ok"}
```

If this hangs or fails:
- Confirm Tailscale is up on both ends: `tailscale status`
- Confirm the service is listening: on Windows, `Get-NetTCPConnection -LocalPort 9092`
- Confirm firewall: try from Windows itself with `curl http://localhost:9092/health` first
- Check service logs: `Get-Content -Tail 50 C:\TM1ExecCmd\logs\tm1executecommandservice.log`

## Step 6 — Run the automated test suite from Mac

```bash
cd scripts/manual-test
./test-from-mac.sh
```

You should see ~24 tests, all green:

```
── Health endpoint ──
PASS  01 /health returns 200
PASS  02 /health body is {"status":"ok"}
── X-Request-ID middleware ──
PASS  03 X-Request-ID header is set
...

──────────────────────────────────────────────
Total: 24   Pass: 24   Fail: 0
```

**Override defaults via env vars:**

```bash
SERVICE_HOST=100.84.94.15 SERVICE_PORT=9092 \
  API_KEY="test-api-key-that-is-at-least-32-chars-long!!" \
  ./test-from-mac.sh
```

## What the test runner covers

| # | Area | Verifies |
|---|------|----------|
| 01–02 | Health endpoint | reachability + body |
| 03–05 | RequestID middleware | header presence, UUID format, freshness |
| 06–09 | APIKeyAuth | missing/wrong/wrong-scheme rejected; `/health` bypasses |
| 10 | Sync execution | echo.bat returns stdout |
| 11 | **Non-zero exit → 200 with body** (locked behaviour) | exit-7.bat |
| 12 | **Sync timeout → 500** | long-running.bat (5s timeout) |
| 13 | `cmd /C` wrapper preserved | parser + executor |
| 14 | `include_subdirs: true` | subdirectory script |
| 15 | Async (Wait=0) | "Command started successfully" |
| 16–19 | Command policy | outside-dir, wrong-ext, shell-metachar, path-traversal |
| 20–23 | Request validation | empty cmd, invalid Wait, wrong Content-Type, PUT |
| 24 | Security headers | X-Content-Type-Options, X-Frame-Options, CSP |
| 25 (`--rate-limit`) | Rate limit | 429 after exceeding cap |

## Known limitation — orphan child processes on timeout (test 12)

Go's `exec.CommandContext` on Windows calls `TerminateProcess` on the parent only — child processes spawned by the script are **not** killed and become orphans. The executor's `cmd.Wait()` blocks until those orphans release the inherited stdout/stderr pipes, which means a request that timed out *internally* at `command_timeout_seconds` may still hang on the wire until the orphaned child finishes naturally.

Test 12 (`long-running.bat`) is the canonical example: it runs `ping -n 9` (~9s) with a 5s server timeout. The 500 response is correctly produced by the executor at 5s but is delayed on the wire until ping finishes at ~9s. The runner uses `--max-time 30` and `Connection: close` on this test specifically to avoid stale-keepalive issues; if you change `long-running.bat` to ping for longer than 30s, the test will fail with `status=000` even though the service is behaving correctly.

The fix — process-tree kill via `CREATE_NEW_PROCESS_GROUP` + `taskkill /T /F` — is tracked in [`docs/ROADMAP.md::TD5`](../../docs/ROADMAP.md). It is deliberately deferred because real TI scripts in scope rarely spawn long-running child processes.

## Optional — testing the rate limit

The default config has `rate_limit.enabled: false` so the suite doesn't impact subsequent tests. To exercise it:

1. Edit `C:\TM1ExecCmd\config.yaml` and set `rate_limit.enabled: true` with `requests_per_minute: 30`.
2. Restart the service.
3. Run: `./test-from-mac.sh --rate-limit`
4. After the test sees a 429, **wait 60+ seconds** before re-running the full suite (otherwise tests will get rate-limited).

## Optional — testing IP-whitelist rejection

The default config allows the entire Tailscale CGNAT range (`100.64.0.0/10`), so any Tailscale device passes. To verify the rejection path:

1. Edit `C:\TM1ExecCmd\config.yaml` and **remove `100.64.0.0/10`** from `allowed_ips` (leave only `127.0.0.1` / `::1`).
2. Restart the service.
3. From your Mac, hit `/health`. You should get `403 Access denied`. The response still carries an `X-Request-ID` header — confirm with `curl -i`.
4. Restore the config and restart.

## Cleanup

```powershell
# Foreground: Ctrl+C
# Service variant:
sc.exe stop "TM1-ExecuteCommand-Service"
sc.exe delete "TM1-ExecuteCommand-Service"

Remove-Item -Recurse C:\TM1ExecCmd
Remove-Item -Recurse C:\Scripts\TM1
Remove-Item -Recurse C:\Scripts\Outside

# Firewall rule:
Remove-NetFirewallRule -DisplayName "TM1 ExecCmd 9092"
```

---

**For a deep, manually-driven walkthrough** (curl-by-curl, with explanations of each phase, ngrok exposure, TM1 v12 integration, log inspection), see [`docs/Manual-Testing-Guide.md`](../../docs/Manual-Testing-Guide.md). This SETUP.md is the fast path for verifying behaviour after a code change.
