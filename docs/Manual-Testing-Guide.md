# ExecuteCommand Service - Manual Testing Guide

## Test Environment

| Component | Details |
|-----------|---------|
| **Windows Machine** | Runs the ExecuteCommand service |
| **ngrok** | Tunnels HTTPS traffic from the internet to the service on localhost |
| **TM1 v12 Instance** | IBM-provided Planning Analytics instance, calls `ExecuteHttpRequest` |

## Architecture During Testing

```
IBM PA SaaS (TM1 v12)
        |
        | HTTPS (ngrok cert)
        v
  ngrok cloud endpoint
  (https://xxxx.ngrok-free.app)
        |
        | HTTP (localhost tunnel)
        v
  Windows Machine
  ExecuteCommand service (port 9090)
        |
        v
  cmd.exe / PowerShell scripts
```

---

## Phase 1: Build and Basic Setup

### 1.1 Build the Service

Open a terminal (PowerShell or Command Prompt) on the Windows machine:

```powershell
cd C:\path\to\tm1-executecommand-service
go build -o tm1-executecommand-service.exe .
```

Verify the binary was created:

```powershell
dir tm1-executecommand-service.exe
```

### 1.2 Create the Test Config

Create a file called `config-test.yaml` in the project root. Start with the simplest possible config (everything disabled except logging):

```yaml
server:
  http_port: 9090
  command_timeout_seconds: 30

logging:
  enabled: true
  file: "logs/tm1executecommandservice.log"
  level: "debug"
  max_size: 10
  max_backups: 3
  max_age: 28

security:
  authentication:
    enabled: false
    api_key: ""

  ip_whitelist:
    enabled: false
    allowed_ips: []
    trust_proxy: false
    trusted_proxies: []

  command_policy:
    enabled: false
    allowed_extensions: []
    allowed_directories: []

  rate_limit:
    enabled: false
    requests_per_minute: 60

  https:
    enabled: false
    port: 9443
    cert_file: ""
    key_file: ""
```

### 1.3 Create the Logs Directory

```powershell
mkdir logs
```

### 1.4 Start the Service

```powershell
.\tm1-executecommand-service.exe --config config-test.yaml
```

You should see:

```
Starting ExecuteCommand service on port 9090...
```

### 1.5 Test the Health Endpoint

Open a **second terminal** on the same Windows machine:

```powershell
curl http://localhost:9090/health
```

**Expected:** `{"status":"ok"}`

> **Pass criteria:** 200 OK with JSON body.

---

## Phase 2: Basic Command Execution (Local)

### 2.1 Simple Echo (POST, Wait=1)

```powershell
curl -X POST http://localhost:9090/ExecuteCommand `
  -H "Content-Type: application/json" `
  -d "{\"CommandLine\": \"cmd /C echo Hello from TM1\", \"Wait\": 1}"
```

**Expected:** `Hello from TM1`

### 2.2 Simple Echo (GET, Wait=1)

```powershell
curl "http://localhost:9090/ExecuteCommand?CommandLine=cmd+/C+echo+Hello+GET&Wait=1"
```

**Expected:** `Hello GET`

### 2.3 Fire-and-Forget (Wait=0)

```powershell
curl -X POST http://localhost:9090/ExecuteCommand `
  -H "Content-Type: application/json" `
  -d "{\"CommandLine\": \"cmd /C echo fire-and-forget > C:\\temp\\test-output.txt\", \"Wait\": 0}"
```

**Expected response:** `Command started successfully`

Then verify the file was created:

```powershell
type C:\temp\test-output.txt
```

> **Note:** Create `C:\temp` beforehand if it doesn't exist.

### 2.4 PowerShell Script Execution

Create a test script `C:\Scripts\test-hello.ps1`:

```powershell
Write-Output "Hello from PowerShell at $(Get-Date)"
```

Execute it:

```powershell
curl -X POST http://localhost:9090/ExecuteCommand `
  -H "Content-Type: application/json" `
  -d "{\"CommandLine\": \"powershell -ExecutionPolicy Bypass -File C:\\Scripts\\test-hello.ps1\", \"Wait\": 1}"
```

**Expected:** `Hello from PowerShell at <current datetime>`

### 2.5 Command Timeout

With the 30-second timeout in config, this should fail:

```powershell
curl -X POST http://localhost:9090/ExecuteCommand `
  -H "Content-Type: application/json" `
  -d "{\"CommandLine\": \"cmd /C ping -n 60 127.0.0.1\", \"Wait\": 1}"
```

**Expected:** `Command execution failed` (HTTP 500 after 30 seconds)

### 2.6 Invalid Requests

**Missing CommandLine:**

```powershell
curl -X POST http://localhost:9090/ExecuteCommand `
  -H "Content-Type: application/json" `
  -d "{\"Wait\": 1}"
```

**Expected:** `No or invalid CommandLine specified` (HTTP 400)

**Invalid Wait value:**

```powershell
curl -X POST http://localhost:9090/ExecuteCommand `
  -H "Content-Type: application/json" `
  -d "{\"CommandLine\": \"cmd /C echo test\", \"Wait\": 5}"
```

**Expected:** `No or invalid Wait value specified` (HTTP 400)

**Wrong Content-Type:**

```powershell
curl -X POST http://localhost:9090/ExecuteCommand `
  -H "Content-Type: text/plain" `
  -d "{\"CommandLine\": \"cmd /C echo test\", \"Wait\": 1}"
```

**Expected:** `Content-Type must be application/json` (HTTP 400)

---

## Phase 3: Authentication (Bearer Token)

### 3.1 Enable Authentication

Stop the service (Ctrl+C). Update `config-test.yaml`:

```yaml
security:
  authentication:
    enabled: true
    api_key: "my-super-secret-test-key-that-is-at-least-32-chars-long"
```

Restart the service:

```powershell
.\tm1-executecommand-service.exe --config config-test.yaml
```

### 3.2 Request Without Token (Should Fail)

```powershell
curl -v http://localhost:9090/ExecuteCommand `
  -H "Content-Type: application/json" `
  -d "{\"CommandLine\": \"cmd /C echo test\", \"Wait\": 1}"
```

**Expected:** HTTP 401 Unauthorized

### 3.3 Request With Wrong Token (Should Fail)

```powershell
curl -v http://localhost:9090/ExecuteCommand `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer wrong-key-here" `
  -d "{\"CommandLine\": \"cmd /C echo test\", \"Wait\": 1}"
```

**Expected:** HTTP 403 Forbidden

### 3.4 Request With Valid Token (Should Pass)

```powershell
curl -X POST http://localhost:9090/ExecuteCommand `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer my-super-secret-test-key-that-is-at-least-32-chars-long" `
  -d "{\"CommandLine\": \"cmd /C echo authenticated!\", \"Wait\": 1}"
```

**Expected:** `authenticated!`

### 3.5 Health Endpoint Bypasses Auth

```powershell
curl http://localhost:9090/health
```

**Expected:** `{"status":"ok"}` (no token needed)

---

## Phase 4: Rate Limiting

### 4.1 Enable Rate Limiting

Stop the service. Update `config-test.yaml`:

```yaml
security:
  rate_limit:
    enabled: true
    requests_per_minute: 5
```

Restart the service.

### 4.2 Exceed the Rate Limit

Run this in a loop (include the auth header if authentication is enabled):

```powershell
for ($i = 1; $i -le 10; $i++) {
    $response = curl -s -o NUL -w "%{http_code}" -X POST http://localhost:9090/ExecuteCommand `
      -H "Content-Type: application/json" `
      -H "Authorization: Bearer my-super-secret-test-key-that-is-at-least-32-chars-long" `
      -d "{\"CommandLine\": \"cmd /C echo request $i\", \"Wait\": 1}"
    Write-Output "Request $i : HTTP $response"
}
```

**Expected:** First ~5 requests return HTTP 200, then subsequent requests return HTTP 429 (Too Many Requests).

### 4.3 Recovery After Waiting

Wait 60 seconds, then try again:

```powershell
Start-Sleep -Seconds 65
curl -X POST http://localhost:9090/ExecuteCommand `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer my-super-secret-test-key-that-is-at-least-32-chars-long" `
  -d "{\"CommandLine\": \"cmd /C echo recovered\", \"Wait\": 1}"
```

**Expected:** `recovered` (HTTP 200)

---

## Phase 5: Command Policy (Directory-Scoped Execution)

### 5.1 Create Test Script Directories

```powershell
mkdir C:\Scripts\TM1
mkdir C:\Scripts\TM1\SubFolder
mkdir C:\Scripts\Blocked
```

Create test scripts:

**`C:\Scripts\TM1\allowed-script.ps1`:**

```powershell
Write-Output "This script is ALLOWED - running from TM1 directory"
```

**`C:\Scripts\TM1\SubFolder\sub-script.ps1`:**

```powershell
Write-Output "This script is in a SUBFOLDER of TM1 directory"
```

**`C:\Scripts\Blocked\blocked-script.ps1`:**

```powershell
Write-Output "This script should be BLOCKED"
```

### 5.2 Enable Command Policy

Stop the service. Update `config-test.yaml`:

```yaml
security:
  command_policy:
    enabled: true
    allowed_extensions:
      - ".ps1"
      - ".bat"
      - ".cmd"
    allowed_directories:
      - path: "C:\\Scripts\\TM1"
        include_subdirs: true
```

Restart the service.

### 5.3 Allowed Script (Should Pass)

```powershell
curl -X POST http://localhost:9090/ExecuteCommand `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer my-super-secret-test-key-that-is-at-least-32-chars-long" `
  -d "{\"CommandLine\": \"powershell -ExecutionPolicy Bypass -File C:\\Scripts\\TM1\\allowed-script.ps1\", \"Wait\": 1}"
```

**Expected:** `This script is ALLOWED - running from TM1 directory`

### 5.4 Allowed Script in Subdirectory (Should Pass)

```powershell
curl -X POST http://localhost:9090/ExecuteCommand `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer my-super-secret-test-key-that-is-at-least-32-chars-long" `
  -d "{\"CommandLine\": \"powershell -ExecutionPolicy Bypass -File C:\\Scripts\\TM1\\SubFolder\\sub-script.ps1\", \"Wait\": 1}"
```

**Expected:** `This script is in a SUBFOLDER of TM1 directory`

### 5.5 Blocked Script (Should Fail - Wrong Directory)

```powershell
curl -X POST http://localhost:9090/ExecuteCommand `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer my-super-secret-test-key-that-is-at-least-32-chars-long" `
  -d "{\"CommandLine\": \"powershell -ExecutionPolicy Bypass -File C:\\Scripts\\Blocked\\blocked-script.ps1\", \"Wait\": 1}"
```

**Expected:** `Command not permitted` (HTTP 403)

### 5.6 Blocked - Wrong Extension

```powershell
curl -X POST http://localhost:9090/ExecuteCommand `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer my-super-secret-test-key-that-is-at-least-32-chars-long" `
  -d "{\"CommandLine\": \"C:\\Scripts\\TM1\\some-script.exe\", \"Wait\": 1}"
```

**Expected:** `Command not permitted` (HTTP 403)

### 5.7 Blocked - Shell Metacharacters

```powershell
curl -X POST http://localhost:9090/ExecuteCommand `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer my-super-secret-test-key-that-is-at-least-32-chars-long" `
  -d "{\"CommandLine\": \"powershell -File C:\\Scripts\\TM1\\allowed-script.ps1 & del C:\\important.txt\", \"Wait\": 1}"
```

**Expected:** `Command not permitted` (HTTP 403)

### 5.8 Blocked - Path Traversal

```powershell
curl -X POST http://localhost:9090/ExecuteCommand `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer my-super-secret-test-key-that-is-at-least-32-chars-long" `
  -d "{\"CommandLine\": \"powershell -File C:\\Scripts\\TM1\\..\\Blocked\\blocked-script.ps1\", \"Wait\": 1}"
```

**Expected:** `Command not permitted` (HTTP 403)

### 5.9 Subdirectory Control (include_subdirs: false)

Update `config-test.yaml` to disable subdirectory access:

```yaml
security:
  command_policy:
    enabled: true
    allowed_extensions:
      - ".ps1"
    allowed_directories:
      - path: "C:\\Scripts\\TM1"
        include_subdirs: false
```

Restart the service. Then test the subfolder script:

```powershell
curl -X POST http://localhost:9090/ExecuteCommand `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer my-super-secret-test-key-that-is-at-least-32-chars-long" `
  -d "{\"CommandLine\": \"powershell -ExecutionPolicy Bypass -File C:\\Scripts\\TM1\\SubFolder\\sub-script.ps1\", \"Wait\": 1}"
```

**Expected:** `Command not permitted` (HTTP 403 - subdirectories blocked)

The parent directory script should still work:

```powershell
curl -X POST http://localhost:9090/ExecuteCommand `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer my-super-secret-test-key-that-is-at-least-32-chars-long" `
  -d "{\"CommandLine\": \"powershell -ExecutionPolicy Bypass -File C:\\Scripts\\TM1\\allowed-script.ps1\", \"Wait\": 1}"
```

**Expected:** `This script is ALLOWED - running from TM1 directory`

---

## Phase 6: Security Headers

### 6.1 Inspect Response Headers

```powershell
curl -v http://localhost:9090/health 2>&1 | Select-String "< "
```

**Expected headers present:**

| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Content-Security-Policy` | `default-src 'none'` |
| `Cache-Control` | `no-store` |

**Expected headers absent** (since HTTPS is disabled):

| Header | Should NOT appear |
|--------|-------------------|
| `Strict-Transport-Security` | Only set when HTTPS is enabled |

---

## Phase 7: ngrok Tunnel Setup

### 7.1 Install and Start ngrok

Download ngrok from [ngrok.com](https://ngrok.com) if not already installed. Then:

```powershell
ngrok http 9090
```

You'll see output like:

```
Forwarding    https://abcd1234.ngrok-free.app -> http://localhost:9090
```

Copy the `https://...ngrok-free.app` URL.

### 7.2 Verify Through ngrok

From the **same Windows machine** (or any machine with internet access):

```powershell
curl https://abcd1234.ngrok-free.app/health
```

**Expected:** `{"status":"ok"}`

### 7.3 Test Command Execution Through ngrok

```powershell
curl -X POST https://abcd1234.ngrok-free.app/ExecuteCommand `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer my-super-secret-test-key-that-is-at-least-32-chars-long" `
  -d "{\"CommandLine\": \"powershell -ExecutionPolicy Bypass -File C:\\Scripts\\TM1\\allowed-script.ps1\", \"Wait\": 1}"
```

**Expected:** `This script is ALLOWED - running from TM1 directory`

---

## Phase 8: End-to-End Test with TM1 v12

### 8.1 Recommended Config for TM1 Testing

This is the recommended `config-test.yaml` for the ngrok+TM1 test. Authentication is the primary access control since IP whitelisting is not practical through ngrok:

```yaml
server:
  http_port: 9090
  command_timeout_seconds: 60

logging:
  enabled: true
  file: "logs/tm1executecommandservice.log"
  level: "debug"
  max_size: 10
  max_backups: 3
  max_age: 28

security:
  authentication:
    enabled: true
    api_key: "my-super-secret-test-key-that-is-at-least-32-chars-long"

  ip_whitelist:
    enabled: false
    allowed_ips: []
    trust_proxy: false
    trusted_proxies: []

  command_policy:
    enabled: true
    allowed_extensions:
      - ".ps1"
      - ".bat"
      - ".cmd"
    allowed_directories:
      - path: "C:\\Scripts\\TM1"
        include_subdirs: true

  rate_limit:
    enabled: true
    requests_per_minute: 30

  https:
    enabled: false
    port: 9443
    cert_file: ""
    key_file: ""
```

### 8.2 Create a TM1 Test Script

Create `C:\Scripts\TM1\tm1-test.ps1`:

```powershell
param(
    [string]$Message = "No message provided"
)

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$hostname = $env:COMPUTERNAME
$output = "TM1 ExecuteCommand Test | Host: $hostname | Time: $timestamp | Message: $Message"

# Write to a log file as proof of execution
$output | Out-File -Append "C:\Scripts\TM1\execution-log.txt"

# Return the output
Write-Output $output
```

### 8.3 Test Locally Before TM1

```powershell
curl -X POST http://localhost:9090/ExecuteCommand `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer my-super-secret-test-key-that-is-at-least-32-chars-long" `
  -d "{\"CommandLine\": \"powershell -ExecutionPolicy Bypass -File C:\\Scripts\\TM1\\tm1-test.ps1 -Message 'Local test'\", \"Wait\": 1}"
```

**Expected:** `TM1 ExecuteCommand Test | Host: <your-hostname> | Time: <timestamp> | Message: Local test`

### 8.4 Configure TM1 v12 to Call the Service

In your TM1 v12 instance, use a TI process with `ExecuteHttpRequest` to call the service through ngrok.

The TI process code would look something like:

```
# In the Prolog tab of a TI process:

sURL = 'https://abcd1234.ngrok-free.app/ExecuteCommand';
sHeaders = 'Content-Type: application/json~Authorization: Bearer my-super-secret-test-key-that-is-at-least-32-chars-long';
sBody = '{"CommandLine": "powershell -ExecutionPolicy Bypass -File C:\\Scripts\\TM1\\tm1-test.ps1 -Message ''Called from TM1''", "Wait": 1}';

nRet = ExecuteHttpRequest( sURL, 'POST', sHeaders, sBody );
```

> **Note:** The exact `ExecuteHttpRequest` syntax may vary. Check IBM's documentation for the function signature in your v12 build. Headers are typically delimited by `~` (tilde). Adjust as needed.

### 8.5 Verify Execution

After running the TI process, check the execution log on the Windows machine:

```powershell
type C:\Scripts\TM1\execution-log.txt
```

You should see a line with `Message: Called from TM1`.

Also check the service log for the full request trail:

```powershell
type logs\tm1executecommandservice.log
```

Look for entries showing:

- HTTP request received from ngrok's IP
- Command permitted check passed
- Command start and completion
- Response sent with 200

### 8.6 Fire-and-Forget from TM1 (Wait=0)

Update the TI process to use `Wait: 0`:

```
sBody = '{"CommandLine": "powershell -ExecutionPolicy Bypass -File C:\\Scripts\\TM1\\tm1-test.ps1 -Message ''Fire and forget''", "Wait": 0}';
```

**Expected:** TM1 gets an immediate response (`Command started successfully`), and the script still executes on the Windows machine. Verify via `execution-log.txt`.

---

## Phase 9: Log Verification

### 9.1 Check Service Logs

After running tests, review the logs:

```powershell
type logs\tm1executecommandservice.log
```

Verify that logs contain:

- **Request received entries** with source IP, method, path
- **Command start entries** with the command line being executed
- **Command completion entries** with duration and output
- **Blocked requests** (if you tested auth failures, policy blocks, etc.) with reasons
- **No sensitive data leaking** in error responses (check that HTTP responses only show generic messages)

### 9.2 Log Rotation

The log config uses `max_size: 10` (10MB). For testing, you can verify rotation works by generating many requests, but this is low-priority for manual testing.

---

## Test Results Checklist

| # | Test | Expected | Result |
|---|------|----------|--------|
| 2.1 | POST echo Wait=1 | `Hello from TM1` (200) | |
| 2.2 | GET echo Wait=1 | `Hello GET` (200) | |
| 2.3 | Fire-and-forget Wait=0 | `Command started successfully` + file created | |
| 2.4 | PowerShell script | Script output (200) | |
| 2.5 | Command timeout | `Command execution failed` (500) | |
| 2.6 | Invalid requests | Appropriate 400 errors | |
| 3.2 | No auth token | 401 | |
| 3.3 | Wrong auth token | 403 | |
| 3.4 | Valid auth token | 200 | |
| 3.5 | Health bypasses auth | 200 | |
| 4.2 | Rate limit exceeded | 429 after burst | |
| 4.3 | Rate limit recovery | 200 after waiting | |
| 5.3 | Allowed directory script | 200 | |
| 5.4 | Allowed subdirectory script | 200 | |
| 5.5 | Blocked directory script | 403 | |
| 5.6 | Wrong extension | 403 | |
| 5.7 | Shell metacharacters | 403 | |
| 5.8 | Path traversal | 403 | |
| 5.9 | Subdirs disabled | 403 for subfolder | |
| 6.1 | Security headers present | Headers verified | |
| 7.2 | ngrok health check | 200 | |
| 7.3 | ngrok command execution | 200 | |
| 8.4 | TM1 ExecuteHttpRequest (Wait=1) | Script output returned | |
| 8.6 | TM1 ExecuteHttpRequest (Wait=0) | Immediate response, script runs | |
| 9.1 | Logs contain expected entries | Verified | |

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| Service won't start | Config validation error | Check terminal output for specific error message |
| `api_key must be at least 32 characters` | API key too short | Use a longer key in config |
| 401 on all requests | Auth enabled but token not sent | Add `Authorization: Bearer <key>` header |
| 403 on commands that should work | Command policy blocking | Check `allowed_extensions` and `allowed_directories` in config |
| 403 with IP whitelist | IP not in allowed list | Disable IP whitelist for ngrok testing, or add ngrok IPs |
| ngrok shows 502 Bad Gateway | Service not running on expected port | Verify `http_port` matches the ngrok target |
| TM1 gets empty response | Possible header format issue | Check TM1 `ExecuteHttpRequest` header delimiter syntax |
| Script runs but no output | PowerShell execution policy | Add `-ExecutionPolicy Bypass` flag |
| Timeout errors | `command_timeout_seconds` too low | Increase timeout in config |
