# Execute Command Service

The "ExecuteCommand" service is a very simple tool that allows clients familiar with the `ExecuteCommand` TI function from TM1 v11 to execute a command. This can be done either by waiting for the process to finish or by returning immediately, similar to how the `ExecuteCommand` TI function operates.

## The Service

This service supports an "ExecuteCommand" resource which can be invoked either as a function using a GET request or as an action using a POST request. When called as a function, the `CommandLine` and `Wait` parameters are passed as query options. When called as an action, the request body must contain a JSON object with two properties: `CommandLine` and `Wait`, representing a string and an integer, respectively.

### Example Requests

#### With Wait: 1 (wait for the command to complete)

As a function:

```bash
curl "http://localhost:8080/execute?CommandLine=/path/to/script.sh+arg1+arg2&Wait=1"
```

Or as an action:

```bash
curl -X POST http://localhost:8080/ExecuteCommand \
    -d '{"CommandLine":"/path/to/script.sh arg1 arg2", "Wait": 1}' \
    -H "Content-Type: application/json"
```

Both requests execute `/bin/bash /path/to/script.sh arg1 arg2` and wait for the script to complete before returning the output.

#### With Wait: 0 (return immediately after starting the command)

As a function:

```bash
curl "http://localhost:8080/execute?CommandLine=/path/to/script.sh+arg1+arg2&Wait=0"
```

Or as an action:

```bash
curl -X POST http://localhost:8080/ExecuteCommand \
    -d '{"CommandLine":"/path/to/script.sh arg1 arg2", "Wait": 0}' \
    -H "Content-Type: application/json"
```

Either of these requests will start `/bin/bash /path/to/script.sh arg1 arg2` and return immediately with the message "Command started successfully" without waiting for the script to finish.

### URL Encoding
- When calling the service as a function using GET, remember to properly URL-encode your query parameters, especially the `CommandLine` string, which may contain spaces or special characters.
- For example, you can use `+` to represent spaces between arguments, or use `%20` for a literal space.

### How it works

- When called as a function using a GET request, the service extracts the `CommandLine` and `Wait` parameters from the URL query string.
- When called as an action using a POST request, the `CommandLine` and `Wait` parameters are extracted from the JSON object in the request body.
- The `Wait` parameter allows the client to specify whether to wait for the command to finish (`Wait: 1`) or to start the command and return immediately (`Wait: 0`).
- If `Wait: 0`, the command is executed asynchronously, meaning the HTTP response is returned right after starting the command, without waiting for the process to complete.
- If `Wait: 1`, the server waits for the command to finish and sends the output (or any errors) back to the client.

> Note that while TM1's `ExecuteCommand` function didn't return anything, if the requester is willing to wait for the command to complete, the output is returned in the response body, ready to be consumed if needed.

### Configuration

The service is configured using a `config.yaml` file, which includes the following sections:

- **Server Configuration**:
  - `http_port`: The port on which the server listens for HTTP requests. Default is 8080.
  - `command_timeout_seconds`: The maximum time allowed for a command to execute before timing out. Default is 300 seconds.

- **Logging Configuration**:
  - `enabled`: Indicates whether logging is enabled.
  - `file`: The path to the log file.
  - `level`: The logging level (e.g., info, debug).
  - `max_size`: The maximum size of the log file before it is rotated.
  - `max_backups`: The maximum number of backup log files to keep.
  - `max_age`: The maximum age (in days) to retain old log files.

- **Security Configuration** (`security:`):
  - **Authentication** (`authentication:`):
    - `enabled`: When `true`, every request to `/ExecuteCommand` must carry an `Authorization: Bearer <api_key>` header. The `/health` endpoint bypasses this check so external probes can liveness-check without a key.
    - `api_key`: A shared secret. Must be at least 32 characters when authentication is enabled. Compared in constant time to prevent timing attacks.
  - **IP Whitelist** (`ip_whitelist:`):
    - `enabled`: When `true`, only requests originating from one of the configured IPs are accepted. **`/health` does NOT bypass this check** — when the whitelist is enabled, you must include `127.0.0.1` (and `::1` if probing over IPv6) in `allowed_ips` so the service's own self-warm goroutine can reach the health endpoint.
    - `allowed_ips`: List of allowed IPs and CIDR ranges (e.g. `127.0.0.1`, `192.168.1.0/24`, `10.0.0.0/8`, IBM Planning Analytics SaaS egress IPs).
    - `trust_proxy`: When `false` (default), the source IP is `r.RemoteAddr` regardless of any `X-Forwarded-For` header. When `true`, the leftmost `X-Forwarded-For` entry is used **only** if the immediate TCP peer (`RemoteAddr`) is in `trusted_proxies`. This prevents `X-Forwarded-For` spoofing from arbitrary clients.
    - `trusted_proxies`: List of proxy IPs that are allowed to set `X-Forwarded-For`. Consulted only when `trust_proxy: true`.
  - **Command Policy** (`command_policy:`):
    - `enabled`: When `true`, only commands invoking scripts under one of the allowed directories with one of the allowed extensions are executed. Disabled by default for development; **enable in production**.
    - `allowed_extensions`: List of script file extensions (with leading dot), e.g. `.ps1`, `.py`, `.bat`, `.cmd`. The policy looks across all command tokens for one matching this list.
    - `allowed_directories`: List of directory roots from which scripts can be executed. Each entry has:
      - `path`: Absolute or relative directory path. Resolved to absolute and symlink-resolved at request time.
      - `include_subdirs`: When `true`, scripts in subdirectories of `path` are also permitted; when `false`, scripts must live directly in `path`.
    - The policy also rejects commands containing shell metacharacters (`& | ; ` `` ` `` ` > < $ \n \r`) on the raw input as defence-in-depth against injection through arguments.
  - **Rate Limit** (`rate_limit:`):
    - `enabled`: When `true`, per-IP rate limiting is enforced.
    - `requests_per_minute`: Maximum requests allowed per source IP within a one-minute sliding window. Excess requests get 429 Too Many Requests.
  - **HTTPS Configuration** (`https:`):
    - `enabled`: Indicates whether HTTPS is enabled. When enabled, the HTTP listener (if running) automatically redirects to HTTPS with a permanent redirect.
    - `port`: The port on which the server listens for HTTPS requests. Default is 9443.
    - `cert_file`: The path to the SSL certificate file.
    - `key_file`: The path to the SSL key file.

### Security Model & Operating Notes

The service is designed for the **TM1 v12 (SaaS) → customer-server** deployment model: IBM Planning Analytics issues `ExecuteHttpRequest` calls from a known, published egress IP range; the customer runs this service on their own server (typically alongside ODBCIS) under a least-privilege Windows service account.

#### Middleware chain

Every accepted request flows through (outer → inner):

```
RequestID  →  IPWhitelist  →  RateLimit  →  APIKeyAuth  →  SecurityHeaders  →  /ExecuteCommand
```

Disallowed IPs short-circuit before consuming a rate-limit slot or being authenticated. Authentication runs after rate limiting so unauthenticated noise does not bypass the per-IP cap. The `/health` endpoint bypasses `APIKeyAuth` only — it does NOT bypass `IPWhitelist` or `RateLimit`.

#### Request traceability with `X-Request-ID`

The outermost `RequestID` middleware assigns every incoming request a fresh UUID and:
- echoes it back as the `X-Request-ID` response header on every response, including 4xx/5xx rejections;
- propagates it via `r.Context()` so all downstream layers (middlewares + handler) emit logs carrying the same `request_id` field.

When a customer reports "request `abc-123` was rejected, why?", grepping logs for `request_id=abc-123` surfaces every log line for that request — including the rejection reason from `IPWhitelist`, `APIKeyAuth`, `RateLimit`, the parser, the policy check, or the executor. This is the canonical mechanism for diagnosing rejections without leaking internal details to the caller.

#### Wire-format note: non-zero exit codes

When `Wait=1` and the executed script exits with a **non-zero status**, the service returns **HTTP 200** with the script's combined stdout+stderr in the response body. The `exit_code` is captured in logs (typed as `ErrNonZeroExit`) but not surfaced to the caller. This is intentional — TM1 callers can read what their failing script printed, while internal error details (timeouts, spawn failures, etc.) still return generic 500 with no body leak.

> **Behavioural change vs. earlier versions**: Prior to the security-hardening pass, non-zero exit returned HTTP 500 with the body discarded. Callers that previously branched on the 500 status to detect script failure should now branch on the script's own output or a separate side-channel.

#### Logging notes for ops

- The `HTTP request received` info line is now emitted at the **top** of the handler, before any validation. Every accepted request produces this line, even if it later 400s on bad content-type or oversize body.
- The `allowed=true|false` field on `HTTP request received` has been **removed**. IP-allowlist rejections now produce a separate `Access denied: ip_not_in_whitelist` log entry from the `IPWhitelist` middleware, carrying the same `request_id`.
- Async (`Wait=0`) executions now log an `async_id` (UUID) and `pid` on the completion line. The async ID is reserved for a future polling endpoint (see `docs/ROADMAP.md#R1`); today it is informational only.

### How to use

Run the Go application directly from source, optionally specifying a port using the --port flag, as in:

```bash
go run main.go --port=9090
```

This will start the ExecuteCommand service listening to port `9090`. If no port is specified, it will default to port `8080`.

Once you are satisfied with the service, or want to use it as is, you would first build an executable using:

```bash
go build
./tm1-executecommand-service.exe --port=9090
```

This places the executable in the root of the source directory, or:

```bash
go install
tm1-executecommand-service.exe --port=9090
```

This also builds the executable but instead of cluttering your source directory, it places it in the `bin` folder of your workspace defined by the `GOPATH` environment variable. This snippet assumes that the `bin` folder is in your path, thus the OS will know where to find your executable for the ExecuteCommand service.

### Installing the ExecuteCommand service

The code checks if it is running as a Windows service and will act accordingly. To set up the ExecuteCommand service as a Windows service, create/register the service and start it with sc.exe:

```bash
sc.exe create TM1-ExecuteCommand-Service binPath= "C:\path\to\your\tm1-executecommand-service.exe"
sc.exe start TM1-ExecuteCommand-Service
```

## Migrating from TM1 v11 to v12

While this service could potentially be generally useful, the trigger for creating it was that TM1 v12 no longer supports the `ExecuteCommand` TI function. The main reason for this removal is that TM1 v12, presumed to be running in a container, would not allow you to execute commands in that limited context, nor would SREs of a SaaS offering or your IT team managing your cluster want you to.

TM1 v12 introduces an `ExecuteHttpRequest` function which, in essence, provides you with even greater power as long as the capability you are looking for is available as a 'service' and is accessible to you through HTTP[S]. As numerous `ExecuteCommand` examples popped up that only needed a context they could run in, and had absolutely no dependency on anything TM1 itself, the idea was born to create a lightweight service to provide such context in which they could continue to be executed and make migration of those `ExecuteCommand` requests straightforward.

This ExecuteCommand service is that service that can help the migration/transitioning to TM1 v12. The only thing required is a straightforward, almost search and replace, conversion of calls to `ExecuteCommand` to calls to `ExecuteHttpRequest` instead. Whilst considering using this pattern keep in mind there are a couple of limitations:

- There is no access to the data directory in a v12 deployment any longer (and you shouldn't if you happen to be running v12 standalone/locally), apart from the fact that the (meta-)data is organized completely differently anyway, so any commands you are trying to execute that require access and depend on those files/structures to be there will need to be rewritten.
- If the command you are executing utilizes applications/utilities, like `TM1RunTI`, that have been built using the older TM1 APIs then those will need to be rewritten as well as TM1 v12 only supports the OData compliant REST API.
- TM1's ExecuteCommand would implicitly look in the data directory of your TM1 server, as well as in the folder which held your `tm1s[d].exe`, for the command you were trying to execute, however, the ExecuteCommand service obviously does not. While there is no notion of either directory any longer, other than adding folders to the `PATH`, you can still start processes in the working directory of your ExecuteCommand service if you prepend the command to be executed with `.\` if your ExecuteCommand service is running on Windows or `./` in the case of Linux.

Provided none of the aforementioned dependencies exist, any existing `ExecuteCommand` requests can easily be replaced by an `ExecuteHttpRequest` function call.

For example:

```
ExecuteCommand( 'cmd /C echo %PATH%', 1 );
```

can simply be replaced by a request to the ExecuteCommand service:

```
ExecuteHttpRequest( 'GET', 'http://<<host>>:<<port>>/ExecuteCommand?CommandLine=cmd+/C+echo+%25PATH%25&Wait=1' );
```

or by calling the ExecuteCommand service as an action as in:

```tm1-ti
ExecuteHttpRequest( 'POST', 
                    'http://<<host>>:<<port>>/ExecuteCommand', 
                    '-h Content-Type:application/json',
                    '-d { "CommandLine":"cmd /C echo %PATH%", "Wait":1 }' );
```

> Note that either method will result in the exact same outcome, and that the command line itself needs to be URL-encoded in the case it is included in a query option as part of the URL request but does not need to be when injecting it in the JSON body of the POST request.
