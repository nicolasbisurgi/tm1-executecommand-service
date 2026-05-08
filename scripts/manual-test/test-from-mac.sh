#!/usr/bin/env bash
#
# End-to-end test runner for tm1-executecommand-service.
#
# Run from a Mac (or any *nix) against a Windows host that is running the
# service with `scripts/manual-test/config.yaml` and the contents of
# `scripts/manual-test/test-scripts/` deployed to C:\Scripts\TM1\
# (and test-scripts-outside\blocked.bat to C:\Scripts\Outside\).
#
# Usage:
#   ./test-from-mac.sh                          # default host/port/key
#   SERVICE_HOST=100.84.94.15 ./test-from-mac.sh
#   ./test-from-mac.sh --rate-limit             # also runs the rate-limit
#                                                 test (requires rate_limit:
#                                                 enabled: true in config)
#
# Exit codes: 0 if all tests pass, 1 otherwise.

set -uo pipefail

SERVICE_HOST="${SERVICE_HOST:-100.84.94.15}"
SERVICE_PORT="${SERVICE_PORT:-9092}"
API_KEY="${API_KEY:-test-api-key-that-is-at-least-32-chars-long!!}"
BASE_URL="http://${SERVICE_HOST}:${SERVICE_PORT}"

RUN_RATE_LIMIT=0
for arg in "$@"; do
  case "$arg" in
    --rate-limit) RUN_RATE_LIMIT=1 ;;
    -h|--help)
      sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
  esac
done

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YLW=$'\033[33m'; C_GRY=$'\033[90m'; C_RST=$'\033[0m'
else
  C_RED=''; C_GRN=''; C_YLW=''; C_GRY=''; C_RST=''
fi

PASS=0
FAIL=0
FAILED_NAMES=()

pass() { printf '%s%s%s\n' "$C_GRN" "PASS  $1" "$C_RST"; PASS=$((PASS+1)); }
fail() {
  printf '%s%s%s\n' "$C_RED" "FAIL  $1" "$C_RST"
  printf '%s%s%s\n' "$C_GRY" "      $2" "$C_RST"
  FAIL=$((FAIL+1))
  FAILED_NAMES+=("$1")
}
section() { printf '\n%s── %s ──%s\n' "$C_YLW" "$1" "$C_RST"; }

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
TMP_BODY="$(mktemp -t tm1ec-body.XXXXXX)"
TMP_HEAD="$(mktemp -t tm1ec-head.XXXXXX)"
trap 'rm -f "$TMP_BODY" "$TMP_HEAD"' EXIT

# req METHOD PATH [extra-curl-args...] -> echoes status code; body in $TMP_BODY, headers in $TMP_HEAD
req() {
  local method="$1" path="$2"
  shift 2
  curl -sS -o "$TMP_BODY" -D "$TMP_HEAD" -w '%{http_code}' \
    -X "$method" \
    "$@" \
    "${BASE_URL}${path}" 2>/dev/null
}

# Convenience for authenticated GET with CommandLine + Wait params
get_auth() {
  local commandline="$1" wait="$2"
  # URL-encode the command line manually for the few special chars we care about
  local encoded
  encoded=$(python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "$commandline" 2>/dev/null \
    || printf '%s' "$commandline" | sed 's/ /%20/g; s/\\/%5C/g; s/&/%26/g; s/|/%7C/g; s/`/%60/g; s/>/%3E/g; s/</%3C/g; s/\$/%24/g')
  req GET "/ExecuteCommand?CommandLine=${encoded}&Wait=${wait}" \
    -H "Authorization: Bearer ${API_KEY}"
}

# Authenticated POST with JSON body
post_auth_json() {
  local commandline="$1" wait="$2"
  local body
  body=$(python3 -c '
import json, sys
print(json.dumps({"CommandLine": sys.argv[1], "Wait": int(sys.argv[2])}))
' "$commandline" "$wait" 2>/dev/null) || {
    # Fallback if python3 unavailable: assume no embedded quotes / specials
    body=$(printf '{"CommandLine":"%s","Wait":%s}' "$commandline" "$wait")
  }
  req POST "/ExecuteCommand" \
    -H "Authorization: Bearer ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d "$body"
}

# Header value extractor (case-insensitive). Strips CR.
header_val() {
  local name="$1"
  awk -v n="$name" 'BEGIN{IGNORECASE=1}
    tolower($0) ~ "^"tolower(n)":" { sub(/\r$/, ""); sub(/^[^:]*:[ \t]*/, ""); print; exit }' "$TMP_HEAD"
}

body() { cat "$TMP_BODY"; }
body_contains() { grep -F -q "$1" "$TMP_BODY"; }

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
section "Pre-flight: reach service at ${BASE_URL}"
if ! status=$(req GET /health 2>/dev/null); then
  printf '%sCannot reach %s — is the service running and is the IP/port correct?%s\n' "$C_RED" "$BASE_URL" "$C_RST"
  exit 2
fi
if [ "$status" != "200" ]; then
  printf '%sService responded with status %s on /health (expected 200). Continuing anyway.%s\n' "$C_YLW" "$status" "$C_RST"
fi
printf '  reachable, /health returned %s\n' "$status"

# Config sanity: probe an unauthenticated /ExecuteCommand request. If we get
# anything other than 401, the deployed config likely has authentication
# disabled — which means we're not running the test config and the rest of
# the suite will produce misleading results.
status=$(req GET "/ExecuteCommand?CommandLine=cmd&Wait=1")
if [ "$status" != "401" ]; then
  printf '%s\n' "${C_RED}Config sanity check FAILED:${C_RST}"
  printf '  Unauthenticated request returned %s, expected 401.\n' "$status"
  printf '  The deployed config does not have authentication.enabled=true.\n'
  printf '  Most likely you are running with the repo-root config/config.yaml\n'
  printf '  instead of scripts/manual-test/config.yaml.\n\n'
  printf '  On the Windows host, verify with:\n'
  printf '    Get-Content C:\\TM1ExecCmd\\config.yaml | Select-String "enabled" -Context 0,1\n\n'
  printf '  Then re-copy the test config and restart the service.\n'
  exit 2
fi
printf '  config sanity: unauthenticated /ExecuteCommand → 401 ✓\n'

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

section "Health endpoint"
status=$(req GET /health)
[ "$status" = "200" ] && pass "01 /health returns 200" \
  || fail "01 /health returns 200" "got $status, body: $(body)"

[ "$(body)" = "{\"status\":\"ok\"}" ] && pass "02 /health body is {\"status\":\"ok\"}" \
  || fail "02 /health body is {\"status\":\"ok\"}" "body: $(body)"

section "X-Request-ID middleware"
status=$(req GET /health)
rid=$(header_val "X-Request-ID")
[ -n "$rid" ] && pass "03 X-Request-ID header is set" \
  || fail "03 X-Request-ID header is set" "no X-Request-ID in response headers"

# UUID format check (loose)
if printf '%s' "$rid" | grep -Eq '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'; then
  pass "04 X-Request-ID is a UUID"
else
  fail "04 X-Request-ID is a UUID" "got: $rid"
fi

# Two requests must have distinct IDs
status=$(req GET /health); rid1=$(header_val "X-Request-ID")
status=$(req GET /health); rid2=$(header_val "X-Request-ID")
[ -n "$rid1" ] && [ -n "$rid2" ] && [ "$rid1" != "$rid2" ] && pass "05 each request gets a fresh X-Request-ID" \
  || fail "05 each request gets a fresh X-Request-ID" "rid1=$rid1 rid2=$rid2"

section "Authentication (Bearer token)"
status=$(req GET "/ExecuteCommand?CommandLine=cmd+%2FC+echo+test&Wait=1")
[ "$status" = "401" ] && pass "06 missing Authorization → 401" \
  || fail "06 missing Authorization → 401" "got $status, body: $(body)"

status=$(req GET "/ExecuteCommand?CommandLine=cmd+%2FC+echo+test&Wait=1" \
  -H "Authorization: Bearer wrong-key-of-sufficient-length-blah-blah-blah")
[ "$status" = "401" ] && pass "07 wrong API key → 401" \
  || fail "07 wrong API key → 401" "got $status, body: $(body)"

status=$(req GET "/ExecuteCommand?CommandLine=cmd+%2FC+echo+test&Wait=1" \
  -H "Authorization: Basic dXNlcjpwYXNz")
[ "$status" = "401" ] && pass "08 wrong scheme (Basic) → 401" \
  || fail "08 wrong scheme (Basic) → 401" "got $status, body: $(body)"

status=$(req GET /health)
[ "$status" = "200" ] && pass "09 /health bypasses APIKeyAuth (no header)" \
  || fail "09 /health bypasses APIKeyAuth (no header)" "got $status"

section "Sync execution (Wait=1)"
# .bat / .cmd invocations are wrapped in `cmd /C` because Windows CreateProcess
# can't reliably spawn a .bat directly when arguments are present (different
# quoting algorithm than the Win32 standard). TM1 v11 callers always wrapped
# via cmd /C; we mirror that.
status=$(post_auth_json 'cmd /C C:\Scripts\TM1\echo.bat alpha beta' 1)
if [ "$status" = "200" ] && body_contains "hello from echo.bat" && body_contains "arg1=alpha"; then
  pass "10 echo.bat success → 200 with stdout"
else
  fail "10 echo.bat success → 200 with stdout" "status=$status body=$(body)"
fi

# Non-zero exit → 200 with body (the locked behavioural change)
status=$(post_auth_json 'cmd /C C:\Scripts\TM1\exit-7.bat' 1)
if [ "$status" = "200" ] && body_contains "failure output line 1"; then
  pass "11 exit-7.bat → 200 with body (non-zero exit)"
else
  fail "11 exit-7.bat → 200 with body (non-zero exit)" "status=$status body=$(body)"
fi

# Timeout → 500
# We use a dedicated curl invocation here (not post_auth_json) so we can:
#   --max-time 30           give the server time to respond AFTER the orphan
#                           child process finishes (see TD5 in ROADMAP.md);
#   -H 'Connection: close'  use a fresh TCP connection so a stale keepalive
#                           pipe from a previous test can't be EOF'd mid-response.
timeout_body=$(printf '{"CommandLine":"cmd /C C:\\\\Scripts\\\\TM1\\\\long-running.bat","Wait":1}')
status=$(curl -sS -o "$TMP_BODY" -D "$TMP_HEAD" -w '%{http_code}' \
  --max-time 30 \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -H "Connection: close" \
  -X POST -d "$timeout_body" \
  "${BASE_URL}/ExecuteCommand" 2>/dev/null)
if [ "$status" = "500" ] && body_contains "Command execution failed"; then
  pass "12 long-running.bat → 500 (timeout)"
elif [ "$status" = "000" ]; then
  fail "12 long-running.bat → 500 (timeout)" \
    "curl got no HTTP response. Likely caused by orphaned child process holding stdout/stderr pipes (see TD5: process-tree kill not implemented). If you keep hitting this, shorten ping in long-running.bat or run with a less aggressive NAT/Tailscale path."
else
  fail "12 long-running.bat → 500 (timeout)" "status=$status body=$(body)"
fi

# Bare path WITHOUT args (no wrapper) — Windows can spawn .bat directly when
# there are no arguments, so this exercises the no-wrapper executor path.
status=$(post_auth_json 'C:\Scripts\TM1\exit-7.bat' 1)
if [ "$status" = "200" ] && body_contains "failure output line 1"; then
  pass "13 bare .bat path (no args) → 200"
else
  fail "13 bare .bat path (no args) → 200" "status=$status body=$(body)"
fi

# Subdirectory script (include_subdirs=true)
status=$(post_auth_json 'cmd /C C:\Scripts\TM1\sub\nested.bat' 1)
if [ "$status" = "200" ] && body_contains "nested script ran"; then
  pass "14 subdirectory script → 200 (include_subdirs=true)"
else
  fail "14 subdirectory script → 200 (include_subdirs=true)" "status=$status body=$(body)"
fi

section "Async execution (Wait=0)"
status=$(post_auth_json 'cmd /C C:\Scripts\TM1\echo.bat async' 0)
if [ "$status" = "200" ] && [ "$(body)" = "Command started successfully" ]; then
  pass "15 Wait=0 → \"Command started successfully\""
else
  fail "15 Wait=0 → \"Command started successfully\"" "status=$status body=$(body)"
fi

section "Command policy enforcement"
# Policy runs BEFORE the executor — so wrapper choice doesn't matter for the
# rejection itself. We use cmd /C to mirror real-world TM1 v11 call shape.

# Script outside allowed directory
status=$(post_auth_json 'cmd /C C:\Scripts\Outside\blocked.bat' 1)
if [ "$status" = "403" ] && body_contains "Command not permitted"; then
  pass "16 script outside allowed dir → 403"
else
  fail "16 script outside allowed dir → 403" "status=$status body=$(body)"
fi

# Wrong extension — `.txt` not in allowed_extensions, so findScriptToken
# returns "" and policy rejects with "no script file with allowed extension".
status=$(post_auth_json 'cmd /C C:\Scripts\TM1\fake.txt' 1)
if [ "$status" = "403" ] && body_contains "Command not permitted"; then
  pass "17 wrong extension (.txt) → 403"
else
  fail "17 wrong extension (.txt) → 403" "status=$status body=$(body)"
fi

# Shell metacharacter — `&` triggers metachar rejection on cmd.Raw
status=$(post_auth_json 'cmd /C C:\Scripts\TM1\echo.bat & del C:\Scripts\TM1\echo.bat' 1)
if [ "$status" = "403" ] && body_contains "Command not permitted"; then
  pass "18 shell metachar (&) → 403"
else
  fail "18 shell metachar (&) → 403" "status=$status body=$(body)"
fi

# Path traversal — Abs+Clean+EvalSymlinks resolves `..` then checks containment
status=$(post_auth_json 'cmd /C C:\Scripts\TM1\..\Outside\blocked.bat' 1)
if [ "$status" = "403" ] && body_contains "Command not permitted"; then
  pass "19 path-traversal (..) → 403"
else
  fail "19 path-traversal (..) → 403" "status=$status body=$(body)"
fi

section "Request validation"
# Empty command
status=$(post_auth_json '' 1)
[ "$status" = "400" ] && pass "20 empty CommandLine → 400" \
  || fail "20 empty CommandLine → 400" "status=$status body=$(body)"

# Invalid Wait value
status=$(post_auth_json 'C:\Scripts\TM1\echo.bat' 2)
[ "$status" = "400" ] && pass "21 Wait=2 → 400" \
  || fail "21 Wait=2 → 400" "status=$status body=$(body)"

# Wrong Content-Type on POST
body_str='{"CommandLine":"C:\\Scripts\\TM1\\echo.bat","Wait":1}'
status=$(req POST /ExecuteCommand \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: text/plain" \
  -d "$body_str")
[ "$status" = "400" ] && pass "22 wrong Content-Type → 400" \
  || fail "22 wrong Content-Type → 400" "status=$status body=$(body)"

# Invalid HTTP method
status=$(req PUT /ExecuteCommand -H "Authorization: Bearer ${API_KEY}")
[ "$status" = "405" ] && pass "23 PUT method → 405" \
  || fail "23 PUT method → 405" "status=$status body=$(body)"

section "Security headers"
status=$(req GET /health)
xcto=$(header_val "X-Content-Type-Options")
xfo=$(header_val "X-Frame-Options")
csp=$(header_val "Content-Security-Policy")
if [ "$xcto" = "nosniff" ] && [ "$xfo" = "DENY" ] && [ -n "$csp" ]; then
  pass "24 OWASP headers present (X-Content-Type-Options, X-Frame-Options, CSP)"
else
  fail "24 OWASP headers present" "xcto=$xcto xfo=$xfo csp=$csp"
fi

# ---------------------------------------------------------------------------
# Optional: rate limit (only when --rate-limit is passed AND config has it on)
# ---------------------------------------------------------------------------
if [ "$RUN_RATE_LIMIT" = "1" ]; then
  section "Rate limit (--rate-limit; requires rate_limit.enabled in config)"
  hit_429=0
  for i in $(seq 1 80); do
    status=$(req GET /health)
    [ "$status" = "429" ] && { hit_429=1; break; }
  done
  [ "$hit_429" = "1" ] && pass "25 rate limit returns 429 once exceeded" \
    || fail "25 rate limit returns 429 once exceeded" "did not see 429 in 80 requests"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
total=$((PASS + FAIL))
printf '\n%s──────────────────────────────────────────────%s\n' "$C_YLW" "$C_RST"
printf 'Total: %d   Pass: %s%d%s   Fail: %s%d%s\n' \
  "$total" "$C_GRN" "$PASS" "$C_RST" "$C_RED" "$FAIL" "$C_RST"

if [ "$FAIL" -gt 0 ]; then
  printf '\n%sFailed tests:%s\n' "$C_RED" "$C_RST"
  for n in "${FAILED_NAMES[@]}"; do
    printf '  %s\n' "$n"
  done
  exit 1
fi
exit 0
