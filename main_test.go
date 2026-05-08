package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hubert-Heijkers/tm1-executecommand-service/command"
	"github.com/Hubert-Heijkers/tm1-executecommand-service/config"
	"github.com/Hubert-Heijkers/tm1-executecommand-service/ip"
	"github.com/Hubert-Heijkers/tm1-executecommand-service/logger"
)

// setupTestApp wires an App with fake executors so handler tests run anywhere.
// Tests override app.sync / app.async to inject specific behaviors.
func setupTestApp(t *testing.T) *App {
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTPPort:              8080,
			CommandTimeoutSeconds: 30,
		},
		Security: config.SecurityConfig{
			IPWhitelist: config.IPWhitelistConfig{
				Enabled:    true,
				AllowedIPs: []string{"127.0.0.1"},
			},
			CommandPolicy:  config.CommandPolicyConfig{Enabled: false},
			Authentication: config.AuthConfig{Enabled: false},
			RateLimit:      config.RateLimitConfig{Enabled: false},
		},
	}

	lg, err := logger.InitLogger(cfg)
	if err != nil {
		t.Fatalf("Failed to initialize logger: %v", err)
	}

	ipChecker, err := ip.NewIPChecker(cfg.Security.IPWhitelist.AllowedIPs)
	if err != nil {
		t.Fatalf("Failed to initialize IP checker: %v", err)
	}

	return &App{
		cfg:       cfg,
		ipChecker: ipChecker,
		logger:    lg,
		sync:      defaultSyncFake(),
		async:     defaultAsyncFake(),
	}
}

func defaultSyncFake() *command.FakeSync {
	return &command.FakeSync{
		OnRun: func(cmd command.Command) (command.Result, error) {
			return command.Result{Stdout: "default-output\r\n"}, nil
		},
	}
}

func defaultAsyncFake() *command.FakeAsync {
	return &command.FakeAsync{
		OnStart: func(cmd command.Command) (command.Handle, error) {
			return command.Handle{ID: "test-id", PID: 1234, StartedAt: time.Now()}, nil
		},
	}
}

// echoSync returns a SyncExecutor that pretends to be `cmd /C echo X Y Z`:
// stdout = the args joined by space, CRLF-terminated. Used by tests that
// want to verify the executor's output reaches the response body unchanged.
//
// Note: ParseCommand strips the `cmd /C` wrapper, so for `cmd /C echo test`
// the parsed Command is {Wrapper: ShellCmdC, Executable: "echo", Args: ["test"]}.
func echoSync() *command.FakeSync {
	return &command.FakeSync{
		OnRun: func(cmd command.Command) (command.Result, error) {
			var out string
			if cmd.Wrapper == command.ShellCmdC && strings.EqualFold(cmd.Executable, "echo") {
				out = strings.Join(cmd.Args, " ")
			} else {
				out = cmd.Executable
			}
			return command.Result{Stdout: out + "\r\n"}, nil
		},
	}
}

func TestBasicCommandExecution(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		commandLine  string
		wait         int64
		sync         command.SyncExecutor
		async        command.AsyncExecutor
		expectedCode int
		expectedBody string
	}{
		{
			name:         "Sync success writes body verbatim",
			method:       "GET",
			commandLine:  "cmd /C echo test",
			wait:         1,
			sync:         echoSync(),
			expectedCode: http.StatusOK,
			expectedBody: "test\r\n",
		},
		{
			name:         "Spawn failure returns generic 500",
			method:       "GET",
			commandLine:  "nonexistentcommand",
			wait:         1,
			sync:         &command.FakeSync{OnRun: func(c command.Command) (command.Result, error) { return command.Result{}, &command.ErrSpawnFailed{} }},
			expectedCode: http.StatusInternalServerError,
			expectedBody: "Command execution failed\n",
		},
		{
			name:         "Empty command rejected before executor",
			method:       "GET",
			commandLine:  "",
			wait:         1,
			expectedCode: http.StatusBadRequest,
		},
		{
			name:         "POST with spaces in command",
			method:       "POST",
			commandLine:  "cmd /C echo hello world",
			wait:         1,
			sync:         echoSync(),
			expectedCode: http.StatusOK,
			expectedBody: "hello world\r\n",
		},
		{
			name:         "Async returns started message",
			method:       "GET",
			commandLine:  "cmd /C echo bg",
			wait:         0,
			expectedCode: http.StatusOK,
			expectedBody: "Command started successfully",
		},
		{
			name:         "Non-zero exit returns 200 with body",
			method:       "GET",
			commandLine:  "cmd /C exit 7",
			wait:         1,
			sync: &command.FakeSync{OnRun: func(c command.Command) (command.Result, error) {
				return command.Result{Stdout: "partial output\r\n", ExitCode: 7}, &command.ErrNonZeroExit{Code: 7}
			}},
			expectedCode: http.StatusOK,
			expectedBody: "partial output\r\n",
		},
		{
			name:         "Timeout returns generic 500",
			method:       "GET",
			commandLine:  "cmd /C waitforever",
			wait:         1,
			sync: &command.FakeSync{OnRun: func(c command.Command) (command.Result, error) {
				return command.Result{}, &command.ErrTimeout{Duration: 30 * time.Second}
			}},
			expectedCode: http.StatusInternalServerError,
			expectedBody: "Command execution failed\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := setupTestApp(t)
			if tt.sync != nil {
				app.sync = tt.sync
			}
			if tt.async != nil {
				app.async = tt.async
			}

			req := newCommandRequest(t, tt.method, tt.commandLine, tt.wait)
			req.RemoteAddr = "127.0.0.1:12345"

			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(app.commandHandler)
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedCode {
				t.Fatalf("status: got %d, want %d, body: %q", rr.Code, tt.expectedCode, rr.Body.String())
			}
			if tt.expectedBody != "" && rr.Body.String() != tt.expectedBody {
				t.Errorf("body: got %q, want %q", rr.Body.String(), tt.expectedBody)
			}
		})
	}
}

func TestConcurrentCommandExecution(t *testing.T) {
	app := setupTestApp(t)
	app.sync = echoSync()

	const numRequests = 10
	var wg sync.WaitGroup
	results := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			cmd := fmt.Sprintf("cmd /C echo Test_%d", id)
			req := newCommandRequest(t, "GET", cmd, 1)
			req.RemoteAddr = "127.0.0.1:12345"

			rr := httptest.NewRecorder()
			http.HandlerFunc(app.commandHandler).ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				results <- fmt.Errorf("request %d failed status %d: %s", id, rr.Code, rr.Body.String())
				return
			}
			expected := fmt.Sprintf("Test_%d\r\n", id)
			if rr.Body.String() != expected {
				results <- fmt.Errorf("request %d output: got %q want %q", id, rr.Body.String(), expected)
				return
			}
			results <- nil
		}(i)
	}

	wg.Wait()
	close(results)

	for err := range results {
		if err != nil {
			t.Error(err)
		}
	}
}

func TestRequestValidation(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		commandLine  string
		wait         int64
		contentType  string
		expectedCode int
	}{
		{"Invalid method", "PUT", "cmd /C echo test", 1, "", http.StatusMethodNotAllowed},
		{"Missing wait parameter", "GET", "cmd /C echo test", 0 /* not added */, "", http.StatusBadRequest},
		{"Invalid wait value", "GET", "cmd /C echo test", 2, "", http.StatusBadRequest},
		{"Invalid content type", "POST", "cmd /C echo test", 1, "text/plain", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := setupTestApp(t)

			var req *http.Request
			if tt.method == "GET" {
				params := url.Values{}
				params.Add("CommandLine", tt.commandLine)
				if tt.name != "Missing wait parameter" {
					params.Add("Wait", fmt.Sprintf("%d", tt.wait))
				}
				req = httptest.NewRequest(tt.method, "/ExecuteCommand?"+params.Encode(), nil)
			} else {
				body := fmt.Sprintf(`{"CommandLine":"%s","Wait":%d}`, tt.commandLine, tt.wait)
				req = httptest.NewRequest(tt.method, "/ExecuteCommand", bytes.NewBufferString(body))
				if tt.contentType != "" {
					req.Header.Set("Content-Type", tt.contentType)
				} else {
					req.Header.Set("Content-Type", "application/json")
				}
			}
			req.RemoteAddr = "127.0.0.1:12345"

			rr := httptest.NewRecorder()
			http.HandlerFunc(app.commandHandler).ServeHTTP(rr, req)

			if rr.Code != tt.expectedCode {
				t.Errorf("got %d, want %d, body: %q", rr.Code, tt.expectedCode, rr.Body.String())
			}
		})
	}
}

// IP whitelist + trust_proxy semantics live in server/middleware_test.go now
// (see TestIPWhitelist). The handler no longer performs the IP check itself —
// it runs as a server-level middleware in createServeMux.

func TestHealthEndpoint(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()
	healthHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if got, want := rr.Body.String(), `{"status":"ok"}`; got != want {
		t.Errorf("body: got %q, want %q", got, want)
	}
	if got, want := rr.Header().Get("Content-Type"), "application/json"; got != want {
		t.Errorf("Content-Type: got %q, want %q", got, want)
	}
}

func TestGenericErrorMessages(t *testing.T) {
	app := setupTestApp(t)
	app.sync = &command.FakeSync{
		OnRun: func(c command.Command) (command.Result, error) {
			return command.Result{}, &command.ErrSpawnFailed{Cause: fmt.Errorf("internal: nonexistentcommand_xyz not found")}
		},
	}

	req := newCommandRequest(t, "GET", "nonexistentcommand_xyz", 1)
	req.RemoteAddr = "127.0.0.1:12345"

	rr := httptest.NewRecorder()
	http.HandlerFunc(app.commandHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Command execution failed") {
		t.Errorf("expected generic error message, got %q", body)
	}
	if strings.Contains(body, "nonexistentcommand_xyz") {
		t.Error("response leaked internal command details")
	}
}

func TestPolicyRejection(t *testing.T) {
	app := setupTestApp(t)
	app.cfg.Security.CommandPolicy = config.CommandPolicyConfig{
		Enabled:           true,
		AllowedExtensions: []string{".ps1"},
		AllowedDirectories: []config.AllowedDirectoryEntry{
			{Path: t.TempDir(), IncludeSubdirs: false},
		},
	}

	// Sync executor must NOT be called when policy rejects.
	app.sync = &command.FakeSync{
		OnRun: func(c command.Command) (command.Result, error) {
			t.Error("executor invoked despite policy rejection")
			return command.Result{}, nil
		},
	}

	req := newCommandRequest(t, "GET", `C:\evil\malware.exe`, 1)
	req.RemoteAddr = "127.0.0.1:12345"

	rr := httptest.NewRecorder()
	http.HandlerFunc(app.commandHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d, body %q", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "Command not permitted") {
		t.Errorf("expected generic 'Command not permitted', got %q", rr.Body.String())
	}
}

// newCommandRequest builds a GET (with query params) or POST (with JSON body)
// request to /ExecuteCommand for handler testing.
func newCommandRequest(t *testing.T, method, commandLine string, wait int64) *http.Request {
	t.Helper()
	switch method {
	case "GET":
		params := url.Values{}
		params.Add("CommandLine", commandLine)
		params.Add("Wait", fmt.Sprintf("%d", wait))
		return httptest.NewRequest("GET", "/ExecuteCommand?"+params.Encode(), nil)
	case "POST":
		body := fmt.Sprintf(`{"CommandLine":"%s","Wait":%d}`, strings.ReplaceAll(commandLine, `"`, `\"`), wait)
		req := httptest.NewRequest("POST", "/ExecuteCommand", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		return req
	default:
		req := httptest.NewRequest(method, "/ExecuteCommand", nil)
		return req
	}
}
