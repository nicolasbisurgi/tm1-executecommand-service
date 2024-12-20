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

	"github.com/Hubert-Heijkers/tm1-executecommand-service/config"
	"github.com/Hubert-Heijkers/tm1-executecommand-service/ip"
	"github.com/Hubert-Heijkers/tm1-executecommand-service/logger"
)

func setupTestConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			HTTPPort:              8080,
			CommandTimeoutSeconds: 30,
		},
		Security: config.SecurityConfig{
			IPWhitelist: config.IPWhitelistConfig{
				Enabled:    true,
				AllowedIPs: []string{"127.0.0.1"},
			},
		},
	}
}

func setupTestEnvironment(t *testing.T) {
	cfg = setupTestConfig()
	var err error
	_, err = logger.InitLogger(cfg)
	if err != nil {
		t.Fatalf("Failed to initialize logger: %v", err)
	}

	// Initialize IP checker
	ipChecker, err = ip.NewIPChecker(cfg.Security.IPWhitelist.AllowedIPs)
	if err != nil {
		t.Fatalf("Failed to initialize IP checker: %v", err)
	}
}

func TestBasicCommandExecution(t *testing.T) {
	setupTestEnvironment(t)

	tests := []struct {
		name          string
		method        string
		commandLine   string
		wait          int64
		expectedCode  int
		expectedError bool
		checkOutput   func(string) bool
	}{
		{
			name:         "Simple echo command",
			method:       "GET",
			commandLine:  "cmd /C echo test",
			wait:         1,
			expectedCode: http.StatusOK,
			checkOutput: func(output string) bool {
				return output == "test\r\n"
			},
		},
		{
			name:          "Invalid command",
			method:        "GET",
			commandLine:   "nonexistentcommand",
			wait:          1,
			expectedCode:  http.StatusInternalServerError,
			expectedError: true,
		},
		{
			name:          "Empty command",
			method:        "GET",
			commandLine:   "",
			wait:          1,
			expectedCode:  http.StatusBadRequest,
			expectedError: true,
		},
		{
			name:         "Command with spaces",
			method:       "POST",
			commandLine:  "cmd /C echo hello world",
			wait:         1,
			expectedCode: http.StatusOK,
			checkOutput: func(output string) bool {
				return output == "hello world\r\n"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request

			if tt.method == "GET" {
				params := url.Values{}
				params.Add("CommandLine", tt.commandLine)
				params.Add("Wait", fmt.Sprintf("%d", tt.wait))
				req = httptest.NewRequest("GET", "/ExecuteCommand?"+params.Encode(), nil)
			} else {
				// For POST requests, create proper JSON body
				jsonStr := fmt.Sprintf(`{"CommandLine":"%s","Wait":%d}`, strings.ReplaceAll(tt.commandLine, `"`, `\"`), tt.wait)
				req = httptest.NewRequest("POST", "/ExecuteCommand", bytes.NewBufferString(jsonStr))
				req.Header.Set("Content-Type", "application/json")
			}

			req.RemoteAddr = "127.0.0.1:12345"

			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(commandHandler)
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedCode {
				t.Errorf("handler returned wrong status code: got %v want %v, body: %q",
					rr.Code, tt.expectedCode, rr.Body.String())
			}

			if !tt.expectedError && tt.checkOutput != nil {
				if !tt.checkOutput(rr.Body.String()) {
					t.Errorf("unexpected output: %q", rr.Body.String())
				}
			}
		})
	}
}

func TestConcurrentCommandExecution(t *testing.T) {
	setupTestEnvironment(t)

	const numRequests = 10
	var wg sync.WaitGroup
	results := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			params := url.Values{}
			params.Add("CommandLine", fmt.Sprintf("cmd /C echo Test %d", id))
			params.Add("Wait", "1")

			req := httptest.NewRequest("GET", "/ExecuteCommand?"+params.Encode(), nil)
			req.RemoteAddr = "127.0.0.1:12345"
			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(commandHandler)
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				results <- fmt.Errorf("request %d failed with status %d: %s", id, rr.Code, rr.Body.String())
				return
			}

			expected := fmt.Sprintf("Test %d\r\n", id)
			if rr.Body.String() != expected {
				results <- fmt.Errorf("request %d returned unexpected output: got %q, want %q",
					id, rr.Body.String(), expected)
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

func TestLongRunningCommand(t *testing.T) {
	setupTestEnvironment(t)
	cfg.Server.CommandTimeoutSeconds = 2

	tests := []struct {
		name          string
		commandLine   string
		wait          int64
		expectedCode  int
		shouldTimeout bool
	}{
		{
			name:         "Command within timeout",
			commandLine:  "cmd /C ping -n 2 127.0.0.1",
			wait:         1,
			expectedCode: http.StatusOK,
		},
		{
			name:          "Command exceeds timeout",
			commandLine:   "cmd /C ping -n 11 127.0.0.1",
			wait:          1,
			expectedCode:  http.StatusInternalServerError,
			shouldTimeout: true,
		},
		{
			name:         "Non-waiting command",
			commandLine:  "cmd /C ping -n 5 127.0.0.1",
			wait:         0,
			expectedCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := url.Values{}
			params.Add("CommandLine", tt.commandLine)
			params.Add("Wait", fmt.Sprintf("%d", tt.wait))

			req := httptest.NewRequest("GET", "/ExecuteCommand?"+params.Encode(), nil)
			req.RemoteAddr = "127.0.0.1:12345"
			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(commandHandler)

			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedCode {
				t.Errorf("handler returned wrong status code: got %v want %v, body: %q",
					rr.Code, tt.expectedCode, rr.Body.String())
			}

			if tt.shouldTimeout && !strings.Contains(rr.Body.String(), "command execution timed out") {
				t.Errorf("expected timeout error, got: %s", rr.Body.String())
			}
		})
	}
}

func TestCommandOutputEncoding(t *testing.T) {
	setupTestEnvironment(t)

	tests := []struct {
		name     string
		command  string
		expected string
	}{
		{
			name:     "ASCII output",
			command:  "cmd /C echo Hello",
			expected: "Hello\r\n",
		},
		{
			name:     "Special characters",
			// Using double caret to print a literal caret
			command:  "cmd /C echo @#$^^^&*()",
			expected: "@#$^&*()\r\n",
		},
		{
			name:     "Multiple lines",
			command:  "cmd /C (echo Line1&&echo Line2)",
			expected: "Line1\r\nLine2\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := url.Values{}
			params.Add("CommandLine", tt.command)
			params.Add("Wait", "1")

			req := httptest.NewRequest("GET", "/ExecuteCommand?"+params.Encode(), nil)
			req.RemoteAddr = "127.0.0.1:12345"
			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(commandHandler)
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v, body: %q",
					rr.Code, http.StatusOK, rr.Body.String())
			}

			if rr.Body.String() != tt.expected {
				t.Errorf("unexpected output: got %q, want %q", rr.Body.String(), tt.expected)
			}
		})
	}
}

func TestRequestValidation(t *testing.T) {
	setupTestEnvironment(t)

	tests := []struct {
		name         string
		method       string
		commandLine  string
		wait         int64
		contentType  string
		expectedCode int
	}{
		{
			name:         "Invalid method",
			method:       "PUT",
			commandLine:  "cmd /C echo test",
			wait:         1,
			expectedCode: http.StatusMethodNotAllowed,
		},
		{
			name:         "Missing wait parameter",
			method:       "GET",
			commandLine:  "cmd /C echo test",
			expectedCode: http.StatusBadRequest,
		},
		{
			name:         "Invalid wait value",
			method:       "GET",
			commandLine:  "cmd /C echo test",
			wait:         2,
			expectedCode: http.StatusBadRequest,
		},
		{
			name:         "Invalid content type",
			method:       "POST",
			commandLine:  "cmd /C echo test",
			wait:         1,
			contentType:  "text/plain",
			expectedCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request

			if tt.method == "GET" {
				params := url.Values{}
				params.Add("CommandLine", tt.commandLine)
				if tt.wait != 0 {
					params.Add("Wait", fmt.Sprintf("%d", tt.wait))
				}
				req = httptest.NewRequest(tt.method, "/ExecuteCommand?"+params.Encode(), nil)
			} else {
				// For POST requests, create proper JSON body
				jsonStr := fmt.Sprintf(`{"CommandLine":"%s","Wait":%d}`, strings.ReplaceAll(tt.commandLine, `"`, `\"`), tt.wait)
				req = httptest.NewRequest(tt.method, "/ExecuteCommand", bytes.NewBufferString(jsonStr))
				if tt.contentType != "" {
					req.Header.Set("Content-Type", tt.contentType)
				} else {
					req.Header.Set("Content-Type", "application/json")
				}
			}

			req.RemoteAddr = "127.0.0.1:12345"
			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(commandHandler)
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedCode {
				t.Errorf("handler returned wrong status code: got %v want %v, body: %q",
					rr.Code, tt.expectedCode, rr.Body.String())
			}
		})
	}
}