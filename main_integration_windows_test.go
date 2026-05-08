//go:build windows

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Hubert-Heijkers/tm1-executecommand-service/command"
	"github.com/Hubert-Heijkers/tm1-executecommand-service/config"
	"github.com/Hubert-Heijkers/tm1-executecommand-service/ip"
	"github.com/Hubert-Heijkers/tm1-executecommand-service/logger"
)

// integrationApp wires real executors so handler-level tests can verify the
// full HTTP → parse → policy → exec → response chain on Windows. The unit
// tests in main_test.go use fakes; this file exists for the cases where
// real cmd.exe / powershell behavior is the actual subject (output encoding,
// shell-quoting quirks).
func integrationApp(t *testing.T) *App {
	t.Helper()
	cfg := &config.Config{
		Server: config.ServerConfig{HTTPPort: 8080, CommandTimeoutSeconds: 30},
		Security: config.SecurityConfig{
			IPWhitelist: config.IPWhitelistConfig{Enabled: true, AllowedIPs: []string{"127.0.0.1"}},
		},
	}
	lg, err := logger.InitLogger(cfg)
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	ipChecker, err := ip.NewIPChecker(cfg.Security.IPWhitelist.AllowedIPs)
	if err != nil {
		t.Fatalf("ip checker: %v", err)
	}
	return &App{
		cfg:       cfg,
		ipChecker: ipChecker,
		logger:    lg,
		sync:      command.NewSyncExecutor(time.Duration(cfg.Server.CommandTimeoutSeconds) * time.Second),
		async:     command.NewAsyncExecutor(),
	}
}

func TestCommandOutputEncoding(t *testing.T) {
	app := integrationApp(t)

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
			name:     "Caret-escaped special characters",
			command:  "cmd /C echo @#$^^^&*()",
			expected: "@#$^&*()\r\n",
		},
		{
			name:     "Multiple lines via && compound",
			command:  "cmd /C (echo Line1&&echo Line2)",
			expected: "Line1\r\nLine2\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newCommandRequest(t, "GET", tt.command, 1)
			req.RemoteAddr = "127.0.0.1:12345"
			rr := httptest.NewRecorder()
			http.HandlerFunc(app.commandHandler).ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("status: got %d, want 200, body %q", rr.Code, rr.Body.String())
			}
			if rr.Body.String() != tt.expected {
				t.Errorf("body: got %q, want %q", rr.Body.String(), tt.expected)
			}
		})
	}
}
