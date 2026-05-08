package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Hubert-Heijkers/tm1-executecommand-service/config"
	"github.com/Hubert-Heijkers/tm1-executecommand-service/ip"
	"github.com/Hubert-Heijkers/tm1-executecommand-service/logger"
)

func setupTestServer(t *testing.T) (*Server, func()) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTPPort:              8080,
			CommandTimeoutSeconds: 30,
		},
		Security: config.SecurityConfig{
			HTTPS: config.HTTPSConfig{
				Enabled: false,
			},
			IPWhitelist: config.IPWhitelistConfig{
				Enabled: false,
			},
			CommandPolicy: config.CommandPolicyConfig{
				Enabled: false,
			},
			Authentication: config.AuthConfig{
				Enabled: false,
			},
			RateLimit: config.RateLimitConfig{
				Enabled: false,
			},
		},
	}

	log, err := logger.InitLogger(cfg)
	if err != nil {
		t.Fatalf("Failed to initialize logger: %v", err)
	}

	srv := NewServer(cfg, log, nil)

	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}

	return srv, cleanup
}

func TestServerBasicHTTP(t *testing.T) {
	srv, cleanup := setupTestServer(t)
	defer cleanup()

	srv.RegisterHandler("/test", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "test response")
	})

	testServer := httptest.NewServer(srv.createServeMux())
	defer testServer.Close()

	resp, err := http.Get(testServer.URL + "/test")
	if err != nil {
		t.Fatalf("Failed to make HTTP request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if string(body) != "test response" {
		t.Errorf("Unexpected response body: got %q, want %q", string(body), "test response")
	}
}

func TestSecurityHeaders(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "test response")
	})

	t.Run("With HTTPS enabled", func(t *testing.T) {
		secureHandler := SecurityHeaders(true, handler)

		req := httptest.NewRequest("GET", "/test", nil)
		rec := httptest.NewRecorder()
		secureHandler.ServeHTTP(rec, req)

		expectedHeaders := map[string]string{
			"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
			"X-Content-Type-Options":    "nosniff",
			"X-Frame-Options":           "DENY",
			"Content-Security-Policy":   "default-src 'self'",
			"Referrer-Policy":           "strict-origin-when-cross-origin",
		}

		for header, expected := range expectedHeaders {
			if got := rec.Header().Get(header); got != expected {
				t.Errorf("Header %q = %q, want %q", header, got, expected)
			}
		}
	})

	t.Run("Without HTTPS - no HSTS", func(t *testing.T) {
		secureHandler := SecurityHeaders(false, handler)

		req := httptest.NewRequest("GET", "/test", nil)
		rec := httptest.NewRecorder()
		secureHandler.ServeHTTP(rec, req)

		// HSTS should NOT be set when HTTPS is disabled
		if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
			t.Errorf("HSTS should not be set when HTTPS is disabled, got %q", got)
		}

		// Other security headers should still be present
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("X-Content-Type-Options = %q, want %q", got, "nosniff")
		}
	})
}

func TestServerShutdown(t *testing.T) {
	srv, cleanup := setupTestServer(t)
	defer cleanup()

	testServer := httptest.NewServer(srv.createServeMux())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	testServer.Close()

	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("Server shutdown failed: %v", err)
	}

	_, err := http.Get(testServer.URL + "/test")
	if err == nil {
		t.Error("Expected error after shutdown, got none")
	}
}

func TestServerConcurrency(t *testing.T) {
	srv, cleanup := setupTestServer(t)
	defer cleanup()

	srv.RegisterHandler("/test", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		fmt.Fprint(w, "test response")
	})

	testServer := httptest.NewServer(srv.createServeMux())
	defer testServer.Close()

	const concurrentRequests = 10
	var wg sync.WaitGroup
	errors := make(chan error, concurrentRequests)

	for i := 0; i < concurrentRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(testServer.URL + "/test")
			if err != nil {
				errors <- fmt.Errorf("request failed: %v", err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				errors <- fmt.Errorf("unexpected status code: %d", resp.StatusCode)
				return
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				errors <- fmt.Errorf("failed to read body: %v", err)
				return
			}

			if string(body) != "test response" {
				errors <- fmt.Errorf("unexpected response: %s", string(body))
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		if err != nil {
			t.Error(err)
		}
	}
}

const maxRequestSize = 1024 * 1024 // 1MB max request size

func TestServerRequestSizeLimit(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > maxRequestSize {
			http.Error(w, "Request too large", http.StatusBadRequest)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
		_, err := io.ReadAll(r.Body)
		if err != nil {
			if err.Error() == "http: request body too large" {
				http.Error(w, "Request too large", http.StatusBadRequest)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		fmt.Fprintf(w, "received request")
	})

	testServer := httptest.NewServer(handler)
	defer testServer.Close()

	largeBody := make([]byte, maxRequestSize+1)
	resp, err := http.Post(testServer.URL, "application/octet-stream", bytes.NewReader(largeBody))
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status %d for large request, got %d", http.StatusBadRequest, resp.StatusCode)
	}

	smallBody := make([]byte, maxRequestSize/2)
	resp, err = http.Post(testServer.URL, "application/octet-stream", bytes.NewReader(smallBody))
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d for acceptable request, got %d", http.StatusOK, resp.StatusCode)
	}
}

// TestFullMiddlewareChain pins the composed chain
//   RequestID → IPWhitelist → RateLimit → APIKeyAuth → SecurityHeaders → mux
// Verifies short-circuit ordering, /health bypass semantics, X-Request-ID
// propagation on every response, and that an authorized happy path reaches
// the handler. Catches regressions when createServeMux is reordered.
func TestFullMiddlewareChain(t *testing.T) {
	const apiKey = "test-api-key-that-is-at-least-32-chars-long!!"

	cfg := &config.Config{
		Server: config.ServerConfig{HTTPPort: 8080, CommandTimeoutSeconds: 30},
		Security: config.SecurityConfig{
			HTTPS: config.HTTPSConfig{Enabled: false},
			IPWhitelist: config.IPWhitelistConfig{
				Enabled:    true,
				AllowedIPs: []string{"127.0.0.1", "::1"},
			},
			Authentication: config.AuthConfig{
				Enabled: true,
				APIKey:  apiKey,
			},
			RateLimit: config.RateLimitConfig{
				Enabled:           true,
				RequestsPerMinute: 1000, // high enough not to interfere with main cases
			},
			CommandPolicy: config.CommandPolicyConfig{Enabled: false},
		},
	}

	lg, err := logger.InitLogger(cfg)
	if err != nil {
		t.Fatalf("logger init: %v", err)
	}
	checker, err := ip.NewIPChecker(cfg.Security.IPWhitelist.AllowedIPs)
	if err != nil {
		t.Fatalf("ip checker: %v", err)
	}

	srv := NewServer(cfg, lg, checker)
	srv.RegisterHandler("/ExecuteCommand", func(w http.ResponseWriter, r *http.Request) {
		// Echo the resolved request ID so tests can assert end-to-end propagation.
		fmt.Fprintf(w, "ok|%s", RequestIDFrom(r.Context()))
	})
	srv.RegisterHandler("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "alive")
	})

	ts := httptest.NewServer(srv.createServeMux())
	defer ts.Close()

	get := func(t *testing.T, path string, headers map[string]string) (*http.Response, string) {
		t.Helper()
		req, err := http.NewRequest("GET", ts.URL+path, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(body)
	}

	t.Run("X-Request-ID set on every response", func(t *testing.T) {
		// Even on rejection, the outermost RequestID middleware must have run.
		resp, _ := get(t, "/ExecuteCommand", nil) // no auth → 401
		if resp.Header.Get("X-Request-ID") == "" {
			t.Error("X-Request-ID missing on 401 response")
		}
	})

	t.Run("Authorized happy path reaches handler", func(t *testing.T) {
		resp, body := get(t, "/ExecuteCommand", map[string]string{
			"Authorization": "Bearer " + apiKey,
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status: got %d, want 200, body: %q", resp.StatusCode, body)
		}
		// Handler echoed `ok|<request-id>`. Confirm it matches the response header.
		want := "ok|" + resp.Header.Get("X-Request-ID")
		if body != want {
			t.Errorf("body: got %q, want %q (request ID parity)", body, want)
		}
		// Security headers must be present on success.
		if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("X-Content-Type-Options: got %q, want nosniff", got)
		}
	})

	t.Run("APIKeyAuth rejects requests without Bearer token", func(t *testing.T) {
		resp, _ := get(t, "/ExecuteCommand", nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status: got %d, want 401", resp.StatusCode)
		}
	})

	t.Run("APIKeyAuth rejects wrong key", func(t *testing.T) {
		resp, _ := get(t, "/ExecuteCommand", map[string]string{
			"Authorization": "Bearer wrong-key-of-sufficient-length-blah-blah-blah",
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status: got %d, want 401", resp.StatusCode)
		}
	})

	t.Run("/health bypasses APIKeyAuth", func(t *testing.T) {
		resp, body := get(t, "/health", nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status: got %d, want 200", resp.StatusCode)
		}
		if body != "alive" {
			t.Errorf("body: got %q, want %q", body, "alive")
		}
	})
}

// TestFullMiddlewareChain_IPRejectionShortCircuits verifies IPWhitelist
// short-circuits before APIKeyAuth — i.e. a request with a valid Bearer
// token from a disallowed IP still gets 403, not 200, even on /health.
//
// Test client always connects from 127.0.0.1; we exclude that to provoke
// the rejection path.
func TestFullMiddlewareChain_IPRejectionShortCircuits(t *testing.T) {
	const apiKey = "test-api-key-that-is-at-least-32-chars-long!!"

	cfg := &config.Config{
		Server: config.ServerConfig{HTTPPort: 8080, CommandTimeoutSeconds: 30},
		Security: config.SecurityConfig{
			IPWhitelist: config.IPWhitelistConfig{
				Enabled:    true,
				AllowedIPs: []string{"10.99.99.99"}, // intentionally not the test client
			},
			Authentication: config.AuthConfig{Enabled: true, APIKey: apiKey},
		},
	}

	lg, _ := logger.InitLogger(cfg)
	checker, _ := ip.NewIPChecker(cfg.Security.IPWhitelist.AllowedIPs)
	srv := NewServer(cfg, lg, checker)
	srv.RegisterHandler("/ExecuteCommand", func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler reached despite disallowed IP")
	})
	srv.RegisterHandler("/health", func(w http.ResponseWriter, r *http.Request) {
		t.Error("health reached despite disallowed IP — IPWhitelist must NOT bypass")
	})

	ts := httptest.NewServer(srv.createServeMux())
	defer ts.Close()

	for _, path := range []string{"/ExecuteCommand", "/health"} {
		t.Run(path, func(t *testing.T) {
			req, _ := http.NewRequest("GET", ts.URL+path, nil)
			req.Header.Set("Authorization", "Bearer "+apiKey)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("status: got %d, want 403", resp.StatusCode)
			}
			// Even on rejection, X-Request-ID must be set (RequestID is outermost).
			if resp.Header.Get("X-Request-ID") == "" {
				t.Error("X-Request-ID missing on rejection response")
			}
		})
	}
}
