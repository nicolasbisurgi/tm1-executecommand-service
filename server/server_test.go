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

	srv := NewServer(cfg, log)

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
