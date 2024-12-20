package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Hubert-Heijkers/tm1-executecommand-service/config"
	"github.com/Hubert-Heijkers/tm1-executecommand-service/logger"
)

func createTestCerts(t *testing.T) (certFile, keyFile string) {
	tmpDir := t.TempDir()
	certFile = filepath.Join(tmpDir, "test.crt")
	keyFile = filepath.Join(tmpDir, "test.key")

	// Generate test certificate and key
	cmd := fmt.Sprintf("openssl req -x509 -newkey rsa:4096 -keyout %s -out %s -days 1 -nodes -subj '/CN=localhost'", 
		keyFile, certFile)
	if err := exec.Command("sh", "-c", cmd).Run(); err != nil {
		t.Fatalf("Failed to generate test certificates: %v", err)
	}

	return certFile, keyFile
}

func setupTestServer(t *testing.T) (*Server, func()) {
	// Create test configuration
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTPPort:             8080,
			CommandTimeoutSeconds: 30,
		},
		Security: config.SecurityConfig{
			HTTPS: config.HTTPSConfig{
				Enabled: false,
			},
			IPWhitelist: config.IPWhitelistConfig{
				Enabled: false,
			},
		},
	}

	// Create test logger
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

	// Add test handler
	srv.RegisterHandler("/test", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "test response")
	})

	// Start server in test mode
	testServer := httptest.NewServer(srv.createServeMux())
	defer testServer.Close()

	// Test HTTP request
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
	_, cleanup := setupTestServer(t)
	defer cleanup()

	// Create test handler with security headers
	handler := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "test response")
	}
	secureHandler := SecurityHeaders(handler)

	// Create test request
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	// Execute handler
	secureHandler.ServeHTTP(rec, req)

	// Check security headers
	expectedHeaders := map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Content-Security-Policy":   "default-src 'self'",
	}

	for header, expected := range expectedHeaders {
		if got := rec.Header().Get(header); got != expected {
			t.Errorf("Header %q = %q, want %q", header, got, expected)
		}
	}
}

func TestServerShutdown(t *testing.T) {
	srv, cleanup := setupTestServer(t)
	defer cleanup()

	// Start server in test mode
	testServer := httptest.NewServer(srv.createServeMux())

	// Test graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Close test server
	testServer.Close()

	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("Server shutdown failed: %v", err)
	}

	// Verify server is no longer accepting connections
	_, err := http.Get(testServer.URL + "/test")
	if err == nil {
		t.Error("Expected error after shutdown, got none")
	}
}

func TestServerConcurrency(t *testing.T) {
	srv, cleanup := setupTestServer(t)
	defer cleanup()

	// Add test handler that simulates work
	srv.RegisterHandler("/test", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		fmt.Fprint(w, "test response")
	})

	// Start server in test mode
	testServer := httptest.NewServer(srv.createServeMux())
	defer testServer.Close()

	// Make concurrent requests
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
	// Create a test handler that enforces size limit
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

	// Start test server
	testServer := httptest.NewServer(handler)
	defer testServer.Close()

	// Test with large request body
	largeBody := make([]byte, maxRequestSize+1) // Exceed max size by 1 byte
	resp, err := http.Post(testServer.URL, "application/octet-stream", bytes.NewReader(largeBody))
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status %d for large request, got %d", http.StatusBadRequest, resp.StatusCode)
	}

	// Test with acceptable request body
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
