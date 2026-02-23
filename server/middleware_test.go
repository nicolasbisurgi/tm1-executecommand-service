package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPSRedirect(t *testing.T) {
	tests := []struct {
		name           string
		httpsPort      string
		requestURL     string
		expectedStatus int
		expectedURL    string
	}{
		{
			name:           "Basic HTTP to HTTPS redirect",
			httpsPort:      "443",
			requestURL:     "http://example.com/test",
			expectedStatus: http.StatusPermanentRedirect,
			expectedURL:    "https://example.com/test",
		},
		{
			name:           "Custom HTTPS port redirect",
			httpsPort:      "8443",
			requestURL:     "http://example.com/test",
			expectedStatus: http.StatusPermanentRedirect,
			expectedURL:    "https://example.com:8443/test",
		},
		{
			name:           "Preserve query parameters",
			httpsPort:      "443",
			requestURL:     "http://example.com/test?param=value",
			expectedStatus: http.StatusPermanentRedirect,
			expectedURL:    "https://example.com/test?param=value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("Handler should not be called during redirect")
			})

			redirectHandler := HTTPSRedirect(tt.httpsPort)(handler)

			req := httptest.NewRequest("GET", tt.requestURL, nil)
			rec := httptest.NewRecorder()

			redirectHandler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rec.Code)
			}

			location := rec.Header().Get("Location")
			if location != tt.expectedURL {
				t.Errorf("Expected redirect to %q, got %q", tt.expectedURL, location)
			}
		})
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	tests := []struct {
		name            string
		method          string
		path            string
		httpsEnabled    bool
		expectedHeaders map[string]string
		absentHeaders   []string
		expectedStatus  int
	}{
		{
			name:         "GET request with HTTPS",
			method:       "GET",
			path:         "/test",
			httpsEnabled: true,
			expectedHeaders: map[string]string{
				"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
				"X-Content-Type-Options":    "nosniff",
				"X-Frame-Options":           "DENY",
				"Content-Security-Policy":   "default-src 'self'",
				"Referrer-Policy":           "strict-origin-when-cross-origin",
				"Permissions-Policy":        "camera=(), microphone=(), geolocation=()",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:         "GET request without HTTPS - no HSTS",
			method:       "GET",
			path:         "/test",
			httpsEnabled: false,
			expectedHeaders: map[string]string{
				"X-Content-Type-Options":  "nosniff",
				"X-Frame-Options":         "DENY",
				"Content-Security-Policy": "default-src 'self'",
			},
			absentHeaders:  []string{"Strict-Transport-Security"},
			expectedStatus: http.StatusOK,
		},
		{
			name:         "POST request security headers",
			method:       "POST",
			path:         "/test",
			httpsEnabled: true,
			expectedHeaders: map[string]string{
				"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
				"X-Content-Type-Options":    "nosniff",
				"X-Frame-Options":           "DENY",
				"Content-Security-Policy":   "default-src 'self'",
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.expectedStatus)
				w.Write([]byte("test response"))
			})

			secureHandler := SecurityHeaders(tt.httpsEnabled, handler)

			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()

			secureHandler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rec.Code)
			}

			for header, expected := range tt.expectedHeaders {
				if got := rec.Header().Get(header); got != expected {
					t.Errorf("Header %q = %q, want %q", header, got, expected)
				}
			}

			for _, header := range tt.absentHeaders {
				if got := rec.Header().Get(header); got != "" {
					t.Errorf("Header %q should be absent, got %q", header, got)
				}
			}
		})
	}
}

func TestAPIKeyAuth(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	apiKey := "test-api-key-that-is-at-least-32-chars-long!!"

	authed := APIKeyAuth(apiKey, handler)

	tests := []struct {
		name         string
		auth         string
		path         string
		expectedCode int
	}{
		{
			name:         "Valid key",
			auth:         "Bearer " + apiKey,
			path:         "/test",
			expectedCode: http.StatusOK,
		},
		{
			name:         "Invalid key",
			auth:         "Bearer wrong-key",
			path:         "/test",
			expectedCode: http.StatusUnauthorized,
		},
		{
			name:         "Missing authorization header",
			auth:         "",
			path:         "/test",
			expectedCode: http.StatusUnauthorized,
		},
		{
			name:         "Wrong auth scheme",
			auth:         "Basic " + apiKey,
			path:         "/test",
			expectedCode: http.StatusUnauthorized,
		},
		{
			name:         "Health endpoint bypasses auth",
			auth:         "",
			path:         "/health",
			expectedCode: http.StatusOK,
		},
		{
			name:         "Health endpoint with wrong key still passes",
			auth:         "Bearer wrong-key",
			path:         "/health",
			expectedCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			if tt.auth != "" {
				req.Header.Set("Authorization", tt.auth)
			}

			rec := httptest.NewRecorder()
			authed.ServeHTTP(rec, req)

			if rec.Code != tt.expectedCode {
				t.Errorf("Expected %d, got %d, body: %q", tt.expectedCode, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestRateLimit(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("Under limit passes", func(t *testing.T) {
		limited := RateLimit(5, handler)

		for i := 0; i < 5; i++ {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			rec := httptest.NewRecorder()
			limited.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("Request %d: expected 200, got %d", i+1, rec.Code)
			}
		}
	})

	t.Run("Over limit returns 429", func(t *testing.T) {
		limited := RateLimit(3, handler)

		// First 3 should pass
		for i := 0; i < 3; i++ {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "10.0.0.1:12345"
			rec := httptest.NewRecorder()
			limited.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("Request %d: expected 200, got %d", i+1, rec.Code)
			}
		}

		// 4th should be rate limited
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		rec := httptest.NewRecorder()
		limited.ServeHTTP(rec, req)

		if rec.Code != http.StatusTooManyRequests {
			t.Errorf("Expected 429, got %d", rec.Code)
		}
	})

	t.Run("Per-IP isolation", func(t *testing.T) {
		limited := RateLimit(2, handler)

		// Exhaust limit for IP1
		for i := 0; i < 3; i++ {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.10:12345"
			rec := httptest.NewRecorder()
			limited.ServeHTTP(rec, req)
		}

		// IP2 should still have capacity
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.20:12345"
		rec := httptest.NewRecorder()
		limited.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Different IP should not be rate limited, got %d", rec.Code)
		}
	})
}

func TestMiddlewareChaining(t *testing.T) {
	var executionOrder []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		executionOrder = append(executionOrder, "handler")
		w.Write([]byte("test response"))
	})

	testMiddleware1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			executionOrder = append(executionOrder, "middleware1")
			next.ServeHTTP(w, r)
		})
	}

	testMiddleware2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			executionOrder = append(executionOrder, "middleware2")
			next.ServeHTTP(w, r)
		})
	}

	finalHandler := testMiddleware1(testMiddleware2(SecurityHeaders(true, handler)))

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	finalHandler.ServeHTTP(rec, req)

	expectedOrder := []string{"middleware1", "middleware2", "handler"}
	for i, step := range expectedOrder {
		if i >= len(executionOrder) || executionOrder[i] != step {
			t.Errorf("Incorrect middleware execution order. Expected %v, got %v", expectedOrder, executionOrder)
			break
		}
	}

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
	}

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

func TestStripPort(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"192.168.1.1:8080", "192.168.1.1"},
		{"127.0.0.1:12345", "127.0.0.1"},
		{"[::1]:8080", "::1"},
		{"192.168.1.1", "192.168.1.1"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := stripPort(tt.input)
			if result != tt.expected {
				t.Errorf("stripPort(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
