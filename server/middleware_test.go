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
		expectedHeaders map[string]string
		expectedStatus  int
	}{
		{
			name:   "GET request security headers",
			method: "GET",
			path:   "/test",
			expectedHeaders: map[string]string{
				"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
				"X-Content-Type-Options":    "nosniff",
				"X-Frame-Options":           "DENY",
				"Content-Security-Policy":   "default-src 'self'",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "POST request security headers",
			method: "POST",
			path:   "/test",
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

			secureHandler := SecurityHeaders(handler)

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
		})
	}
}

func TestSecurityHeadersWithErrors(t *testing.T) {
	tests := []struct {
		name           string
		handler       func(w http.ResponseWriter, r *http.Request)
		expectedCode  int
		checkHeaders  bool
	}{
		{
			name: "Panic in handler",
			handler: func(w http.ResponseWriter, r *http.Request) {
				panic("test panic")
			},
			expectedCode: http.StatusInternalServerError,
			checkHeaders: true,
		},
		{
			name: "Write after WriteHeader",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				w.WriteHeader(http.StatusOK) // Should be ignored
			},
			expectedCode: http.StatusBadRequest,
			checkHeaders: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(tt.handler)
			secureHandler := SecurityHeaders(handler)

			req := httptest.NewRequest("GET", "/test", nil)
			rec := httptest.NewRecorder()

			if tt.name == "Panic in handler" {
				defer func() {
					if r := recover(); r == nil {
						t.Error("Expected panic was not recovered")
					}
				}()
			}

			secureHandler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedCode {
				t.Errorf("Expected status %d, got %d", tt.expectedCode, rec.Code)
			}

			if tt.checkHeaders {
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
		})
	}
}

func TestMiddlewareChaining(t *testing.T) {
	// Create a handler that records the order of middleware execution
	var executionOrder []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		executionOrder = append(executionOrder, "handler")
		w.Write([]byte("test response"))
	})

	// Create test middleware
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

	// Chain middlewares
	finalHandler := testMiddleware1(testMiddleware2(SecurityHeaders(handler)))

	// Test request
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	finalHandler.ServeHTTP(rec, req)

	// Verify execution order
	expectedOrder := []string{"middleware1", "middleware2", "handler"}
	for i, step := range expectedOrder {
		if i >= len(executionOrder) || executionOrder[i] != step {
			t.Errorf("Incorrect middleware execution order. Expected %v, got %v", expectedOrder, executionOrder)
			break
		}
	}

	// Verify response
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
	}

	// Verify security headers are still present
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
