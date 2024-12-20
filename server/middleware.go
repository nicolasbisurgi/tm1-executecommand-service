// server/middleware.go
package server

import (
	"net/http"
	"strings"
)

// SecurityHeaders adds various security-related HTTP headers to all responses
func SecurityHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Security headers based on OWASP recommendations
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

		next(w, r)
	}
}

// HTTPSRedirect middleware redirects HTTP requests to HTTPS
func HTTPSRedirect(httpsPort string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip redirect if this is the health endpoint
			if r.URL.Path == "/health" {
				next.ServeHTTP(w, r)
				return
			}

			if r.Header.Get("X-Forwarded-Proto") != "https" && r.TLS == nil {
				host := r.Host
				// Remove port if present
				if strings.Contains(host, ":") {
					host = strings.Split(host, ":")[0]
				}

				// Only append non-standard HTTPS ports
				portSuffix := ""
				if httpsPort != "443" {
					portSuffix = ":" + httpsPort
				}

				httpsURL := "https://" + host + portSuffix + r.URL.RequestURI()
				http.Redirect(w, r, httpsURL, http.StatusPermanentRedirect)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
