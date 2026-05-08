// server/middleware.go
package server

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Hubert-Heijkers/tm1-executecommand-service/ip"
	"github.com/Hubert-Heijkers/tm1-executecommand-service/logger"
	"github.com/google/uuid"
)

// ctxKey is unexported so values written by these middlewares cannot be
// overwritten by other packages putting strings into the context.
type ctxKey int

const requestIDKey ctxKey = iota

// RequestID assigns a UUID to every incoming request, propagates it via
// r.Context() so downstream layers can correlate logs, and echoes it on
// the response as X-Request-ID for the caller. It is the OUTERMOST
// middleware — every other layer's logs reference the value it sets.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.NewString()
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequestIDFrom returns the request ID set by the RequestID middleware,
// or "" if the middleware was not in the chain (e.g. a unit test calling
// the handler directly).
func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// IPWhitelist rejects requests whose source IP is not in the configured
// allowlist. When trustProxy is true and the request peer (RemoteAddr) is
// in trustedProxies, the leftmost X-Forwarded-For entry is used as the
// client identity — otherwise XFF is ignored to prevent spoofing.
//
// /health is NOT bypassed (per CONTEXT.md). Health probes from disallowed
// IPs return 403; the self-warm goroutine connects from localhost which
// callers are expected to allow.
func IPWhitelist(checker *ip.IPChecker, trustProxy bool, trustedProxies []string, lg *logger.CommandLogger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := resolveClientIP(r, trustProxy, trustedProxies)
			if !checker.IsAllowed(clientIP) {
				lg.LogAccessDenied("ip_not_in_whitelist", logger.Fields{
					"request_id":  RequestIDFrom(r.Context()),
					"client_ip":   clientIP,
					"remote_addr": r.RemoteAddr,
					"method":      r.Method,
					"path":        r.URL.Path,
				})
				http.Error(w, "Access denied", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// resolveClientIP returns the request's client IP, consulting X-Forwarded-For
// only when (a) trustProxy is enabled AND (b) the immediate peer is itself a
// trusted proxy. Otherwise the TCP peer's address is used.
func resolveClientIP(r *http.Request, trustProxy bool, trustedProxies []string) string {
	peer := stripPort(r.RemoteAddr)
	if !trustProxy {
		return peer
	}
	for _, proxy := range trustedProxies {
		if peer == proxy {
			xff := r.Header.Get("X-Forwarded-For")
			if xff == "" {
				return peer
			}
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[0])
		}
	}
	return peer
}

// SecurityHeaders adds OWASP-recommended security headers to all responses.
// HSTS is only included when httpsEnabled is true.
func SecurityHeaders(httpsEnabled bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if httpsEnabled {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

		next.ServeHTTP(w, r)
	})
}

// APIKeyAuth validates Bearer token authentication.
// The /health endpoint is excluded from authentication.
// Uses constant-time comparison to prevent timing attacks.
func APIKeyAuth(apiKey string, next http.Handler) http.Handler {
	keyBytes := []byte(apiKey)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health endpoint
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		token := auth[7:] // len("Bearer ") == 7
		if subtle.ConstantTimeCompare([]byte(token), keyBytes) != 1 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// rateLimiter implements a per-IP sliding window rate limiter.
type rateLimiter struct {
	mu       sync.Mutex
	counters map[string]*ipCounter
	rpm      int
}

type ipCounter struct {
	count    int
	lastSeen time.Time
	resetAt  time.Time
}

func newRateLimiter(rpm int) *rateLimiter {
	rl := &rateLimiter{
		counters: make(map[string]*ipCounter),
		rpm:      rpm,
	}
	go rl.cleanup()
	return rl
}

func (rl *rateLimiter) allow(ipAddr string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	counter, exists := rl.counters[ipAddr]

	if !exists || now.After(counter.resetAt) {
		rl.counters[ipAddr] = &ipCounter{
			count:    1,
			lastSeen: now,
			resetAt:  now.Add(time.Minute),
		}
		return true
	}

	counter.lastSeen = now
	counter.count++
	return counter.count <= rl.rpm
}

// cleanup periodically removes stale entries to prevent memory leaks.
func (rl *rateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, counter := range rl.counters {
			if now.Sub(counter.lastSeen) > 10*time.Minute {
				delete(rl.counters, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// RateLimit enforces per-IP rate limiting using a sliding window.
// Returns 429 Too Many Requests when the limit is exceeded.
func RateLimit(rpm int, next http.Handler) http.Handler {
	limiter := newRateLimiter(rpm)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := stripPort(r.RemoteAddr)
		if !limiter.allow(ip) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// HTTPSRedirect middleware redirects HTTP requests to HTTPS.
func HTTPSRedirect(httpsPort string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip redirect for health endpoint
			if r.URL.Path == "/health" {
				next.ServeHTTP(w, r)
				return
			}

			if r.Header.Get("X-Forwarded-Proto") != "https" && r.TLS == nil {
				host := r.Host
				if strings.Contains(host, ":") {
					host = strings.Split(host, ":")[0]
				}

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

// stripPort removes the port from an address string (e.g., "192.168.1.1:8080" -> "192.168.1.1").
func stripPort(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
