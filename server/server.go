// server/server.go
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Hubert-Heijkers/tm1-executecommand-service/config"
	"github.com/Hubert-Heijkers/tm1-executecommand-service/ip"
	"github.com/Hubert-Heijkers/tm1-executecommand-service/logger"
)

type Server struct {
	httpServer  *http.Server
	httpsServer *http.Server
	config      *config.Config
	logger      *logger.CommandLogger
	ipChecker   *ip.IPChecker
	handlers    map[string]http.HandlerFunc
}

// NewServer constructs a Server. ipChecker may be nil when the IP whitelist
// is disabled — createServeMux only wires the IPWhitelist middleware when
// both the config flag is on AND the checker is non-nil.
func NewServer(cfg *config.Config, log *logger.CommandLogger, ipChecker *ip.IPChecker) *Server {
	return &Server{
		config:    cfg,
		logger:    log,
		ipChecker: ipChecker,
		handlers:  make(map[string]http.HandlerFunc),
	}
}

func (s *Server) RegisterHandler(path string, handler http.HandlerFunc) {
	s.handlers[path] = handler
}

func (s *Server) setupTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		SessionTicketsDisabled: false,
	}
}

func (s *Server) createServeMux() http.Handler {
	mux := http.NewServeMux()
	for path, handler := range s.handlers {
		mux.HandleFunc(path, handler)
	}

	// Build middleware chain (innermost -> outermost). Final order:
	//   RequestID → IPWhitelist → RateLimit → APIKeyAuth → SecurityHeaders → mux
	// RequestID is OUTERMOST so every other layer (including rejection logs
	// from IPWhitelist / APIKeyAuth) can correlate with the X-Request-ID
	// header sent back to the caller.
	var h http.Handler = mux

	h = SecurityHeaders(s.config.Security.HTTPS.Enabled, h)

	if s.config.Security.Authentication.Enabled {
		h = APIKeyAuth(s.config.Security.Authentication.APIKey, h)
	}

	if s.config.Security.RateLimit.Enabled {
		h = RateLimit(s.config.Security.RateLimit.RequestsPerMinute, h)
	}

	if s.config.Security.IPWhitelist.Enabled && s.ipChecker != nil {
		h = IPWhitelist(
			s.ipChecker,
			s.config.Security.IPWhitelist.TrustProxy,
			s.config.Security.IPWhitelist.TrustedProxies,
			s.logger,
		)(h)
	}

	h = RequestID(h)

	return h
}

func maybeRedirectToHTTPS(cfg *config.Config, httpsPort string, baseHandler http.Handler) http.Handler {
	if cfg != nil && cfg.Security.HTTPS.Enabled {
		return HTTPSRedirect(httpsPort)(baseHandler)
	}
	return baseHandler
}

func (s *Server) Start(httpPort, httpsPort string) error {
	var wg sync.WaitGroup
	errChan := make(chan error, 2)
	readyChan := make(chan struct{}, 2)

	baseHandler := s.createServeMux()

	// Start HTTP server if required
	if !s.config.Security.HTTPS.Enabled || httpPort != "" {
		handler := maybeRedirectToHTTPS(s.config, httpsPort, baseHandler)
		s.httpServer = &http.Server{
			Addr:         ":" + httpPort,
			Handler:      handler,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
			ErrorLog:     log.New(s.logger.Writer(), "HTTP: ", log.Ldate|log.Ltime|log.Lshortfile),
		}
		s.httpServer.SetKeepAlivesEnabled(true)

		wg.Add(1)
		go func() {
			defer wg.Done()
			listener, err := net.Listen("tcp", ":"+httpPort)
			if err != nil {
				errChan <- fmt.Errorf("HTTP listener error: %v", err)
				return
			}

			// Listener created successfully — signal readiness
			readyChan <- struct{}{}
			s.logger.Info(fmt.Sprintf("HTTP server listening on port %s", httpPort))

			if err := s.httpServer.Serve(listener); err != http.ErrServerClosed {
				errChan <- fmt.Errorf("HTTP server error: %v", err)
			}
		}()
	}

	// Start HTTPS server if enabled
	if s.config.Security.HTTPS.Enabled {
		cert, err := tls.LoadX509KeyPair(s.config.Security.HTTPS.CertFile, s.config.Security.HTTPS.KeyFile)
		if err != nil {
			return fmt.Errorf("failed to load certificates: %v", err)
		}

		tlsConfig := s.setupTLSConfig()
		tlsConfig.Certificates = []tls.Certificate{cert}

		s.httpsServer = &http.Server{
			Addr:         ":" + httpsPort,
			Handler:      baseHandler,
			TLSConfig:    tlsConfig,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
			ErrorLog:     log.New(s.logger.Writer(), "HTTPS: ", log.Ldate|log.Ltime|log.Lshortfile),
		}
		s.httpsServer.SetKeepAlivesEnabled(true)

		wg.Add(1)
		go func() {
			defer wg.Done()

			listener, err := tls.Listen("tcp", ":"+httpsPort, tlsConfig)
			if err != nil {
				errChan <- fmt.Errorf("HTTPS listener error: %v", err)
				return
			}

			// Listener created successfully — signal readiness
			readyChan <- struct{}{}
			s.logger.Info(fmt.Sprintf("HTTPS server listening on port %s", httpsPort))

			if err := s.httpsServer.Serve(listener); err != http.ErrServerClosed {
				if !strings.Contains(err.Error(), "EOF") {
					errChan <- fmt.Errorf("HTTPS server error: %v", err)
				}
			}
		}()
	}

	expectedReadySignals := 0
	if !s.config.Security.HTTPS.Enabled || httpPort != "" {
		expectedReadySignals++
	}
	if s.config.Security.HTTPS.Enabled {
		expectedReadySignals++
	}

	// Wait for ready signals or errors
	for i := 0; i < expectedReadySignals; i++ {
		select {
		case err := <-errChan:
			return err
		case <-readyChan:
			continue
		}
	}

	// Self-warm goroutine for health checks
	go func() {
		client := &http.Client{
			Timeout: 5 * time.Second,
		}

		var healthURL string
		if !s.config.Security.HTTPS.Enabled || httpPort != "" {
			healthURL = "http://127.0.0.1:" + httpPort + "/health"
		} else {
			transport := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			client.Transport = transport
			healthURL = "https://127.0.0.1:" + httpsPort + "/health"
		}

		interval := 60 * time.Second
		for {
			resp, err := client.Get(healthURL)
			if err != nil {
				log.Printf("Self-warm health check failed: %v", err)
			} else if resp != nil {
				resp.Body.Close()
			}
			time.Sleep(interval)
		}
	}()

	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	var shutdownError error

	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			shutdownError = fmt.Errorf("HTTP server shutdown error: %v", err)
		}
	}

	if s.httpsServer != nil {
		if err := s.httpsServer.Shutdown(ctx); err != nil {
			if shutdownError != nil {
				shutdownError = fmt.Errorf("%v; HTTPS server shutdown error: %v", shutdownError, err)
			} else {
				shutdownError = fmt.Errorf("HTTPS server shutdown error: %v", err)
			}
		}
	}

	return shutdownError
}
