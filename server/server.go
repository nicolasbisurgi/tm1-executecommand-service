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
	"github.com/Hubert-Heijkers/tm1-executecommand-service/logger"
)

type Server struct {
	httpServer  *http.Server
	httpsServer *http.Server
	config      *config.Config
	logger      *logger.CommandLogger
	handlers    map[string]http.HandlerFunc
}

func NewServer(cfg *config.Config, log *logger.CommandLogger) *Server {
	return &Server{
		config:   cfg,
		logger:   log,
		handlers: make(map[string]http.HandlerFunc),
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
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		// Session tickets and caching enabled for faster subsequent TLS handshakes
		SessionTicketsDisabled: false,
		ClientSessionCache:     tls.NewLRUClientSessionCache(128),
	}
}

func (s *Server) createServeMux() http.Handler {
	mux := http.NewServeMux()

	for path, handler := range s.handlers {
		wrappedHandler := SecurityHeaders(handler)
		mux.Handle(path, wrappedHandler)
	}

	return mux
}

func maybeRedirectToHTTPS(cfg *config.Config, httpsPort string, baseHandler http.Handler) http.Handler {
	if cfg != nil && cfg.Security.HTTPS.Enabled {
		return HTTPSRedirect(httpsPort)(baseHandler)
	}
	return baseHandler
}

func (s *Server) waitForPort(port string) error {
	for i := 0; i < 10; i++ {
		conn, err := net.Dial("tcp", "127.0.0.1:"+port)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("port %s not ready after waiting", port)
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

			if err := s.waitForPort(httpPort); err == nil {
				readyChan <- struct{}{}
				s.logger.Info(fmt.Sprintf("HTTP server listening on port %s", httpPort))
			} else {
				errChan <- err
				return
			}

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

			if err := s.waitForPort(httpsPort); err == nil {
				readyChan <- struct{}{}
				s.logger.Info(fmt.Sprintf("HTTPS server listening on port %s", httpsPort))
			} else {
				errChan <- err
				return
			}

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

	// At this point, servers are ready. Start self-warm goroutine.
	go func() {
		client := &http.Client{
			Timeout: 5 * time.Second,
		}

		var healthURL string
		// If HTTP is available, use it for health checks to avoid TLS overhead.
		if !s.config.Security.HTTPS.Enabled || httpPort != "" {
			healthURL = "http://127.0.0.1:" + httpPort + "/health"
		} else {
			// If only HTTPS is available, use HTTPS. If testing with self-signed certs, consider InsecureSkipVerify.
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