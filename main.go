package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Hubert-Heijkers/tm1-executecommand-service/command"
	"github.com/Hubert-Heijkers/tm1-executecommand-service/config"
	"github.com/Hubert-Heijkers/tm1-executecommand-service/ip"
	"github.com/Hubert-Heijkers/tm1-executecommand-service/logger"
	"github.com/Hubert-Heijkers/tm1-executecommand-service/server"
	"github.com/google/uuid"
)

const maxRequestSize = 1024 * 1024 // 1MB max request size

// App holds the application dependencies, replacing package-level globals.
type App struct {
	cfg       *config.Config
	ipChecker *ip.IPChecker
	logger    *logger.CommandLogger
	sync      command.SyncExecutor
	async     command.AsyncExecutor
}

type executeCommandRequest struct {
	CommandLine string `json:"CommandLine"`
	Wait        int64  `json:"Wait"`
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (app *App) commandHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	lg := app.logger

	rw := &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}

	// Resolve request ID and emit "HTTP request received" before any
	// validation or body parse so every rejection path inherits it for
	// log correlation. The RequestID middleware normally supplies the
	// value; the fallback handles unit tests that bypass the chain.
	requestID := server.RequestIDFrom(r.Context())
	if requestID == "" {
		requestID = uuid.NewString()
	}
	threadID := lg.LogHTTPRequestReceived(r, requestID)

	if r.ContentLength > maxRequestSize {
		http.Error(rw, "Request too large", http.StatusBadRequest)
		return
	}

	var commandLine string
	var wait int64 = -1

	switch r.Method {
	case http.MethodGet:
		if len(r.URL.RawQuery) > maxRequestSize {
			http.Error(rw, "Query string too large", http.StatusBadRequest)
			return
		}
		commandLine = r.URL.Query().Get("CommandLine")
		waitParam := r.URL.Query().Get("Wait")
		if waitParam != "" {
			parsedWait, err := strconv.ParseInt(waitParam, 10, 0)
			if err == nil {
				wait = parsedWait
			}
		}

	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(rw, "Content-Type must be application/json", http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(rw, r.Body, maxRequestSize)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			if strings.Contains(err.Error(), "request body too large") {
				http.Error(rw, "Request too large", http.StatusBadRequest)
				return
			}
			http.Error(rw, "Failed to read request body", http.StatusBadRequest)
			return
		}
		var cmdReq executeCommandRequest
		if err := json.Unmarshal(body, &cmdReq); err != nil {
			http.Error(rw, "Invalid JSON format", http.StatusBadRequest)
			return
		}
		commandLine = cmdReq.CommandLine
		wait = cmdReq.Wait

	default:
		http.Error(rw, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	if commandLine == "" {
		http.Error(rw, "No or invalid CommandLine specified", http.StatusBadRequest)
		return
	}

	const maxCommandLength = 10000
	if len(commandLine) > maxCommandLength {
		http.Error(rw, "CommandLine too large", http.StatusBadRequest)
		return
	}

	if wait != 0 && wait != 1 {
		http.Error(rw, "No or invalid Wait value specified", http.StatusBadRequest)
		return
	}

	parsedCmd, err := command.ParseCommand(commandLine)
	if err != nil {
		lg.LogCommandError(fmt.Errorf("parse: %v", err), logger.Fields{
			"command":    commandLine,
			"source_ip":  r.RemoteAddr,
			"request_id": requestID,
			"thread_id":  threadID,
		})
		http.Error(rw, "Invalid command format", http.StatusBadRequest)
		return
	}

	if app.cfg != nil {
		if permitted, reason := app.cfg.IsCommandPermitted(parsedCmd); !permitted {
			lg.LogCommandError(&command.ErrPolicyRejected{Reason: reason}, logger.Fields{
				"command":    commandLine,
				"source_ip":  r.RemoteAddr,
				"request_id": requestID,
				"thread_id":  threadID,
				"reason":     reason,
			})
			http.Error(rw, "Command not permitted", http.StatusForbidden)
			return
		}
	}

	lg.LogCommandStart(commandLine, logger.Fields{
		"wait":       wait,
		"source_ip":  r.RemoteAddr,
		"request_id": requestID,
		"thread_id":  threadID,
		"user_agent": r.UserAgent(),
		"method":     r.Method,
		"path":       r.URL.Path,
	})

	if wait == 1 {
		app.handleSync(rw, r, parsedCmd, commandLine, requestID, threadID, start)
	} else {
		app.handleAsync(rw, r, parsedCmd, commandLine, requestID, threadID, start)
	}

	lg.LogHTTPRequestProcessed(r, rw.statusCode, time.Since(start), requestID, threadID)
}

// handleSync runs the parsed command via the SyncExecutor and writes the
// result. Per the locked decision, ErrNonZeroExit returns 200 with the
// script's output so callers can see what the failing script printed.
func (app *App) handleSync(rw *responseWriter, r *http.Request, cmd command.Command, raw, requestID string, threadID uint64, start time.Time) {
	lg := app.logger
	result, err := app.sync.Run(cmd)
	body := result.Stdout + result.Stderr

	fields := logger.Fields{
		"command":     raw,
		"source_ip":   r.RemoteAddr,
		"request_id":  requestID,
		"thread_id":   threadID,
		"duration_ms": time.Since(start).Milliseconds(),
		"wait":        int64(1),
		"exit_code":   result.ExitCode,
	}

	if err == nil {
		lg.LogCommandComplete(raw, body, time.Since(start), fields)
		rw.Write([]byte(body))
		return
	}

	var nonZero *command.ErrNonZeroExit
	if errors.As(err, &nonZero) {
		// Non-zero exit: surface the script's output to the caller.
		fields["stderr_len"] = len(result.Stderr)
		lg.LogCommandError(err, fields)
		rw.Write([]byte(body))
		return
	}

	// Timeout, spawn failure, anything else — generic 500.
	lg.LogCommandError(err, fields)
	http.Error(rw, "Command execution failed", http.StatusInternalServerError)
}

// handleAsync starts the parsed command via the AsyncExecutor and returns
// immediately. The Handle's ID is logged for traceability (and reserved for
// the future polling endpoint, see ROADMAP R1).
func (app *App) handleAsync(rw *responseWriter, r *http.Request, cmd command.Command, raw, requestID string, threadID uint64, start time.Time) {
	lg := app.logger
	handle, err := app.async.Start(cmd)

	fields := logger.Fields{
		"command":     raw,
		"source_ip":   r.RemoteAddr,
		"request_id":  requestID,
		"thread_id":   threadID,
		"duration_ms": time.Since(start).Milliseconds(),
		"wait":        int64(0),
	}
	if err != nil {
		lg.LogCommandError(err, fields)
		http.Error(rw, "Command execution failed", http.StatusInternalServerError)
		return
	}
	fields["async_id"] = handle.ID
	fields["pid"] = handle.PID
	const startedMsg = "Command started successfully"
	lg.LogCommandComplete(raw, startedMsg, time.Since(start), fields)
	rw.Write([]byte(startedMsg))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func (app *App) runServer() {
	srv := server.NewServer(app.cfg, app.logger, app.ipChecker)
	srv.RegisterHandler("/ExecuteCommand", app.commandHandler)
	srv.RegisterHandler("/health", healthHandler)

	httpPort := strconv.Itoa(app.cfg.Server.HTTPPort)
	httpsPort := ""

	if app.cfg.Security.HTTPS.Enabled {
		httpsPort = strconv.Itoa(app.cfg.Security.HTTPS.Port)
	}

	if err := srv.Start(httpPort, httpsPort); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server shutdown error: %v", err)
	}
}

func main() {
	configFile := flag.String("config", "", "Path to configuration file (required)")
	flag.Parse()

	if *configFile == "" {
		log.Fatal("Configuration file is required. Use --config flag to specify the path.")
	}

	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	lg, err := logger.InitLogger(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	var ipChecker *ip.IPChecker
	if cfg.Security.IPWhitelist.Enabled {
		ipChecker, err = ip.NewIPChecker(cfg.Security.IPWhitelist.AllowedIPs)
		if err != nil {
			log.Fatalf("Failed to initialize IP checker: %v", err)
		}
		lg.Info("IP whitelist enabled with " +
			strconv.Itoa(len(cfg.Security.IPWhitelist.AllowedIPs)) +
			" entries")
	}

	syncExec := command.NewSyncExecutor(time.Duration(cfg.Server.CommandTimeoutSeconds) * time.Second)
	asyncExec := command.NewAsyncExecutor()

	app := &App{
		cfg:       cfg,
		ipChecker: ipChecker,
		logger:    lg,
		sync:      syncExec,
		async:     asyncExec,
	}

	lg.Info("Service starting with configuration from: " + *configFile)

	startService(app)
}
