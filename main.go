package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Hubert-Heijkers/tm1-executecommand-service/config"
	"github.com/Hubert-Heijkers/tm1-executecommand-service/ip"
	"github.com/Hubert-Heijkers/tm1-executecommand-service/logger"
	"github.com/Hubert-Heijkers/tm1-executecommand-service/server"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
)

// elog is the Windows event log — kept as package-level since it's only used at startup.
var elog debug.Log

const maxRequestSize = 1024 * 1024 // 1MB max request size

// App holds the application dependencies, replacing package-level globals.
type App struct {
	cfg       *config.Config
	ipChecker *ip.IPChecker
	logger    *logger.CommandLogger
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

func (app *App) executeCommand(commandLine string, wait int64, r *http.Request, requestID string, threadID uint64) (string, error) {
	lg := app.logger
	startTime := time.Now()

	// Log command start
	lg.LogCommandStart(commandLine, logger.Fields{
		"wait":       wait,
		"source_ip":  r.RemoteAddr,
		"request_id": requestID,
		"thread_id":  threadID,
		"user_agent": r.UserAgent(),
		"method":     r.Method,
		"path":       r.URL.Path,
	})

	// Check command policy
	if app.cfg != nil {
		allowed, reason := app.cfg.IsCommandPermitted(commandLine)
		if !allowed {
			lg.LogCommandError(fmt.Errorf("command not permitted: %s", reason), logger.Fields{
				"command":     commandLine,
				"source_ip":   r.RemoteAddr,
				"request_id":  requestID,
				"thread_id":   threadID,
				"duration_ms": time.Since(startTime).Milliseconds(),
				"reason":      reason,
			})
			return "", fmt.Errorf("command not permitted")
		}
	}

	// Parse the command
	var cmd *exec.Cmd

	if strings.HasPrefix(strings.ToLower(commandLine), "cmd /c ") {
		cmdArgs := strings.SplitN(commandLine, " ", 3)
		if len(cmdArgs) == 3 {
			cmd = exec.Command("cmd", "/C", cmdArgs[2])
		}
	} else {
		cmdParts := strings.Fields(commandLine)
		if len(cmdParts) > 0 {
			cmd = exec.Command(cmdParts[0], cmdParts[1:]...)
		}
	}

	if cmd == nil {
		lg.LogCommandError(fmt.Errorf("invalid command format: %s", commandLine), logger.Fields{
			"command":     commandLine,
			"source_ip":   r.RemoteAddr,
			"request_id":  requestID,
			"thread_id":   threadID,
			"duration_ms": time.Since(startTime).Milliseconds(),
		})
		return "", fmt.Errorf("invalid command format")
	}

	var output string

	if wait == 1 {
		// For wait commands, use context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(app.cfg.Server.CommandTimeoutSeconds)*time.Second)
		defer cancel()

		cmd = exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)

		outputBytes, err := cmd.CombinedOutput()
		output = string(outputBytes)
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				err = fmt.Errorf("command execution timed out after %d seconds", app.cfg.Server.CommandTimeoutSeconds)
			}
			lg.LogCommandError(err, logger.Fields{
				"command":     commandLine,
				"output":      output,
				"source_ip":   r.RemoteAddr,
				"request_id":  requestID,
				"thread_id":   threadID,
				"duration_ms": time.Since(startTime).Milliseconds(),
				"wait":        wait,
			})
			return output, err
		}
	} else {
		// For fire-and-forget (wait==0): do NOT use context so the process survives
		// after the HTTP handler returns
		if err := cmd.Start(); err != nil {
			lg.LogCommandError(err, logger.Fields{
				"command":     commandLine,
				"source_ip":   r.RemoteAddr,
				"request_id":  requestID,
				"thread_id":   threadID,
				"duration_ms": time.Since(startTime).Milliseconds(),
				"wait":        wait,
			})
			return "", err
		}
		output = "Command started successfully"
	}

	// Log command completion
	lg.LogCommandComplete(commandLine, output, time.Since(startTime), logger.Fields{
		"wait":       wait,
		"source_ip":  r.RemoteAddr,
		"request_id": requestID,
		"thread_id":  threadID,
		"method":     r.Method,
		"path":       r.URL.Path,
	})

	return output, nil
}

// getClientIP extracts the real client IP, respecting trust_proxy configuration.
// Only reads X-Forwarded-For when the request comes from a trusted proxy.
func (app *App) getClientIP(r *http.Request) string {
	if app.cfg != nil && app.cfg.Security.IPWhitelist.TrustProxy {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		for _, proxy := range app.cfg.Security.IPWhitelist.TrustedProxies {
			if host == proxy {
				xff := r.Header.Get("X-Forwarded-For")
				if xff != "" {
					// Take the leftmost (original client) IP
					parts := strings.Split(xff, ",")
					return strings.TrimSpace(parts[0])
				}
				break
			}
		}
	}
	return r.RemoteAddr
}

func (app *App) isIPAllowed(r *http.Request) bool {
	if app.cfg == nil || !app.cfg.Security.IPWhitelist.Enabled {
		return true
	}

	clientIP := app.getClientIP(r)
	return app.ipChecker.IsAllowed(clientIP)
}

func (app *App) commandHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	lg := app.logger

	rw := &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}

	if r.ContentLength > maxRequestSize {
		http.Error(rw, "Request too large", http.StatusBadRequest)
		return
	}

	allowed := app.isIPAllowed(r)

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

	// Log HTTP request received with command and IP status
	requestID, threadID := lg.LogHTTPRequestReceived(r, commandLine, allowed)

	if !allowed {
		http.Error(rw, "Access denied", http.StatusForbidden)
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

	output, err := app.executeCommand(commandLine, wait, r, requestID, threadID)
	if err != nil {
		// Use generic error messages to avoid leaking internal details
		if strings.Contains(err.Error(), "not permitted") {
			http.Error(rw, "Command not permitted", http.StatusForbidden)
		} else {
			http.Error(rw, "Command execution failed", http.StatusInternalServerError)
		}
		return
	}

	rw.Write([]byte(output))

	// Log HTTP request processed
	lg.LogHTTPRequestProcessed(r, rw.statusCode, time.Since(start), requestID, threadID)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

type executeCommandService struct {
	app *App
}

func (m *executeCommandService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}
	go m.app.runServer()
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

loop:
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			break loop
		default:
			elog.Error(1, fmt.Sprintf("Unexpected service control request #%d", c.Cmd))
		}
	}
	changes <- svc.Status{State: svc.StopPending}
	return
}

func runWindowsService(name string, app *App) {
	run := svc.Run
	elog.Info(1, fmt.Sprintf("starting %s service on port %d", name, app.cfg.Server.HTTPPort))
	err := run(name, &executeCommandService{app: app})
	if err != nil {
		elog.Error(1, fmt.Sprintf("service %s failed: %v", name, err))
		return
	}
	elog.Info(1, fmt.Sprintf("service %s stopped", name))
}

func (app *App) runServer() {
	srv := server.NewServer(app.cfg, app.logger)
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

	app := &App{
		cfg:       cfg,
		ipChecker: ipChecker,
		logger:    lg,
	}

	lg.Info("Service starting with configuration from: " + *configFile)

	isWindowsService, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("Failed to determine if we are running in a windows service: %v", err)
	}

	if isWindowsService {
		elog, err = eventlog.Open("ExecuteCommandService")
		if err != nil {
			return
		}
		defer elog.Close()
		runWindowsService("ExecuteCommandService", app)
	} else {
		fmt.Printf("Starting ExecuteCommand service on port %d...\n", cfg.Server.HTTPPort)
		elog = debug.New("ExecuteCommandService")
		app.runServer()
	}
}
