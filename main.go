package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
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

var (
	cfg       *config.Config
	ipChecker *ip.IPChecker
	elog      debug.Log
)

const maxRequestSize = 1024 * 1024 // 1MB max request size

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

func executeCommand(commandLine string, wait int64, r *http.Request, requestID string, threadID uint64) (string, error) {
	log := logger.GetLogger()
	startTime := time.Now()

	// Log command start
	log.LogCommandStart(commandLine, logger.Fields{
		"wait":       wait,
		"source_ip":  r.RemoteAddr,
		"request_id": requestID,
		"thread_id":  threadID,
		"user_agent": r.UserAgent(),
		"method":     r.Method,
		"path":       r.URL.Path,
	})

	if cfg != nil && !cfg.IsCommandAllowed(commandLine) {
		log.LogCommandError(fmt.Errorf("command not allowed by whitelist: %s", commandLine), logger.Fields{
			"command":     commandLine,
			"source_ip":   r.RemoteAddr,
			"request_id":  requestID,
			"thread_id":   threadID,
			"duration_ms": time.Since(startTime).Milliseconds(),
		})
		return "", fmt.Errorf("command not allowed by whitelist: %s", commandLine)
	}

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
		log.LogCommandError(fmt.Errorf("invalid command format: %s", commandLine), logger.Fields{
			"command":     commandLine,
			"source_ip":   r.RemoteAddr,
			"request_id":  requestID,
			"thread_id":   threadID,
			"duration_ms": time.Since(startTime).Milliseconds(),
		})
		return "", fmt.Errorf("invalid command format: %s", commandLine)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Server.CommandTimeoutSeconds)*time.Second)
	defer cancel()

	// Set the command's context
	cmd = exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)

	var output string

	if wait == 1 {
		outputBytes, err := cmd.CombinedOutput()
		output = string(outputBytes)
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				err = fmt.Errorf("command execution timed out after %d seconds", cfg.Server.CommandTimeoutSeconds)
			}
			log.LogCommandError(err, logger.Fields{
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
		if err := cmd.Start(); err != nil {
			log.LogCommandError(err, logger.Fields{
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
	log.LogCommandComplete(commandLine, output, time.Since(startTime), logger.Fields{
		"wait":       wait,
		"source_ip":  r.RemoteAddr,
		"request_id": requestID,
		"thread_id":  threadID,
		"method":     r.Method,
		"path":       r.URL.Path,
	})

	return output, nil
}

func isIPAllowed(r *http.Request) bool {
	if cfg == nil || !cfg.Security.IPWhitelist.Enabled {
		return true
	}

	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}

	return ipChecker.IsAllowed(clientIP)
}

func commandHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	log := logger.GetLogger()

	rw := &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}

	if r.ContentLength > maxRequestSize {
		http.Error(rw, "Request too large", http.StatusBadRequest)
		return
	}

	allowed := isIPAllowed(r)

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
	requestID, threadID := log.LogHTTPRequestReceived(r, commandLine, allowed)

	if !allowed {
		http.Error(rw, "Access denied: IP not in whitelist", http.StatusForbidden)
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

	output, err := executeCommand(commandLine, wait, r, requestID, threadID)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Error executing command: %v", err), http.StatusInternalServerError)
		return
	}

	rw.Write([]byte(output))

	// Log HTTP request processed
	log.LogHTTPRequestProcessed(r, rw.statusCode, time.Since(start), requestID, threadID)
}

type executeCommandService struct{}

func (m *executeCommandService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}
	go runServer()
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

func runWindowsService(name string) {
	run := svc.Run
	elog.Info(1, fmt.Sprintf("starting %s service on port %d", name, cfg.Server.HTTPPort))
	err := run(name, &executeCommandService{})
	if err != nil {
		elog.Error(1, fmt.Sprintf("service %s failed: %v", name, err))
		return
	}
	elog.Info(1, fmt.Sprintf("service %s stopped", name))
}

func runServer() {
	srv := server.NewServer(cfg, logger.GetLogger())
	srv.RegisterHandler("/ExecuteCommand", commandHandler)

	httpsPort := strconv.Itoa(cfg.Server.HTTPPort)
	httpPort := ""

	if cfg != nil && cfg.Security.HTTPS.Enabled {
		httpPort = strconv.Itoa(cfg.Server.HTTPPort)
		httpsPort = strconv.Itoa(cfg.Security.HTTPS.Port)
	} else {
		httpPort = strconv.Itoa(cfg.Server.HTTPPort)
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

	var err error
	cfg, err = config.LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	lg, err := logger.InitLogger(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	if cfg.Security.IPWhitelist.Enabled {
		ipChecker, err = ip.NewIPChecker(cfg.Security.IPWhitelist.AllowedIPs)
		if err != nil {
			log.Fatalf("Failed to initialize IP checker: %v", err)
		}
		lg.Info("IP whitelist enabled with " +
			strconv.Itoa(len(cfg.Security.IPWhitelist.AllowedIPs)) +
			" entries")
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
		runWindowsService("ExecuteCommandService")
	} else {
		fmt.Printf("Starting ExecuteCommand service on port %d...\n", cfg.Server.HTTPPort)
		elog = debug.New("ExecuteCommandService")
		runServer()
	}
}