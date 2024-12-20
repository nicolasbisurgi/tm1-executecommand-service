package logger

import (
    "fmt"
    "io"
    "net/http"
    "sync/atomic"
    "time"

    "github.com/Hubert-Heijkers/tm1-executecommand-service/config"
    "github.com/google/uuid"
    "github.com/sirupsen/logrus"
    "gopkg.in/natefinch/lumberjack.v2"
)

// CommandLogger wraps logrus.Logger and provides our custom methods
type CommandLogger struct {
    logger *logrus.Logger
    threadCounter uint64
}

type logWriter struct {
    logger *CommandLogger
}

func (w *logWriter) Write(p []byte) (n int, err error) {
    w.logger.logger.Error(string(p))
    return len(p), nil
}

// Add this method to the CommandLogger struct
func (l *CommandLogger) Writer() io.Writer {
    return &logWriter{logger: l}
}

// Fields represents structured log fields
type Fields map[string]interface{}

var instance *CommandLogger

// InitLogger initializes the logging system based on configuration
func InitLogger(cfg *config.Config) (*CommandLogger, error) {
    logger := &CommandLogger{
        logger: logrus.New(),
        threadCounter: 0,
    }
    
    if cfg == nil || !cfg.Logging.Enabled {
        logger.logger.SetOutput(io.Discard)
        instance = logger
        return logger, nil
    }

    // Set log level
    level, err := logrus.ParseLevel(cfg.Logging.Level)
    if err != nil {
        return nil, fmt.Errorf("invalid log level: %v", err)
    }
    logger.logger.SetLevel(level)

    // Configure log rotation
    rotator := &lumberjack.Logger{
        Filename:   cfg.Logging.File,
        MaxSize:    cfg.Logging.MaxSize,
        MaxBackups: cfg.Logging.MaxBackups,
        MaxAge:     cfg.Logging.MaxAge,
        Compress:   true,
    }

    // Configure custom formatter
    formatter := &CustomFormatter{
        TimestampFormat: time.RFC3339,
    }

    logger.logger.SetFormatter(formatter)
    logger.logger.SetOutput(rotator)
    instance = logger
    return logger, nil
}

// getNextThreadID generates a new thread ID
func (l *CommandLogger) getNextThreadID() uint64 {
    return atomic.AddUint64(&l.threadCounter, 1) % 10000 // Wrap around after 9999
}

// CustomFormatter implements logrus.Formatter interface
type CustomFormatter struct {
    TimestampFormat string
}

// Format renders a single log entry
func (f *CustomFormatter) Format(entry *logrus.Entry) ([]byte, error) {
    timestamp := entry.Time.Format(f.TimestampFormat)
    threadID := entry.Data["thread_id"]
    level := fmt.Sprintf("%-5s", entry.Level.String())
    msg := entry.Message

    // Format the log line with thread ID
    logLine := fmt.Sprintf("%s - %04d - %s - %s", timestamp, threadID, level, msg)

    // Add fields in a consistent order
    if requestID, exists := entry.Data["request_id"]; exists {
        logLine += fmt.Sprintf(" - request_id=%v", requestID)
    }
    
    // Add remaining fields
    for k, v := range entry.Data {
        if k != "request_id" && k != "thread_id" { // Skip request_id and thread_id as they're already included
            logLine += fmt.Sprintf(" - %s=%v", k, v)
        }
    }
    
    return []byte(logLine + "\n"), nil
}

// GetLogger returns the singleton logger instance
func GetLogger() *CommandLogger {
    if instance == nil {
        logger := &CommandLogger{
            logger: logrus.New(),
            threadCounter: 0,
        }
        logger.logger.SetOutput(io.Discard)
        instance = logger
    }
    return instance
}

// Info logs an info message (for backward compatibility)
func (l *CommandLogger) Info(msg string) {
    threadID := l.getNextThreadID()
    l.logger.WithFields(logrus.Fields{
        "request_id": uuid.New().String(),
        "thread_id": threadID,
    }).Info(msg)
}

// LogHTTPRequest logs HTTP requests (for backward compatibility)
func (l *CommandLogger) LogHTTPRequest(r *http.Request, statusCode int, duration time.Duration) {
    requestID := uuid.New().String()
    threadID := l.getNextThreadID()
    l.LogHTTPRequestProcessed(r, statusCode, duration, requestID, threadID)
}

// LogHTTPRequestReceived logs incoming HTTP requests
func (l *CommandLogger) LogHTTPRequestReceived(r *http.Request, command string, allowed bool) (string, uint64) {
    requestID := uuid.New().String()
    threadID := l.getNextThreadID()
    
    // Info level - basic request info with command
    l.logger.WithFields(logrus.Fields{
        "request_id": requestID,
        "thread_id": threadID,
        "user_agent": r.UserAgent(),
        "client_ip":  r.Header.Get("X-Forwarded-For"),
        "allowed":    allowed,
        "path":       r.URL.Path,
        "method":     r.Method,
        "command":    command,
    }).Info("HTTP request received")

    // Debug level - detailed request info and IP access info
    l.logger.WithFields(logrus.Fields{
        "request_id": requestID,
        "thread_id": threadID,
        "request_url":     r.URL.String(),
        "headers":         r.Header,
        "x_forwarded_for": r.Header.Get("X-Forwarded-For"),
        "remote_addr":     r.RemoteAddr,
        "allowed":         allowed,
    }).Debug("IP access details")

    return requestID, threadID
}

// LogCommandStart logs when a command execution starts
func (l *CommandLogger) LogCommandStart(command string, fields Fields) {
    requestID, _ := fields["request_id"].(string)
    threadID, _ := fields["thread_id"].(uint64)
    if requestID == "" {
        requestID = uuid.New().String()
        threadID = l.getNextThreadID()
    }
    wait, _ := fields["wait"].(int64)
    
    // Info level - basic command info
    l.logger.WithFields(logrus.Fields{
        "request_id": requestID,
        "thread_id": threadID,
        "command":    command,
        "wait":       wait,
    }).Info("Command execution started")

    // Debug level - detailed command info
    debugFields := logrus.Fields{
        "request_id": requestID,
        "thread_id": threadID,
        "command":    command,
        "wait":       wait,
    }
    // Add any additional fields for debug level
    for k, v := range fields {
        if k != "request_id" && k != "command" && k != "wait" && k != "thread_id" {
            debugFields[k] = v
        }
    }
    l.logger.WithFields(debugFields).Debug("Command execution details")
}

// LogCommandComplete logs when a command execution completes
func (l *CommandLogger) LogCommandComplete(command string, output string, duration time.Duration, fields Fields) {
    requestID, _ := fields["request_id"].(string)
    threadID, _ := fields["thread_id"].(uint64)
    if requestID == "" {
        requestID = uuid.New().String()
        threadID = l.getNextThreadID()
    }
    
    // Info level - basic completion info
    l.logger.WithFields(logrus.Fields{
        "request_id":   requestID,
        "thread_id":    threadID,
        "command":      command,
        "duration_ms":  duration.Milliseconds(),
        "status":       "success",
    }).Info("Command execution completed")

    // Debug level - detailed completion info
    debugFields := logrus.Fields{
        "request_id":   requestID,
        "thread_id":    threadID,
        "command":      command,
        "duration_ms":  duration.Milliseconds(),
        "status":       "success",
        "output":       output,
    }
    // Add any additional fields for debug level
    for k, v := range fields {
        if k != "request_id" && k != "command" && k != "duration_ms" && k != "status" && k != "thread_id" {
            debugFields[k] = v
        }
    }
    l.logger.WithFields(debugFields).Debug("Command execution completed with details")
}

// LogCommandError logs command execution errors
func (l *CommandLogger) LogCommandError(err error, fields Fields) {
    requestID, _ := fields["request_id"].(string)
    threadID, _ := fields["thread_id"].(uint64)
    if requestID == "" {
        requestID = uuid.New().String()
        threadID = l.getNextThreadID()
    }
    command, _ := fields["command"].(string)
    
    // Info level - basic error info
    l.logger.WithFields(logrus.Fields{
        "request_id":   requestID,
        "thread_id":    threadID,
        "command":      command,
        "status":       "failure",
        "error":        err.Error(),
    }).Error("Command execution failed")

    // Debug level - detailed error info
    debugFields := logrus.Fields{
        "request_id":   requestID,
        "thread_id":    threadID,
        "command":      command,
        "status":       "failure",
        "error":        err.Error(),
        "stack_trace":  fmt.Sprintf("%+v", err),
    }
    // Add any additional fields for debug level
    for k, v := range fields {
        if k != "request_id" && k != "command" && k != "status" && k != "error" && k != "thread_id" {
            debugFields[k] = v
        }
    }
    l.logger.WithFields(debugFields).Debug("Command execution failure details")
}

// LogHTTPRequestProcessed logs when an HTTP request is completed
func (l *CommandLogger) LogHTTPRequestProcessed(r *http.Request, statusCode int, duration time.Duration, requestID string, threadID uint64) {
    // Info level - basic response info
    l.logger.WithFields(logrus.Fields{
        "request_id":   requestID,
        "thread_id":    threadID,
        "status_code":  statusCode,
        "duration_ms":  duration.Milliseconds(),
    }).Info("HTTP request processed")

    // Debug level - detailed response info
    l.logger.WithFields(logrus.Fields{
        "request_id":   requestID,
        "thread_id":    threadID,
        "status_code":  statusCode,
        "duration_ms":  duration.Milliseconds(),
        "method":       r.Method,
        "path":        r.URL.Path,
        "client_ip":   r.RemoteAddr,
    }).Debug("HTTP request processing details")
}

// LogIPAccess logs IP-based access attempts (now at debug level)
func (l *CommandLogger) LogIPAccess(clientIP string, allowed bool, details map[string]interface{}) {
    requestID := uuid.New().String()
    threadID := l.getNextThreadID()
    fields := logrus.Fields{
        "request_id": requestID,
        "thread_id": threadID,
        "client_ip":  clientIP,
        "allowed":    allowed,
    }
    
    // Add additional details to fields
    for k, v := range details {
        fields[k] = v
    }

    // Now always log at debug level
    l.logger.WithFields(fields).Debug("IP access check")
}

// LogAccessDenied logs when access is denied for any reason
func (l *CommandLogger) LogAccessDenied(reason string, fields Fields) {
    requestID := uuid.New().String()
    threadID := l.getNextThreadID()
    fields["request_id"] = requestID
    fields["thread_id"] = threadID
    l.logger.WithFields(logrus.Fields(fields)).Warn("Access denied: " + reason)
}

// LogDebug logs debug information with detailed fields
func (l *CommandLogger) LogDebug(fields map[string]interface{}) {
    requestID := uuid.New().String()
    threadID := l.getNextThreadID()
    fields["request_id"] = requestID
    fields["thread_id"] = threadID
    l.logger.WithFields(logrus.Fields(fields)).Debug("Debug information")
}
