// config/config.go

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Hubert-Heijkers/tm1-executecommand-service/command"
	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure for the entire service.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Logging  LoggingConfig  `yaml:"logging"`
	Security SecurityConfig `yaml:"security"`
}

// ServerConfig holds server-specific configuration options.
type ServerConfig struct {
	HTTPPort              int `yaml:"http_port"`
	CommandTimeoutSeconds int `yaml:"command_timeout_seconds"`
}

// LoggingConfig holds all logging-related configuration options.
type LoggingConfig struct {
	Enabled    bool   `yaml:"enabled"`
	File       string `yaml:"file"`
	Level      string `yaml:"level"`
	MaxSize    int    `yaml:"max_size"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAge     int    `yaml:"max_age"`
}

// SecurityConfig groups all security-related configuration options.
type SecurityConfig struct {
	Authentication AuthConfig          `yaml:"authentication"`
	IPWhitelist    IPWhitelistConfig   `yaml:"ip_whitelist"`
	CommandPolicy  CommandPolicyConfig `yaml:"command_policy"`
	RateLimit      RateLimitConfig     `yaml:"rate_limit"`
	HTTPS          HTTPSConfig         `yaml:"https"`
}

// AuthConfig controls API key authentication.
type AuthConfig struct {
	Enabled bool   `yaml:"enabled"`
	APIKey  string `yaml:"api_key"`
}

// IPWhitelistConfig controls IP-based access restrictions.
type IPWhitelistConfig struct {
	Enabled        bool     `yaml:"enabled"`
	AllowedIPs     []string `yaml:"allowed_ips"`
	TrustProxy     bool     `yaml:"trust_proxy"`
	TrustedProxies []string `yaml:"trusted_proxies"`
}

// CommandPolicyConfig controls which commands are allowed to be executed.
// Only scripts in allowed directories with allowed extensions can be run.
type CommandPolicyConfig struct {
	Enabled            bool                    `yaml:"enabled"`
	AllowedExtensions  []string                `yaml:"allowed_extensions"`
	AllowedDirectories []AllowedDirectoryEntry `yaml:"allowed_directories"`
}

// AllowedDirectoryEntry defines a directory from which scripts can be executed.
type AllowedDirectoryEntry struct {
	Path           string `yaml:"path"`
	IncludeSubdirs bool   `yaml:"include_subdirs"`
}

// RateLimitConfig controls per-IP rate limiting.
type RateLimitConfig struct {
	Enabled           bool `yaml:"enabled"`
	RequestsPerMinute int  `yaml:"requests_per_minute"`
}

// HTTPSConfig controls HTTPS-related settings.
type HTTPSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Port     int    `yaml:"port"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// shellMetacharacters are characters that could be used for command injection.
var shellMetacharacters = []string{"&", "|", ";", "`", ">", "<", "$", "\n", "\r"}

// DefaultConfig returns a configuration with sensible default values.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			HTTPPort:              8080,
			CommandTimeoutSeconds: 300,
		},
		Logging: LoggingConfig{
			Enabled:    true,
			File:       "logs/executecommand.log",
			Level:      "info",
			MaxSize:    100,
			MaxBackups: 3,
			MaxAge:     28,
		},
		Security: SecurityConfig{
			Authentication: AuthConfig{
				Enabled: false,
			},
			IPWhitelist: IPWhitelistConfig{
				Enabled:    false,
				AllowedIPs: []string{},
			},
			CommandPolicy: CommandPolicyConfig{
				Enabled: false,
				AllowedExtensions: []string{
					".ps1",
					".py",
					".bat",
					".cmd",
				},
				AllowedDirectories: []AllowedDirectoryEntry{},
			},
			RateLimit: RateLimitConfig{
				Enabled:           false,
				RequestsPerMinute: 60,
			},
			HTTPS: HTTPSConfig{
				Enabled:  false,
				Port:     9443,
				CertFile: "cert/server.crt",
				KeyFile:  "cert/server.key",
			},
		},
	}
}

// LoadConfig loads configuration from a YAML file.
// If the file doesn't exist, it creates one with default values.
func LoadConfig(configFile string) (*Config, error) {
	config := DefaultConfig()

	data, err := os.ReadFile(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			if err := config.SaveToFile(configFile); err != nil {
				return nil, fmt.Errorf("failed to create default config file: %v", err)
			}
			return config, nil
		}
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	return config, nil
}

// Validate checks if the configuration is valid and normalizes paths.
func (c *Config) Validate() error {
	// Validate server configuration
	if c.Server.HTTPPort <= 0 || c.Server.HTTPPort > 65535 {
		return fmt.Errorf("server.http_port must be between 1 and 65535")
	}
	if c.Server.CommandTimeoutSeconds <= 0 {
		return fmt.Errorf("server.command_timeout_seconds must be positive")
	}

	// Validate logging configuration
	if c.Logging.Enabled {
		if c.Logging.MaxSize <= 0 {
			return fmt.Errorf("logging.max_size must be positive")
		}
		if c.Logging.MaxBackups < 0 {
			return fmt.Errorf("logging.max_backups cannot be negative")
		}
		if c.Logging.MaxAge < 0 {
			return fmt.Errorf("logging.max_age cannot be negative")
		}
		logDir := filepath.Dir(c.Logging.File)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return fmt.Errorf("failed to create log directory: %v", err)
		}
	}

	// Validate HTTPS configuration
	if c.Security.HTTPS.Enabled {
		if c.Security.HTTPS.CertFile == "" || c.Security.HTTPS.KeyFile == "" {
			return fmt.Errorf("HTTPS cert_file and key_file must be specified when HTTPS is enabled")
		}
	}

	// Validate authentication
	if c.Security.Authentication.Enabled {
		if len(c.Security.Authentication.APIKey) < 32 {
			return fmt.Errorf("authentication.api_key must be at least 32 characters when authentication is enabled")
		}
	}

	// Validate IP whitelist trust_proxy
	if c.Security.IPWhitelist.TrustProxy && len(c.Security.IPWhitelist.TrustedProxies) == 0 {
		return fmt.Errorf("trusted_proxies must not be empty when trust_proxy is enabled")
	}

	// Validate command policy
	if c.Security.CommandPolicy.Enabled {
		for _, ext := range c.Security.CommandPolicy.AllowedExtensions {
			if !strings.HasPrefix(ext, ".") {
				return fmt.Errorf("allowed extension %q must start with '.'", ext)
			}
		}
		for i, dir := range c.Security.CommandPolicy.AllowedDirectories {
			absPath, err := filepath.Abs(dir.Path)
			if err != nil {
				return fmt.Errorf("failed to resolve directory path %q: %v", dir.Path, err)
			}
			info, err := os.Stat(absPath)
			if err != nil {
				return fmt.Errorf("allowed directory %q does not exist: %v", dir.Path, err)
			}
			if !info.IsDir() {
				return fmt.Errorf("allowed directory %q is not a directory", dir.Path)
			}
			// Normalize to absolute path
			c.Security.CommandPolicy.AllowedDirectories[i].Path = absPath
		}
	}

	// Validate rate limit
	if c.Security.RateLimit.Enabled {
		if c.Security.RateLimit.RequestsPerMinute <= 0 {
			return fmt.Errorf("rate_limit.requests_per_minute must be positive")
		}
	}

	return nil
}

// SaveToFile saves the current configuration to a YAML file.
func (c *Config) SaveToFile(filename string) error {
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

// IsCommandPermitted checks if a parsed Command is allowed by the
// directory-scoped policy. Returns (allowed, reason) for logging.
func (c *Config) IsCommandPermitted(cmd command.Command) (bool, string) {
	if !c.Security.CommandPolicy.Enabled {
		return true, "command policy disabled"
	}

	for _, meta := range shellMetacharacters {
		if strings.Contains(cmd.Raw, meta) {
			return false, fmt.Sprintf("command contains shell metacharacter: %q", meta)
		}
	}

	scriptPath := findScriptToken(cmd, c.Security.CommandPolicy.AllowedExtensions)
	if scriptPath == "" {
		return false, "no script file with allowed extension found in command"
	}

	absPath, err := filepath.Abs(scriptPath)
	if err != nil {
		return false, fmt.Sprintf("failed to resolve script path: %v", err)
	}
	absPath = filepath.Clean(absPath)

	if resolved, err := filepath.EvalSymlinks(absPath); err == nil {
		absPath = resolved
	}

	for _, dir := range c.Security.CommandPolicy.AllowedDirectories {
		dirPath := filepath.Clean(dir.Path)
		// Resolve symlinks on the allowed-dir side too so containment checks
		// compare apples to apples (e.g. macOS resolves /var → /private/var).
		if resolved, err := filepath.EvalSymlinks(dirPath); err == nil {
			dirPath = resolved
		}
		if dir.IncludeSubdirs {
			if isSubPath(absPath, dirPath) {
				return true, "permitted"
			}
		} else {
			if filepath.Dir(absPath) == dirPath {
				return true, "permitted"
			}
		}
	}

	return false, fmt.Sprintf("script %q is not in any allowed directory", absPath)
}

// findScriptToken returns the first token in cmd (Executable, then Args) whose
// extension is in allowedExtensions. Preserves the legacy behavior that
// `python C:\Scripts\foo.py` is permitted because `foo.py` is found.
// Returns "" if no token matches.
func findScriptToken(cmd command.Command, allowedExtensions []string) string {
	candidates := make([]string, 0, 1+len(cmd.Args))
	candidates = append(candidates, cmd.Executable)
	candidates = append(candidates, cmd.Args...)

	for _, token := range candidates {
		ext := strings.ToLower(filepath.Ext(token))
		if ext == "" {
			continue
		}
		for _, allowedExt := range allowedExtensions {
			if strings.EqualFold(ext, allowedExt) {
				return token
			}
		}
	}
	return ""
}

// isSubPath checks if child path is under or equal to the parent directory.
func isSubPath(child, parent string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, "..")
}
