// config/config.go

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure for the entire service.
// It contains subsections for different aspects of the service like logging
// and security features.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Logging  LoggingConfig  `yaml:"logging"`
	Security SecurityConfig `yaml:"security"`
}

// ServerConfig holds server-specific configuration options.
type ServerConfig struct {
	HTTPPort             int `yaml:"http_port"`              // Port number for HTTP server
	CommandTimeoutSeconds int `yaml:"command_timeout_seconds"` // Maximum execution time for commands
}

// LoggingConfig holds all logging-related configuration options.
// It controls whether logging is enabled, where logs are stored,
// and how they are managed.
type LoggingConfig struct {
	Enabled    bool   `yaml:"enabled"`     // Whether logging is enabled
	File       string `yaml:"file"`        // Path to the log file
	Level      string `yaml:"level"`       // Logging level (debug, info, warn, error)
	MaxSize    int    `yaml:"max_size"`    // Maximum size of log file before rotation (in MB)
	MaxBackups int    `yaml:"max_backups"` // Number of old log files to retain
	MaxAge     int    `yaml:"max_age"`     // Days to keep old log files
}

// SecurityConfig groups all security-related configuration options.
// This includes IP whitelisting, HTTPS settings, and command restrictions.
type SecurityConfig struct {
	IPWhitelist      IPWhitelistConfig      `yaml:"ip_whitelist"`
	HTTPS            HTTPSConfig            `yaml:"https"`
	CommandWhitelist CommandWhitelistConfig `yaml:"command_whitelist"`
}

// IPWhitelistConfig controls IP-based access restrictions.
// When enabled, only requests from allowed IPs or ranges will be processed.
type IPWhitelistConfig struct {
	Enabled    bool     `yaml:"enabled"`     // Whether IP whitelisting is enabled
	AllowedIPs []string `yaml:"allowed_ips"` // List of allowed IP addresses/ranges
}

// HTTPSConfig controls HTTPS-related settings.
// When enabled, the service will serve requests over HTTPS instead of HTTP.
type HTTPSConfig struct {
	Enabled  bool   `yaml:"enabled"`   // Whether HTTPS is enabled
	Port     int    `yaml:"port"`      // Port number for HTTPS server
	CertFile string `yaml:"cert_file"` // Path to SSL certificate file
	KeyFile  string `yaml:"key_file"`  // Path to SSL private key file
}

// CommandWhitelistConfig controls which commands are allowed to be executed.
// When enabled, only commands matching the allowed patterns can be run.
type CommandWhitelistConfig struct {
	Enabled         bool             `yaml:"enabled"`          // Whether command whitelisting is enabled
	AllowedCommands []string         `yaml:"allowed_commands"` // List of allowed command patterns
	compiledRegexps []*regexp.Regexp // Compiled regular expressions for matching
}

// DefaultConfig returns a configuration with sensible default values.
// This is used when no configuration file is provided or when creating
// a new configuration file.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			HTTPPort:             8080,
			CommandTimeoutSeconds: 300, // 5 minutes default timeout
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
			IPWhitelist: IPWhitelistConfig{
				Enabled:    false,
				AllowedIPs: []string{},
			},
			HTTPS: HTTPSConfig{
				Enabled:  false,
				CertFile: "cert/server.crt",
				KeyFile:  "cert/server.key",
			},
			CommandWhitelist: CommandWhitelistConfig{
				Enabled: false,
				AllowedCommands: []string{
					"^powershell.*\\.ps1$",
					"^python.*\\.py$",
					"^cmd /C.*\\.bat$",
				},
			},
		},
	}
}

// LoadConfig loads configuration from a YAML file.
// If the file doesn't exist, it creates one with default values.
// Returns the loaded configuration and any error encountered.
func LoadConfig(configFile string) (*Config, error) {
	config := DefaultConfig()

	// Read the configuration file
	data, err := os.ReadFile(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			// If file doesn't exist, create it with default values
			if err := config.SaveToFile(configFile); err != nil {
				return nil, fmt.Errorf("failed to create default config file: %v", err)
			}
			return config, nil
		}
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	// Parse YAML into config struct
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	// Validate and process configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	return config, nil
}

// Validate checks if the configuration is valid and processes necessary components.
// It validates file paths, compiles regular expressions, and ensures
// configuration values are within acceptable ranges.
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

		// Ensure log directory exists
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

	// Compile command whitelist patterns
	if c.Security.CommandWhitelist.Enabled {
		c.Security.CommandWhitelist.compiledRegexps = make([]*regexp.Regexp, 0, len(c.Security.CommandWhitelist.AllowedCommands))
		for _, pattern := range c.Security.CommandWhitelist.AllowedCommands {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("invalid command whitelist pattern '%s': %v", pattern, err)
			}
			c.Security.CommandWhitelist.compiledRegexps = append(c.Security.CommandWhitelist.compiledRegexps, re)
		}
	}

	return nil
}

// SaveToFile saves the current configuration to a YAML file.
// It creates the necessary directories if they don't exist.
func (c *Config) SaveToFile(filename string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	// Marshal config to YAML
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	// Write to file
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

// IsCommandAllowed checks if a command is allowed based on the whitelist patterns.
// Returns true if command whitelisting is disabled or if the command matches
// any of the allowed patterns.
func (c *Config) IsCommandAllowed(command string) bool {
	if !c.Security.CommandWhitelist.Enabled {
		return true
	}

	for _, re := range c.Security.CommandWhitelist.compiledRegexps {
		if re.MatchString(command) {
			return true
		}
	}
	return false
}
