package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name:    "Valid default config",
			cfg:     *DefaultConfig(),
			wantErr: false,
		},
		{
			name: "Invalid port - zero",
			cfg: Config{
				Server: ServerConfig{HTTPPort: 0, CommandTimeoutSeconds: 30},
			},
			wantErr: true,
		},
		{
			name: "Invalid port - too high",
			cfg: Config{
				Server: ServerConfig{HTTPPort: 70000, CommandTimeoutSeconds: 30},
			},
			wantErr: true,
		},
		{
			name: "Invalid timeout",
			cfg: Config{
				Server: ServerConfig{HTTPPort: 8080, CommandTimeoutSeconds: -1},
			},
			wantErr: true,
		},
		{
			name: "HTTPS enabled without cert",
			cfg: Config{
				Server: ServerConfig{HTTPPort: 8080, CommandTimeoutSeconds: 30},
				Security: SecurityConfig{
					HTTPS: HTTPSConfig{Enabled: true, CertFile: "", KeyFile: ""},
				},
			},
			wantErr: true,
		},
		{
			name: "Auth enabled with short key",
			cfg: Config{
				Server: ServerConfig{HTTPPort: 8080, CommandTimeoutSeconds: 30},
				Security: SecurityConfig{
					Authentication: AuthConfig{Enabled: true, APIKey: "short"},
				},
			},
			wantErr: true,
		},
		{
			name: "Auth enabled with valid key",
			cfg: Config{
				Server: ServerConfig{HTTPPort: 8080, CommandTimeoutSeconds: 30},
				Security: SecurityConfig{
					Authentication: AuthConfig{
						Enabled: true,
						APIKey:  "this-is-a-very-long-api-key-that-is-at-least-32-chars",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Rate limit with invalid RPM",
			cfg: Config{
				Server: ServerConfig{HTTPPort: 8080, CommandTimeoutSeconds: 30},
				Security: SecurityConfig{
					RateLimit: RateLimitConfig{Enabled: true, RequestsPerMinute: 0},
				},
			},
			wantErr: true,
		},
		{
			name: "Trust proxy without trusted proxies",
			cfg: Config{
				Server: ServerConfig{HTTPPort: 8080, CommandTimeoutSeconds: 30},
				Security: SecurityConfig{
					IPWhitelist: IPWhitelistConfig{
						TrustProxy:     true,
						TrustedProxies: []string{},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Command policy with invalid extension",
			cfg: Config{
				Server: ServerConfig{HTTPPort: 8080, CommandTimeoutSeconds: 30},
				Security: SecurityConfig{
					CommandPolicy: CommandPolicyConfig{
						Enabled:           true,
						AllowedExtensions: []string{"ps1"}, // missing leading dot
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateCommandPolicyDirectories(t *testing.T) {
	tmpDir := t.TempDir()
	scriptsDir := filepath.Join(tmpDir, "scripts")
	os.MkdirAll(scriptsDir, 0755)

	// Create a file (not a directory)
	filePath := filepath.Join(tmpDir, "notadir.txt")
	os.WriteFile(filePath, []byte("test"), 0644)

	tests := []struct {
		name    string
		dirs    []AllowedDirectoryEntry
		wantErr bool
	}{
		{
			name: "Valid existing directory",
			dirs: []AllowedDirectoryEntry{
				{Path: scriptsDir, IncludeSubdirs: true},
			},
			wantErr: false,
		},
		{
			name: "Non-existent directory",
			dirs: []AllowedDirectoryEntry{
				{Path: filepath.Join(tmpDir, "nonexistent"), IncludeSubdirs: false},
			},
			wantErr: true,
		},
		{
			name: "Path is a file, not a directory",
			dirs: []AllowedDirectoryEntry{
				{Path: filePath, IncludeSubdirs: false},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Server: ServerConfig{HTTPPort: 8080, CommandTimeoutSeconds: 30},
				Security: SecurityConfig{
					CommandPolicy: CommandPolicyConfig{
						Enabled:            true,
						AllowedExtensions:  []string{".ps1", ".py"},
						AllowedDirectories: tt.dirs,
					},
				},
			}
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsCommandPermitted(t *testing.T) {
	// Create temp directory structure
	tmpDir := t.TempDir()
	scriptsDir := filepath.Join(tmpDir, "scripts")
	subDir := filepath.Join(scriptsDir, "sub")
	noSubsDir := filepath.Join(tmpDir, "nosubs")
	os.MkdirAll(subDir, 0755)
	os.MkdirAll(noSubsDir, 0755)

	// Create test script files
	os.WriteFile(filepath.Join(scriptsDir, "test.ps1"), []byte("# test"), 0644)
	os.WriteFile(filepath.Join(subDir, "sub_test.py"), []byte("# test"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "outside.ps1"), []byte("# test"), 0644)
	os.WriteFile(filepath.Join(noSubsDir, "direct.bat"), []byte("@echo off"), 0644)

	cfg := &Config{
		Security: SecurityConfig{
			CommandPolicy: CommandPolicyConfig{
				Enabled:           true,
				AllowedExtensions: []string{".ps1", ".py", ".bat", ".cmd"},
				AllowedDirectories: []AllowedDirectoryEntry{
					{Path: scriptsDir, IncludeSubdirs: true},
					{Path: noSubsDir, IncludeSubdirs: false},
				},
			},
		},
	}

	tests := []struct {
		name    string
		command string
		allowed bool
	}{
		{
			name:    "Script in allowed dir",
			command: filepath.Join(scriptsDir, "test.ps1"),
			allowed: true,
		},
		{
			name:    "Script in subdirectory with include_subdirs=true",
			command: filepath.Join(subDir, "sub_test.py"),
			allowed: true,
		},
		{
			name:    "Script outside allowed directory",
			command: filepath.Join(tmpDir, "outside.ps1"),
			allowed: false,
		},
		{
			name:    "Script with interpreter prefix",
			command: "python " + filepath.Join(scriptsDir, "test.ps1"),
			allowed: true,
		},
		{
			name:    "Script in noSubsDir directly",
			command: filepath.Join(noSubsDir, "direct.bat"),
			allowed: true,
		},
		{
			name:    "No script file with allowed extension",
			command: "python -m module_name",
			allowed: false,
		},
		{
			name:    "Shell metacharacter - ampersand",
			command: filepath.Join(scriptsDir, "test.ps1") + " & del files",
			allowed: false,
		},
		{
			name:    "Shell metacharacter - pipe",
			command: filepath.Join(scriptsDir, "test.ps1") + " | grep something",
			allowed: false,
		},
		{
			name:    "Shell metacharacter - semicolon",
			command: filepath.Join(scriptsDir, "test.ps1") + "; rm -rf /",
			allowed: false,
		},
		{
			name:    "Shell metacharacter - backtick",
			command: filepath.Join(scriptsDir, "test.ps1") + " `whoami`",
			allowed: false,
		},
		{
			name:    "Shell metacharacter - redirect",
			command: filepath.Join(scriptsDir, "test.ps1") + " > output.txt",
			allowed: false,
		},
		{
			name:    "Path traversal attempt",
			command: scriptsDir + string(filepath.Separator) + ".." + string(filepath.Separator) + "outside.ps1",
			allowed: false,
		},
		{
			name:    "Disallowed extension",
			command: filepath.Join(scriptsDir, "malware.exe"),
			allowed: false,
		},
		{
			name:    "Command policy disabled",
			command: "anything goes",
			allowed: true, // tested separately below
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "Command policy disabled" {
				disabledCfg := &Config{
					Security: SecurityConfig{
						CommandPolicy: CommandPolicyConfig{Enabled: false},
					},
				}
				allowed, _ := disabledCfg.IsCommandPermitted(tt.command)
				if allowed != tt.allowed {
					t.Errorf("IsCommandPermitted(%q) = %v, want %v", tt.command, allowed, tt.allowed)
				}
				return
			}

			allowed, reason := cfg.IsCommandPermitted(tt.command)
			if allowed != tt.allowed {
				t.Errorf("IsCommandPermitted(%q) = %v (reason: %s), want %v", tt.command, allowed, reason, tt.allowed)
			}
		})
	}
}

func TestExtractScriptPath(t *testing.T) {
	extensions := []string{".ps1", ".py", ".bat"}

	tests := []struct {
		name        string
		command     string
		expectedErr bool
		expected    string
	}{
		{
			name:     "Simple script path",
			command:  "C:\\Scripts\\test.ps1",
			expected: "C:\\Scripts\\test.ps1",
		},
		{
			name:     "Script with interpreter",
			command:  "python C:\\Scripts\\test.py arg1",
			expected: "C:\\Scripts\\test.py",
		},
		{
			name:     "cmd /C prefix",
			command:  "cmd /C C:\\Scripts\\test.bat arg1",
			expected: "C:\\Scripts\\test.bat",
		},
		{
			name:     "Quoted path",
			command:  `"C:\Scripts\test.ps1" arg1`,
			expected: `C:\Scripts\test.ps1`,
		},
		{
			name:        "No script file found",
			command:     "python -m module",
			expectedErr: true,
		},
		{
			name:        "Empty command",
			command:     "",
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := extractScriptPath(tt.command, extensions)
			if tt.expectedErr {
				if err == nil {
					t.Errorf("expected error, got result: %q", result)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("got %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	t.Run("Missing file creates default", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "new_config.yaml")

		cfg, err := LoadConfig(configPath)
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}

		if cfg.Server.HTTPPort != 8080 {
			t.Errorf("expected default HTTP port 8080, got %d", cfg.Server.HTTPPort)
		}

		// Verify file was created
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			t.Error("expected config file to be created")
		}
	})

	t.Run("Invalid YAML", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "bad.yaml")
		os.WriteFile(configPath, []byte("{{invalid yaml"), 0644)

		_, err := LoadConfig(configPath)
		if err == nil {
			t.Error("expected error for invalid YAML")
		}
	})
}

func TestSaveAndLoadConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "roundtrip.yaml")

	original := DefaultConfig()
	original.Server.HTTPPort = 9999
	original.Server.CommandTimeoutSeconds = 60

	if err := original.SaveToFile(configPath); err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	loaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if loaded.Server.HTTPPort != 9999 {
		t.Errorf("HTTPPort: got %d, want 9999", loaded.Server.HTTPPort)
	}
	if loaded.Server.CommandTimeoutSeconds != 60 {
		t.Errorf("CommandTimeoutSeconds: got %d, want 60", loaded.Server.CommandTimeoutSeconds)
	}
}
