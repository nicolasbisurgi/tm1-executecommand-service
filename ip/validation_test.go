package ip

import (
	"net"
	"testing"
)

func TestParseIPEntry(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		isRange bool
	}{
		{"Valid IPv4", "192.168.1.1", false, false},
		{"Valid IPv6", "2001:db8::1", false, false},
		{"Valid CIDR IPv4", "192.168.1.0/24", false, true},
		{"Valid CIDR IPv6", "2001:db8::/32", false, true},
		{"Invalid IP", "256.256.256.256", true, false},
		{"Invalid CIDR", "192.168.1.0/33", true, false},
		{"Empty string", "", true, false},
		{"Invalid format", "not-an-ip", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipRange, err := ParseIPEntry(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseIPEntry() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && ipRange.IsRange != tt.isRange {
				t.Errorf("ParseIPEntry() isRange = %v, want %v", ipRange.IsRange, tt.isRange)
			}
		})
	}
}

func TestIPChecker_IsAllowed(t *testing.T) {
	// Create an IPChecker with various allowed ranges
	allowedEntries := []string{
		"127.0.0.1",             // Localhost
		"192.168.1.0/24",        // Private network
		"10.0.0.0/8",           // Another private network
		"2001:db8::/32",        // IPv6 range
		"2001:db8::1",          // Single IPv6
	}

	checker, err := NewIPChecker(allowedEntries)
	if err != nil {
		t.Fatalf("Failed to create IPChecker: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		allowed  bool
		comment  string
	}{
		{"Localhost", "127.0.0.1", true, "Localhost should be allowed"},
		{"Localhost with port", "127.0.0.1:8080", true, "IP with port should be handled"},
		{"IPv6 localhost", "::1", false, "Not in whitelist"},
		{"Private network IP", "192.168.1.100", true, "IP in allowed range"},
		{"Outside private network", "192.168.2.1", false, "IP outside allowed range"},
		{"Private network large", "10.10.10.10", true, "IP in large private range"},
		{"IPv6 in range", "2001:db8:1234::", true, "IPv6 in allowed range"},
		{"IPv6 single allowed", "2001:db8::1", true, "Allowed single IPv6"},
		{"IPv6 outside range", "2001:db9::1", false, "IPv6 outside allowed range"},
		{"Invalid IP", "invalid-ip", false, "Invalid IP should be rejected"},
		{"Empty string", "", false, "Empty string should be rejected"},
		{"X-Forwarded-For single", "192.168.1.100", true, "Single IP in X-Forwarded-For"},
		{"X-Forwarded-For multiple", "192.168.1.100, 10.0.0.1", true, "Should use first IP"},
		{"IPv6 with brackets", "[2001:db8::1]:8080", true, "IPv6 with port in brackets"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checker.IsAllowed(tt.input)
			if result != tt.allowed {
				t.Errorf("IsAllowed(%q) = %v, want %v (%s)", tt.input, result, tt.allowed, tt.comment)
			}
		})
	}
}

func TestNewIPChecker(t *testing.T) {
	tests := []struct {
		name          string
		allowedEntries []string
		wantErr       bool
	}{
		{
			name: "Valid entries",
			allowedEntries: []string{
				"127.0.0.1",
				"192.168.1.0/24",
				"2001:db8::/32",
			},
			wantErr: false,
		},
		{
			name: "Invalid entries",
			allowedEntries: []string{
				"invalid-ip",
				"256.256.256.256",
				"192.168.1.0/33",
			},
			wantErr: true,
		},
		{
			name:          "Empty list",
			allowedEntries: []string{},
			wantErr:       false,
		},
		{
			name: "Mixed valid and invalid",
			allowedEntries: []string{
				"127.0.0.1",
				"invalid-ip",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewIPChecker(tt.allowedEntries)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewIPChecker() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIPRange_Functionality(t *testing.T) {
	tests := []struct {
		name      string
		ipRange   string
		testIP    string
		shouldMatch bool
	}{
		{"Single IP match", "192.168.1.1", "192.168.1.1", true},
		{"Single IP no match", "192.168.1.1", "192.168.1.2", false},
		{"CIDR range match", "192.168.1.0/24", "192.168.1.100", true},
		{"CIDR range no match", "192.168.1.0/24", "192.168.2.1", false},
		{"IPv6 single match", "2001:db8::1", "2001:db8::1", true},
		{"IPv6 single no match", "2001:db8::1", "2001:db8::2", false},
		{"IPv6 range match", "2001:db8::/32", "2001:db8:1234::1", true},
		{"IPv6 range no match", "2001:db8::/32", "2001:db9::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipRange, err := ParseIPEntry(tt.ipRange)
			if err != nil {
				t.Fatalf("Failed to parse IP range: %v", err)
			}

			testIP := net.ParseIP(tt.testIP)
			if testIP == nil {
				t.Fatalf("Failed to parse test IP: %v", tt.testIP)
			}

			var matches bool
			if ipRange.IsRange {
				matches = ipRange.Network.Contains(testIP)
			} else {
				matches = testIP.Equal(ipRange.Single)
			}

			if matches != tt.shouldMatch {
				t.Errorf("IP %v match test failed: got %v, want %v", tt.testIP, matches, tt.shouldMatch)
			}
		})
	}
}
