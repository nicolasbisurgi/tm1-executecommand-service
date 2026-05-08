
package ip

import (
    "fmt"
    "net"
    "strings"
)

// IPRange represents either a single IP address or a CIDR range
type IPRange struct {
    Network *net.IPNet
    Single  net.IP
    IsRange bool
}

// ParseIPEntry takes a string representation of an IP address or CIDR range
// and returns a parsed IPRange structure
func ParseIPEntry(entry string) (*IPRange, error) {
    // Check if the entry is a CIDR range
    if strings.Contains(entry, "/") {
        _, network, err := net.ParseCIDR(entry)
        if err != nil {
            return nil, fmt.Errorf("invalid CIDR format: %v", err)
        }
        return &IPRange{
            Network: network,
            IsRange: true,
        }, nil
    }

    // Parse as single IP address
    ip := net.ParseIP(entry)
    if ip == nil {
        return nil, fmt.Errorf("invalid IP address: %s", entry)
    }
    return &IPRange{
        Single: ip,
        IsRange: false,
    }, nil
}

// IPChecker manages a collection of allowed IP ranges
type IPChecker struct {
    allowedRanges []*IPRange
}

// NewIPChecker creates a new IPChecker instance with the provided allowed IP entries
func NewIPChecker(allowedEntries []string) (*IPChecker, error) {
    checker := &IPChecker{
        allowedRanges: make([]*IPRange, 0, len(allowedEntries)),
    }

    for _, entry := range allowedEntries {
        ipRange, err := ParseIPEntry(entry)
        if err != nil {
            return nil, fmt.Errorf("failed to parse IP entry '%s': %v", entry, err)
        }
        checker.allowedRanges = append(checker.allowedRanges, ipRange)
    }

    return checker, nil
}

// IsAllowed checks if the provided IP address is allowed based on the configured ranges
func (c *IPChecker) IsAllowed(ipStr string) bool {
    // Handle X-Forwarded-For header format (take the leftmost IP)
    if strings.Contains(ipStr, ",") {
        ipStr = strings.TrimSpace(strings.Split(ipStr, ",")[0])
    }

    // Handle IPv6 with square brackets
    ipStr = strings.Trim(ipStr, "[]")
    
    // Remove port number if present
    if strings.Contains(ipStr, ":") {
        // Handle IPv6 addresses properly
        if strings.Count(ipStr, ":") > 1 {
            // This is an IPv6 address, find the last colon for port
            if lastColon := strings.LastIndex(ipStr, "]"); lastColon != -1 {
                // Extract IP part without port
                ipStr = strings.Trim(ipStr[:lastColon], "[]")
            }
        } else {
            // IPv4 address with port
            ipStr = strings.Split(ipStr, ":")[0]
        }
    }

    ip := net.ParseIP(ipStr)
    if ip == nil {
        return false
    }

    for _, ipRange := range c.allowedRanges {
        if ipRange.IsRange {
            if ipRange.Network.Contains(ip) {
                return true
            }
        } else {
            if ip.Equal(ipRange.Single) {
                return true
            }
        }
    }
    return false
}