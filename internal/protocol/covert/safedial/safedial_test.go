package safedial

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestValidateIP(t *testing.T) {
	tests := []struct {
		name      string
		ipStr     string
		expectErr bool
	}{
		// Prohibited addresses
		{"IPv4 Loopback", "127.0.0.1", true},
		{"IPv4 Loopback 127.0.0.2", "127.0.0.2", true},
		{"IPv6 Loopback", "::1", true},
		{"Unspecified IPv4", "0.0.0.0", true},
		{"Unspecified IPv6", "::", true},
		{"RFC1918 10.x", "10.0.0.1", true},
		{"RFC1918 172.16.x", "172.16.0.1", true},
		{"RFC1918 192.168.x", "192.168.1.1", true},
		{"Link-Local IPv4", "169.254.1.1", true},
		{"Cloud Metadata IPv4", "169.254.169.254", true},
		{"Cloud Metadata IPv6", "fd00:ec2::254", true},
		{"Carrier-Grade NAT", "100.64.0.1", true},
		{"IPv6 Unique Local", "fc00::1", true},
		{"IPv6 Link Local", "fe80::1", true},
		{"IPv4-mapped IPv6 loopback", "::ffff:127.0.0.1", true},
		{"IPv4-mapped IPv6 private", "::ffff:10.0.0.1", true},
		{"TEST-NET-1", "192.0.2.1", true},
		{"Multicast IPv4", "224.0.0.1", true},

		// Allowed public addresses
		{"Cloudflare DNS", "1.1.1.1", false},
		{"Google DNS", "8.8.8.8", false},
		{"Quad9 DNS", "9.9.9.9", false},
		{"Google IPv6 DNS", "2001:4860:4860::8888", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ipStr)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ipStr)
			}
			err := ValidateIP(ip)
			if tt.expectErr && err == nil {
				t.Errorf("Expected IP %s to be rejected, but it was accepted", tt.ipStr)
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Expected IP %s to be allowed, but got error: %v", tt.ipStr, err)
			}
		})
	}
}

func TestSafeDialer_SSRF_Rejection(t *testing.T) {
	dialer := NewSafeDialer(2 * time.Second)
	ctx := context.Background()

	targets := []string{
		"127.0.0.1:80",
		"localhost:8080",
		"169.254.169.254:80",
		"10.0.0.1:5432",
		"192.168.1.1:22",
		"[::1]:6379",
		"[::ffff:127.0.0.1]:80",
		"127.0.0.1:0",     // Invalid port
		"127.0.0.1:99999", // Port overflow
		"invalid-format",  // Malformed
	}

	for _, target := range targets {
		t.Run("Reject_"+target, func(t *testing.T) {
			conn, err := dialer.DialContext(ctx, "tcp", target)
			if err == nil {
				conn.Close()
				t.Fatalf("SSRF check failed: dial to %s succeeded but should have been blocked!", target)
			}
		})
	}
}
