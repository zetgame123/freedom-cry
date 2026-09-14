package xray

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// DefaultHighReputationSNIPool contains enterprise CDN domains that support TLS 1.3
var DefaultHighReputationSNIPool = []string{
	"www.microsoft.com",
	"gateway.icloud.com",
	"azure.microsoft.com",
	"d1.awsstatic.com",
	"www.apple.com",
	"dl.google.com",
}

// ValidateSNIDomain performs a TLS 1.3 handshake against target SNI domain to ensure
// it is alive, supports TLS 1.3, and negotiates HTTP/2 or HTTP/1.1
func ValidateSNIDomain(sni string, timeout time.Duration) error {
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	conf := &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:443", sni), conf)
	if err != nil {
		return fmt.Errorf("TLS 1.3 handshake failed for SNI %s: %w", sni, err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		return fmt.Errorf("domain %s did not negotiate TLS 1.3 (got 0x%04x)", sni, state.Version)
	}

	return nil
}

// SelectHealthySNI tests domains in the pool and returns the first healthy TLS 1.3 SNI domain.
// If none respond, it falls back to the default SNI.
func SelectHealthySNI(poolStr string, fallback string) string {
	domains := strings.Split(poolStr, ",")
	if len(domains) == 0 || domains[0] == "" {
		domains = DefaultHighReputationSNIPool
	}

	for _, raw := range domains {
		d := strings.TrimSpace(raw)
		if d == "" {
			continue
		}
		if err := ValidateSNIDomain(d, 2*time.Second); err == nil {
			return d
		}
	}

	if fallback != "" {
		return fallback
	}
	return "www.microsoft.com"
}
